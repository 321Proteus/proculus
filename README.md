# Proculus

Proculus is a Modular Attack Service Intelligence system. Offers discovery scans of large networks with change tracking, created as an entry to HackNation 2026.

## Build

Needs CMake, a C11/C++17 compiler, expat, OpenSSL and [nlohmann-json](https://github.com/nlohmann/json)
(`sudo port install nlohmann-json expat openssl3` / `apt install nlohmann-json3-dev libexpat1-dev libssl-dev`).
`libs/db` additionally needs libpq and libsodium; it is skipped if they are missing.

```sh
cmake -S . -B build && cmake --build build
./build/services/gateway/gateway
```

Or with Docker: `docker compose up --build`

## Try it without a network

The gateway currently runs a demonstration of the scan pipeline against an
emulated network of 12,000+ addresses (virtual time, nothing is sent):

```sh
./build/services/gateway/gateway                       # 3 rounds, short window to show pause/resume
./build/services/gateway/gateway --window 22:00-06:00  # a window long enough for a whole round
./build/services/gateway/gateway --help
```

It plans chunks (planner), scans them with parallel virtual workers through the
same safety checks as a real scan (scan-worker), learns the real scan speed
(timing), keeps to the scan window and resumes in the next one (scheduler), and
compares each round with the previous one.

## Saved results

Pass `--store DIR` (or set `PROCULUS_STORE_DIR`) and every round is saved as a
run: `DIR/run-000001.json`, `run-000002.json`, ... Read them with `exporter`:

```sh
./build/services/gateway/gateway --store results --window 22:00-06:00
./build/services/exporter/exporter --store results list
./build/services/exporter/exporter --store results show latest                  # readable text
./build/services/exporter/exporter --store results show 2 --format json
./build/services/exporter/exporter --store results show 2 --format csv --output run2.csv
```

With Docker the gateway saves to the shared `results` volume:

```sh
docker compose run --rm gateway --window 22:00-06:00
docker compose run --rm exporter --store /data list
docker compose run --rm exporter --store /data show latest --format csv
```

## Following changes over time

`differ` compares saved runs and follows hosts and services across all of them:

```sh
./build/services/differ/differ --store results diff previous latest   # what changed in the last run
./build/services/differ/differ --store results diff 1 5 --all
./build/services/differ/differ --store results track                  # replay every run
./build/services/differ/differ --store results track --events --format json
```

`track` keeps a state per host (new, active, flapping, stale, gone). A host
that misses a scan is not simply "gone": every miss is weighed by how reliably
that host usually answers (at that hour of the day), so flapping hosts and hosts
that only answer during office hours are not written off early, while a host
that always answered is flagged after two misses. Thresholds are options
(`--stale-below`, `--gone-below`, `--gone-after`, `--flap-window`, ...).
It also lists hosts worth probing again and shows how confidently each service
was identified.

## Looking at web services

`http-prober` makes the first request a browser would make to a web service and
records what it shows: status, headers, cookies (names and flags only, never the
values), page title, redirects, TLS version and certificate (subject, SAN, key,
validity, self-signed/expired, host name match) and a favicon fingerprint.

```sh
./build/services/http-prober/http-prober --scope 10.0.0.0/24 --allowed-ports 80,443,8443 http://10.0.0.5 https://10.0.0.5:8443
./build/services/http-prober/http-prober --scope 10.0.0.0/24 --allowed-ports 80,443 --store results --run latest --format json
```

It is built to be safe to point at a network: it refuses any address outside
`--scope` or port outside `--allowed-ports` before sending anything, only sends
GET requests for `/`, the favicon and the few plain paths that signatures ask for (no logins, no query strings, no guessing), follows
redirects only when they stay on the same host, never sends cookies or
credentials, limits body and header sizes and time, and rate limits requests.

Run files are plain text for now; keep the directory protected. Encrypted
storage is the database's job (`libs/db`).

## Detecting technologies

`http-prober` matches what it sees against 125 built-in signatures (servers,
frameworks, CMS, admin panels, IoT, staging/debug exposure, TLS and cookie
hygiene) and reports detections with a confidence and the evidence behind it. A
few safe extra pages (`/wp-login.php`, `/phpmyadmin/`, ...) are fetched with a
plain GET, at most `--max-paths` per service (`--no-paths` turns it off).

Write your own, check them, and use them:

```sh
./build/services/signatures/signatures list --category cms
./build/services/signatures/signatures lint my-signatures/       # checks them and runs their examples
./build/services/http-prober/http-prober --signatures my-signatures/ --scope ... --allowed-ports ... http://10.0.0.5
```

The format and an example are in [libs/signatures](libs/signatures/README.md).

To follow web changes over time, let the prober save a copy of a run with the web
results and detections attached, then compare the saved runs with `differ`
(it reports changed titles, status, server, redirects, cookies, TLS certificates
and problems, and technologies added, removed or changing version):

```sh
./build/services/http-prober/http-prober --scope ... --allowed-ports ... --store results --run latest --save-run
./build/services/differ/differ --store results diff previous latest
```

Cookie values never reach a report or a saved run: `Set-Cookie` headers are
stored as `name=<redacted>; attributes`.

## Layout

- `libs/netutil` – IP/CIDR/range/port sets, target parsing (C11)
- `libs/timing` – scan speed estimator
- `libs/results` – what a scan run found, and the store that keeps it
- `libs/db` – Postgres access, field encryption, migrations
- `services/planner` – target list to balanced, spread-out chunks
- `services/scan-worker` – validated nmap runs, XML parsing, emulated network
- `services/scheduler` – scan windows, frequency, overrun handling
- `services/exporter` – lists saved runs and dumps them as text, JSON or CSV
- `services/differ` – compares runs and follows hosts and services over time
- `services/http-prober` – looks at web services: headers, cookies, titles, redirects, TLS certificates, favicon fingerprints
- `libs/signatures` – detection signatures: loader, matching engine, 125 built-ins
- `services/signatures` – list, lint, test and try out signatures
- `services/gateway` – entry point (currently the demo above)

## Tests

```sh
ctest --test-dir build                                  # unit tests
docker build --target test .                            # same, on Debian
docker compose --profile test run --rm integration-test # with a real Postgres
```
