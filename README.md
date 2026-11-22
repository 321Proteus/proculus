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

## Scanning a real network

`runner` runs real scans with nmap: it reads targets (IPs, CIDRs, ranges, domains),
plans balanced chunks, finds the hosts that answer, identifies their services,
optionally probes the web services and detects technologies, and saves the round
as a run that the web UI, `differ` and `exporter` read.

```sh
# what would it do, and roughly how long? (scans nothing)
./build/services/runner/runner --dry-run --scope 10.0.0.0/16 --allowed-ports 22,80,443,8080 10.0.0.0/16

# a scan now, saved as a run, with web probing and detections
./build/services/runner/runner --scope 10.0.0.0/24 --allowed-ports 22,80,443,8080 \
    --workers 4 --rate 200 --web --store results 10.0.0.0/24 -x 10.0.0.1

# every night in a window, every 24 hours, until stopped; a round that does not fit
# the window is stopped when it closes and resumed in the next one
./build/services/runner/runner --scope 10.0.0.0/16 --allowed-ports 22,80,443,8080 \
    --window 22:00-06:00 --interval 24h --rounds 0 --web --store results -t targets.txt
```

Safety: `--scope` and `--allowed-ports` are required and are hard limits. Every
nmap command passes the same checks (nothing outside the scope or the allowed ports,
reserved addresses removed, rate and timing ceilings, no shell), domains are resolved
and every address must be in scope, and web probing has its own gates. Only the
packets-per-second you set are used (`--workers` x `--rate` in total). Unprivileged
scans use TCP connects; `--privileged` (root or `CAP_NET_RAW`) adds SYN scans and
ICMP ping for better host discovery. A scan that cannot finish (a chunk fails
repeatedly, or you stop it with Ctrl-C) saves nothing, so a half-scanned network is
never mistaken for hosts that disappeared. Only scan networks you are authorised to scan.

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

## Web UI

Two small services: `gateway serve` is the read-only JSON API over the saved
runs, and `ui` serves the pages and passes the page's `/api/` requests on to it.

```sh
./build/services/gateway/gateway --store results --window 22:00-06:00        # make some runs
./build/services/gateway/gateway serve --store results                        # the API, on 127.0.0.1:8081
./build/services/ui/ui                                                        # the UI, http://127.0.0.1:8080
docker compose --profile ui up --build ui                                     # both, in Docker (http://localhost:8080)
```

The layout and look follow the Python build (`PROCULUS_SCANNER/Proculus_NEW.py`): a header with the
emblem and status badges, seven numbered tabs, KPI cards, and the scan configuration beside live
telemetry on the first tab. Differences are deliberate: the live panels are updated in place instead
of being rebuilt (no flicker; the log keeps its scroll position unless you are at the bottom), the
guided tour ("Przewodnik") measures its target only after the smooth scroll has stopped and is
repositioned on resize, tooltips appear at the pointer, status dots actually pulse, and all motion
is off for users who prefer reduced motion. Tabs 4-6 (CSV/JSON targets, custom signatures,
schedule and DefectDojo) are placeholders for now.

A dashboard over the saved runs (Polish or English): size of the latest run and
what changed since the previous one, services ranked by priority with the
reasons, detections by category, the most common technologies, and host states
over time (new, active, flapping, stale, gone). Further views list and filter
all services, list the runs and compare any two.

The priority (0-100) combines what the signatures found (their own interest,
scaled by confidence) with what is exposed at all: telnet, databases, remote
desktop and similar are ranked even when no signature matched.

**Starting scans from the UI.** The "New scan" page (targets, exclusions, ports,
workers, rate, timing, web probing, a plan preview, live progress, stop) is off
unless the operator turns it on when starting the gateway. The limits are fixed
there; the form can only choose targets inside the scope and values under the
ceilings, and one scan runs at a time. It uses the same runner as the command line,
with the same safety checks.

```sh
export PROCULUS_CONTROL_TOKEN=choose-a-long-secret        # else a random one is printed at startup
./build/services/gateway/gateway serve --store results --enable-scans \
    --scan-scope 192.168.1.0/24 --scan-ports 22,80,443,8080 --scan-max-workers 2 --scan-max-rate 100
./build/services/ui/ui
```

With login off (`--no-auth`), starting, planning and stopping scans need that control
token (entered in the form, sent as `X-Proculus-Token`); wrong guesses are limited.
Requests must be JSON, so a web page on another site cannot trigger a scan by
posting a form. With login, the `scan.run` permission replaces the token.
In Docker: `docker-compose.scans.yml` (see its header).

The UI service holds no data and decides nothing; the gateway enforces logins and
roles. The proxy only forwards GET requests to plain `/api/...` paths, POST only
to a fixed list of routes (scans, login, users, roles), to the one configured
gateway, passes on only the session and control tokens, and only passes back JSON
of a limited size. Both services listen on the loopback interface only, answer
only to local host names (`--allow-host NAME` adds more, against DNS rebinding),
and the pages are sent with a strict Content-Security-Policy. Titles and banners come from scanned hosts and are
never inserted as HTML. For UI development, `ui --web-dir services/ui/web`
serves the files from disk without a rebuild.

## Keeping runs in Postgres

By default runs are JSON files. `runner` and `gateway serve` can keep them in
Postgres instead (`--db URL` or `PROCULUS_DB_URL`); nothing else changes, and the
file store remains the default. Addresses, ports, timestamps and service names stay
in the clear so runs can be queried; page titles, headers, cookies, TLS details,
redirects and detections are encrypted per column with XChaCha20-Poly1305
(libsodium), so a value copied into another column or opened with another key
fails. A run is saved in one transaction.

```sh
export PROCULUS_KEY=1:$(openssl rand -hex 32)       # or PROCULUS_KEY_FILE; keep it safe
export PROCULUS_DB_URL=postgresql://user:password@localhost:5432/proculus
./build/services/runner/runner --scope 10.0.0.0/24 --allowed-ports 22,80,443 --web 10.0.0.0/24   # saves into Postgres
./build/services/gateway/gateway serve                                                           # reads from it
```

The schema is created on first use from `db/migrations`. `differ` and `exporter` still
read files for now. In Docker: `docker-compose.db.yml` (see its header). Needs libpq
and libsodium; without them the programs build as before and `--db` says so.
Tests: `PROCULUS_TEST_DB_URL=postgresql://... ctest --test-dir build`.

## Users, roles and login

Login is on by default. Accounts, roles and an audit log are kept in files next to the runs
(`DIR/accounts`, mode 0600) or, with `--db`, in Postgres. Passwords are Argon2id hashes, and there
are no default accounts. On the first start with no accounts the gateway prints a **setup token**
on its console; the first visit to the UI asks for it and creates the administrator (the token
stops anyone else who can reach the page from claiming the account first; setup works once, and
wrong tokens are throttled).

```sh
./build/services/gateway/gateway serve --store results        # prints the setup token; open the UI and use it
./build/services/ui/ui                                        # http://127.0.0.1:8080

# or create the first administrator from the command line instead
./build/services/gateway/gateway user add your.name --role admin --store results   # asks for the password
./build/services/gateway/gateway user list | roles | passwd | role | disable | enable   # (--help)

./build/services/gateway/gateway serve --store results --no-auth   # NO LOGIN (local use only; the UI warns)
```

Four built-in roles match the spec: **admin** (Administracja: everything, including users and
configuration), **manager** (add, delete and modify data, run scans), **editor** (modify and
read) and **viewer** (read). A role is just a set of permissions (`data.read`, `data.edit`,
`data.create`, `data.delete`, `export`, `scan.run`, `config.manage`, `users.manage`), so more roles
can be created in the Administration page without code. Every route has a required permission in
one table (`services/gateway/src/server.cpp`) and is denied by default; the menu hides what a role
cannot use, but the server is what enforces it. Sessions are server-side, expire when idle, and end
at once when an account is changed or disabled; too many wrong passwords lock a user name for a
few minutes; the last administrator cannot be removed or disabled; logins, failures, scans and
account changes are written to the audit log (never passwords). The command line and the server
can change the same accounts at the same time. Keep the accounts directory private: it holds
password hashes. Nothing encrypts the connection itself: put the UI behind a TLS proxy for real use.

## Editing what the scans found

Hosts and services can be edited in the UI ("Edytuj" on any row, or the Edits page): a host name,
environment (prod, staging, test, dev), a status (ignored, false positive, confirmed), a priority
(0-100, replacing the computed one), tags and a note, for a host or for one of its services. Edits
are kept **apart from the scans**, keyed by address (and port and protocol for a service), so no scan
ever touches them: they survive every later scan and stay when a host stops answering for a while.
They are applied when the data is read: the UI shows your value and, under it, what the scan found.
Ignored and false-positive services are left out of the dashboard counts and top findings (and can be
hidden in the list). Changing needs the `data.edit` permission (or the control token when login is off),
and every change goes to the audit log (field names and values, never the text of notes). Edits are
files in `DIR/edits/` (mode 0600) or, with `--db`, the `entity_edits` table with the values sealed.

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
- `libs/pgstore` – runs kept in Postgres (the same store interface as the files)
- `services/planner` – target list to balanced, spread-out chunks
- `services/scan-worker` – validated nmap runs, XML parsing, emulated network
- `services/runner` – real scans: planning, nmap workers, scan windows, web probing, saved runs
- `services/scheduler` – scan windows, frequency, overrun handling
- `services/exporter` – lists saved runs and dumps them as text, JSON or CSV
- `services/differ` – compares runs and follows hosts and services over time
- `services/http-prober` – looks at web services: headers, cookies, titles, redirects, TLS certificates, favicon fingerprints
- `libs/signatures` – detection signatures: loader, matching engine, 125 built-ins
- `services/signatures` – list, lint, test and try out signatures
- `libs/insight` – priority score for services and the dashboard summary
- `libs/edits` – user edits of scanned data (files; the Postgres version is in `libs/pgstore`)
- `libs/web` – Host-header guard, sessions and login throttle shared by the web-facing services
- `libs/auth` – users, roles and the audit log in Postgres
- `services/gateway` – the demo above, and `serve`: the read-only JSON API
- `services/ui` – the web UI: the pages, and a strict proxy to the gateway API
- `third_party/httplib` – cpp-httplib (single header, MIT) used by the web server

## Tests

```sh
ctest --test-dir build                                  # unit tests
docker build --target test .                            # same, on Debian
docker compose --profile test run --rm integration-test # with a real Postgres
```
