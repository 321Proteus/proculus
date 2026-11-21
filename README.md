# Proculus

Proculus is a Modular Attack Service Intelligence system. Offers discovery scans of large networks with change tracking, created as an entry to HackNation 2026.

## Build
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

## Layout

- `libs/netutil` – IP/CIDR/range/port sets, target parsing (C11)
- `libs/timing` – scan speed estimator
- `libs/db` – Postgres access, field encryption, migrations
- `services/planner` – target list to balanced, spread-out chunks
- `services/scan-worker` – validated nmap runs, XML parsing, emulated network
- `services/scheduler` – scan windows, frequency, overrun handling
- `services/gateway` – entry point (currently the demo above)

## Tests

```sh
ctest --test-dir build                                  # unit tests
docker build --target test .                            # same, on Debian
docker compose --profile test run --rm integration-test # with a real Postgres
```
