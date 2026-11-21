# Proculus

Proculus is a Modular Attack Service Intelligence system. Offers discovery scans of large networks with change tracking, created as an entry to HackNation 2026.

## Build
```sh
    cmake -S . -B build && cmake --build build
    ./build/services/gateway/gateway
```

Or with Docker: `docker compose up --build`
