# One Dockerfile for every service: a shared build stage plus a small runtime
# stage per service. Build one with e.g. `docker build --target scan-worker .`
# Run the test suite with `docker build --target test .`

FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config \
        libexpat1-dev libpq-dev libsodium-dev nlohmann-json3-dev libssl-dev libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DPROCULUS_REQUIRE_DB=ON \
    && cmake --build build

FROM build AS test
RUN ctest --test-dir build --output-on-failure

# Same build, but meant to run against a live database: see the integration-test
# service in docker-compose.yml.
FROM build AS integration
CMD ["ctest", "--test-dir", "build", "--output-on-failure"]

FROM debian:bookworm-slim AS runtime-base
RUN useradd --system --no-create-home --shell /usr/sbin/nologin proculus \
    && mkdir /data && chown proculus:proculus /data

FROM runtime-base AS gateway
RUN apt-get update && apt-get install -y --no-install-recommends libexpat1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/services/gateway/gateway /usr/local/bin/gateway
USER proculus
ENTRYPOINT ["gateway"]

FROM runtime-base AS ui
COPY --from=build /src/build/services/ui/ui /usr/local/bin/ui
USER proculus
ENTRYPOINT ["ui"]

FROM runtime-base AS planner
COPY --from=build /src/build/services/planner/planner /usr/local/bin/planner
USER proculus
ENTRYPOINT ["planner"]

FROM runtime-base AS exporter
COPY --from=build /src/build/services/exporter/exporter /usr/local/bin/exporter
USER proculus
ENTRYPOINT ["exporter"]

FROM runtime-base AS differ
COPY --from=build /src/build/services/differ/differ /usr/local/bin/differ
USER proculus
ENTRYPOINT ["differ"]

FROM runtime-base AS http-prober
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 libpcre2-8-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/services/http-prober/http-prober /usr/local/bin/http-prober
USER proculus
ENTRYPOINT ["http-prober"]

FROM runtime-base AS signatures
RUN apt-get update && apt-get install -y --no-install-recommends libpcre2-8-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/services/signatures/signatures /usr/local/bin/signatures
USER proculus
ENTRYPOINT ["signatures"]

FROM runtime-base AS scheduler
COPY --from=build /src/build/services/scheduler/scheduler /usr/local/bin/scheduler
USER proculus
ENTRYPOINT ["scheduler"]

FROM runtime-base AS scan-worker
RUN apt-get update && apt-get install -y --no-install-recommends nmap libexpat1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/services/scan-worker/scan-worker /usr/local/bin/scan-worker
USER proculus
ENTRYPOINT ["scan-worker"]
