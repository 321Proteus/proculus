FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --target gateway

FROM debian:bookworm-slim
COPY --from=build /src/build/services/gateway/gateway /usr/local/bin/gateway
ENTRYPOINT ["gateway"]
