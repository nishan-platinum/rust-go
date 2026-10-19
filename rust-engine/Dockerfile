# syntax=docker/dockerfile:1
# Build context: repository root (needs ../proto).
FROM rust:1.99-slim-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY proto ./proto
COPY rust-engine ./rust-engine
WORKDIR /src/rust-engine
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/rust-engine/target \
    cargo build --release --locked && cp target/release/rust-engine /rust-engine

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 engine
COPY --from=build /rust-engine /usr/local/bin/rust-engine
USER engine
EXPOSE 50051
ENTRYPOINT ["/usr/local/bin/rust-engine"]
