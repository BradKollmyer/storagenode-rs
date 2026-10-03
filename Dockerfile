# syntax=docker/dockerfile:1.4
# Context is the parent of this repo (`docker build -f storagenode-rs/Dockerfile .`).
# The crate path-depends on storj-uplink, and the UI stage builds storj/web/storagenode.
# Copy those trees only so a local target/ directory is not sent to the daemon.

ARG NODE_VERSION=24.11.1

FROM --platform=$BUILDPLATFORM node:${NODE_VERSION} AS ui

WORKDIR /work
COPY storj/web/storagenode/package.json storj/web/storagenode/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY storj/web/storagenode/ ./
RUN --mount=type=cache,target=/root/.npm npm run build

FROM rust:1.88-bookworm AS rust

WORKDIR /src
COPY storj-uplink /src/storj-uplink
COPY storagenode-rs/Cargo.toml storagenode-rs/Cargo.lock storagenode-rs/rust-toolchain.toml /src/storagenode-rs/
COPY storagenode-rs/.cargo /src/storagenode-rs/.cargo
COPY storagenode-rs/crates /src/storagenode-rs/crates
COPY storagenode-rs/proto /src/storagenode-rs/proto
COPY storagenode-rs/third_party /src/storagenode-rs/third_party
WORKDIR /src/storagenode-rs
RUN cargo build --locked --release -p storagenode

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=rust /src/storagenode-rs/target/release/storagenode /usr/local/bin/storagenode
COPY --from=ui /work/dist/ /usr/share/storagenode/ui/

# PLAN.md defaults. Secrets and STORJ_SATELLITES stay runtime configuration.
ENV STORJ_S3_REGION=us-east-1 \
    STORJ_S3_PREFIX=pieces

# Required: STORJ_S3_ENDPOINT, STORJ_S3_BUCKET, STORJ_S3_ACCESS_KEY_ID,
# STORJ_S3_SECRET_ACCESS_KEY, STORJ_OPERATOR_EMAIL, STORJ_OPERATOR_WALLET,
# STORJ_CONTACT_EXTERNAL_ADDRESS, STORJ_SATELLITES.
# Optional: STORJ_S3_PATH_STYLE (auto when unset), STORJ_ALLOCATED_BYTES.
# /var/lib/storj holds the identity, pieces.db, and the bandwidth rollup.

VOLUME ["/var/lib/storj"]
EXPOSE 28967/tcp 28967/udp 14002/tcp
ENTRYPOINT ["storagenode"]
