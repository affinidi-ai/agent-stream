# syntax=docker/dockerfile:1
#
# Multi-stage build for the agent-stream binary + dashboard.
#
#   base    → Rust toolchain + native build dependencies
#   chef    → base + cargo-chef (dependency caching)
#   code    → source tree, test targets stripped for binary-only builds
#   planner → cargo-chef recipe (dependency graph)
#   cacher  → compiled dependencies (cached layer)
#   builder → the release binary
#   www     → the dashboard build (Node)
#   runtime → final slim-ish image: binary + dashboard, non-root
#
# Build:  docker build -t agent-stream:local .
# Run:    see docker-compose.yml / `make docker-run`.

ARG NODE_VERSION=22.23.4
ARG RUST_VERSION=1.95.0

# Cargo release profile overrides for the in-container build. These default to
# memory-friendly values (LTO off, more codegen units) so the release compile
# does not get OOM-killed inside a memory-constrained builder — e.g. the buildx
# docker-container driver used by `make docker-run`. They override Cargo.toml's
# [profile.release] only for the Docker image; native/CI release builds keep the
# committed profile (thin LTO, one codegen unit). Pass --build-arg to change them.
ARG CARGO_BUILD_FLAGS=
ARG CARGO_PROFILE_RELEASE_LTO=off
ARG CARGO_PROFILE_RELEASE_CODEGEN_UNITS=4
ARG CARGO_PROFILE_RELEASE_OPT_LEVEL=3

###############################################################################
# base — Rust toolchain + native build dependencies
# https://github.com/rust-lang/docker-rust/blob/master/stable/bookworm/slim/Dockerfile
###############################################################################
FROM rust:${RUST_VERSION}-slim-bookworm AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    # needed by the latest affinidi-tdk-rs
    build-essential \
    libdbus-1-dev \
    libssl-dev \
    git \
    # sasl2-sys
    libsasl2-2 \
    libsasl2-dev \
    libsasl2-modules \
    # rdkafka-sys
    cmake \
    libcurl4-openssl-dev \
    # libxml (samael dependency)
    libxml2-dev \
    libxmlsec1-dev \
    # bindgen (samael dependency)
    libclang-dev \
    pkg-config \
    # pulsar
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

###############################################################################
# chef — base + cargo-chef for dependency caching
###############################################################################
FROM base AS chef
WORKDIR /app
RUN cargo install cargo-chef

###############################################################################
# code — source tree (test targets stripped for binary-only builds)
###############################################################################
FROM base AS code
WORKDIR /app

COPY src/ ./src
# Files embedded with include_str! (rejection taxonomy, prompt-guard defaults,
# LLM catalog schema).
COPY config/examples/ ./config/examples
COPY config/schemas/ ./config/schemas
COPY Cargo.* ./
# cargo-chef doesn't create stubs for [[test]] targets with harness=false,
# causing manifest parsing to fail. Strip them so tests are not needed for the
# binary.
RUN sed -i '/^\[\[test\]\]/,/^$/d' Cargo.toml

###############################################################################
# planner — compute the cargo-chef dependency recipe
###############################################################################
FROM chef AS planner
WORKDIR /app

COPY --from=code /app .
RUN cargo chef prepare --bin agent-stream --recipe-path recipe.json

###############################################################################
# cacher — cook (compile) dependencies as a cached layer
###############################################################################
FROM chef AS cacher
ARG CARGO_BUILD_FLAGS
ARG CARGO_PROFILE_RELEASE_LTO
ARG CARGO_PROFILE_RELEASE_CODEGEN_UNITS
ARG CARGO_PROFILE_RELEASE_OPT_LEVEL
# Cargo reads these from the environment and overrides [profile.release]. Must
# match the builder stage so the cooked dependency cache is reused.
ENV CARGO_PROFILE_RELEASE_LTO=${CARGO_PROFILE_RELEASE_LTO} \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=${CARGO_PROFILE_RELEASE_CODEGEN_UNITS} \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=${CARGO_PROFILE_RELEASE_OPT_LEVEL}
WORKDIR /app

COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --bin agent-stream --release --recipe-path recipe.json ${CARGO_BUILD_FLAGS}

###############################################################################
# builder — build the release binary against the cached dependencies
###############################################################################
FROM base AS builder
ARG CARGO_BUILD_FLAGS
ARG CARGO_PROFILE_RELEASE_LTO
ARG CARGO_PROFILE_RELEASE_CODEGEN_UNITS
ARG CARGO_PROFILE_RELEASE_OPT_LEVEL
# Must match the cacher stage's ENV so the cooked dependency cache is reused
# instead of recompiled.
ENV CARGO_PROFILE_RELEASE_LTO=${CARGO_PROFILE_RELEASE_LTO} \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=${CARGO_PROFILE_RELEASE_CODEGEN_UNITS} \
    CARGO_PROFILE_RELEASE_OPT_LEVEL=${CARGO_PROFILE_RELEASE_OPT_LEVEL}
WORKDIR /app

COPY --from=code /app .
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
RUN cargo build --bin agent-stream --frozen --release ${CARGO_BUILD_FLAGS}

###############################################################################
# www — build the dashboard
###############################################################################
FROM node:${NODE_VERSION}-bookworm AS www
ARG WWW_DIR=www/default
WORKDIR /app/www

COPY ${WWW_DIR}/public/ ./public
COPY ${WWW_DIR}/src/ ./src
COPY ${WWW_DIR}/build.sh ./
COPY ${WWW_DIR}/package.json ./
COPY ${WWW_DIR}/package-lock.json ./
COPY ${WWW_DIR}/tsconfig.json ./
COPY ${WWW_DIR}/craco.config.js ./

RUN ./build.sh

###############################################################################
# runtime — final image: binary + dashboard, running as a non-root user
###############################################################################
FROM base AS runtime

# Drop git, patch remaining packages, and install curl for the container
# healthcheck.
RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get -y remove git git-man \
    && apt-get install -y --no-install-recommends curl \
    && apt-get -y autoclean && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/agent-stream /usr/local/bin/
COPY --from=www /app/www/build/ /app/www/
COPY scripts/certs/generate-cert.sh /usr/local/bin/

# Pre-generated realtime filler/refusal clips (PCM16 / 24 kHz / mono WAVs) and
# their catalog. Baked read-only outside the /app/config and /app/_storage
# mounts; point config_files.audio_streams to /app/audio_streams/audio_streams.json
# and storage_paths.audio_streams to /app/audio_streams to use them.
COPY config/examples/audio_streams/ /app/audio_streams/
COPY config/examples/audio_streams.example.json /app/audio_streams/audio_streams.json

# Create the writable storage and backup directories and a non-root user that
# owns them. The uid/gid are pinned (10001) so host bind mounts can be handed to
# them (scripts/_prepare.sh does this on Linux) and runAsNonRoot can verify the
# numeric user. Keep in sync with Dockerfile.dev and container_uid in
# scripts/_env.sh.
RUN groupadd -r -g 10001 lowPrivGroup && useradd -r -u 10001 -g lowPrivGroup lowPrivUser \
    && mkdir -p /app/_storage /app/_backup_restore \
    && chown -R 10001:10001 /app/_storage /app/_backup_restore

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/agent-stream"]
CMD ["--config", "/app/config/config.toml"]
