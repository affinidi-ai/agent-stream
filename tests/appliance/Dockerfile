# Testkit build of agent-stream — DEBUG profile.
#
# The testkit authenticates to the admin API through the debug-only test-auth
# bootstrap endpoint, which is compiled in ONLY under `debug_assertions`. We must
# therefore build the DEBUG binary. This image must never be used as a
# production artefact (see tests/appliance/README.md).
#
# Build context is the repository root (see docker-compose.yml `context: ../..`).

ARG TESTKIT_RUNTIME_IMAGE=debian:bookworm-slim

FROM rust:1.95.0-slim-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libdbus-1-dev \
    libssl-dev \
    libsasl2-2 \
    libsasl2-dev \
    libsasl2-modules \
    protobuf-compiler \
    cmake \
    libcurl4-openssl-dev \
    libxml2-dev \
    libxmlsec1-dev \
    libclang-dev \
    pkg-config \
    nodejs \
    npm \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependency compilation (debug profile).
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo chef cook --recipe-path recipe.json

# Build the debug binary (only this layer rebuilds on source changes).
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --bin agent-stream

FROM ${TESTKIT_RUNTIME_IMAGE} AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libdbus-1-3 \
    libssl3 \
    openssl \
    libxmlsec1-openssl \
    ca-certificates \
    iputils-ping \
    libsasl2-2 \
    bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY scripts/certs/generate-cert.sh /app/scripts/certs/generate-cert.sh
RUN /app/scripts/certs/generate-cert.sh >/dev/null
COPY config/examples/agent-stream.example.json /app/config/agent-stream.json
COPY config/examples/metrics.example.json /app/config/metrics.json
COPY config/examples/rbac.example.json /app/config/rbac.json
COPY tests/appliance/config/managed.limits.json /app/config/limits.json
COPY config/examples/saml.example.json /app/config/saml.json
COPY config/examples/prompt-guard.example.json /app/config/prompt-guard.json
COPY config/examples/marketplace-models.example.json /app/config/marketplace-models.json
COPY config/examples/rejection_categories.example.json /app/config/rejection_categories.json
COPY config/examples/audio_streams.example.json /app/config/audio_streams.json
COPY config/examples/surface_templates /app/config/surface_templates
COPY config/examples/defaults /app/config/defaults
RUN sed -i 's/YOUR_DOMAIN/localhost/g; s/"port": 8080/"port": 8280/; s/localhost:8080/localhost:8280/g' /app/config/agent-stream.json \
    && grep -q '"port": 8280' /app/config/agent-stream.json \
    && mkdir -p /app/www

FROM runtime AS ci
COPY tests/appliance/bin/agent-stream /app/agent-stream
CMD ["/app/agent-stream", "--config", "/app/config/config.toml"]

FROM runtime AS local
COPY --from=builder /app/target/debug/agent-stream /app/agent-stream
CMD ["/app/agent-stream", "--config", "/app/config/config.toml"]
