# syntax=docker/dockerfile:1
#
# Distroless container recipe for apohara-agentguard. The builder stage
# cross-builds the static musl binary (same target as the release workflow's
# verified static build); the runtime stage is gcr.io/distroless/cc-debian12
# running as nonroot — no shell, no package manager, minimal surface.
#
# Build:
#   docker build -t apohara-agentguard \
#     --build-arg VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)" \
#     --build-arg REVISION="$(git rev-parse HEAD)" .
#
# Run (the CLI is the entrypoint; append subcommands):
#   docker run --rm apohara-agentguard version
#
# NOTE on sandboxing inside containers: the seccomp+Landlock tiers need the
# corresponding kernel features; under a default docker/seccomp profile some
# syscalls may already be filtered, so run `doctor` in-container to confirm
# what this runtime can enforce.
#
# TODO-humano: wire an optional GHCR publish workflow (build on tag,
# push to ghcr.io/suarezpm/apohara-agentguard:<tag> with cosign signing) if
# container distribution is wanted for the launch.

FROM rust:bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /src
COPY . .
RUN cargo build --release --locked --target x86_64-unknown-linux-musl \
        --bin apohara-agentguard


FROM gcr.io/distroless/cc-debian12:nonroot

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="apohara-agentguard" \
      org.opencontainers.image.description="Deterministic, offline safety hook + local seccomp+Landlock sandbox + input firewall for AI coding agents" \
      org.opencontainers.image.source="https://github.com/SuarezPM/apohara-agentguard" \
      org.opencontainers.image.url="https://github.com/SuarezPM/apohara-agentguard" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/apohara-agentguard \
    /usr/local/bin/apohara-agentguard

ENTRYPOINT ["/usr/local/bin/apohara-agentguard"]
