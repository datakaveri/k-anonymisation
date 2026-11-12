# =============================================================================
# SKALD — Multi-stage Rust build (static musl binary)
#
# Stage 1 (builder): Compiles a fully static binary via musl libc on Alpine.
#                    No glibc dependency — nothing from this stage reaches
#                    the final image except the binary itself.
# Stage 2 (runtime): Uses 'scratch' (empty base) — zero OS packages,
#                    zero CVEs, ~10 MB final image, running as a non-root user.
#
# I/O contract:
#   Mount config JSON  →  /app/config/   (read-only)
#   Mount input data   →  /app/data/     (read-only)
#   Read results from  →  /app/output/   (the release — safe to ship)
#   Key material in    →  /app/keys/     (token vaults, keys, salts — NEVER ship)
#   Scratch            →  /app/chunks/   (raw rows during a run; use a tmpfs)
#
# The process runs as uid:gid 65532:65532. Host directories bind-mounted at
# /app/output, /app/keys and /app/chunks must be writable by that uid
# (`chown 65532:65532 output keys`), or run with `--user "$(id -u):$(id -g)"`.
#
# Flags pass through the entrypoint, so a container can be pointed at a
# specific config or input without rebuilding:
#   docker run … skald --config config/my_dataset.json --data data/export.csv
# The SKALD_CONFIG / SKALD_DATA / SKALD_OUTPUT / SKALD_KEYS environment
# variables do the same. A postgres input or output sink is configured in the
# config JSON.
# =============================================================================

# ── Stage 1: Build ────────────────────────────────────────────────────────────
# Pinned by digest so the image is byte-reproducible for attestation; bump the
# tag and the digest together with SKALD/rust-toolchain.toml. The toolchain
# file is not copied in: the pinned image already fixes the compiler, and the
# file would make rustup download clippy/rustfmt during the build.
FROM rust:1.99-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS builder
LABEL org.opencontainers.image.source=https://github.com/datakaveri/k-anonymisation
LABEL org.opencontainers.image.licenses=Apache-2.0

# musl-dev provides headers; gcc on Alpine already targets musl natively —
# no cross-compiler needed. `ring` (the TLS crypto provider behind the
# PostgreSQL connector) compiles C, so gcc is named explicitly rather than
# relied on as a base-image detail. Register the musl target with rustup.
RUN apk add --no-cache musl-dev gcc \
    && rustup target add x86_64-unknown-linux-musl

# Static linking: embed musl crt so the binary has zero runtime deps
ENV RUSTFLAGS="-C target-feature=+crt-static"

WORKDIR /build

# Copy manifests first — dependency layer is cached independently of source.
# benches/ is declared in Cargo.toml, so Cargo needs it present to parse the
# manifest even though the image never builds it.
COPY SKALD/Cargo.toml SKALD/Cargo.lock ./
COPY SKALD/benches ./benches

# Stub src so Cargo can fetch + cache all dependencies without the real source
RUN mkdir -p src/pipeline src/bin \
    && echo 'pub mod pipeline { pub mod entry {} }' > src/lib.rs \
    && echo 'fn main() {}' > src/bin/skald_pipeline.rs \
    && cargo build --release --locked --target x86_64-unknown-linux-musl \
                   --bin skald_pipeline 2>/dev/null || true \
    && rm -rf src

# Real source — deps already cached above, only skald_ola2 recompiles
COPY SKALD/src ./src
RUN touch src/lib.rs src/bin/skald_pipeline.rs \
    && cargo build --release --locked --target x86_64-unknown-linux-musl \
                   --bin skald_pipeline

# The runtime has no shell to create directories with, so lay out /app here,
# owned by the runtime user.
RUN mkdir -p /rootfs/app/config /rootfs/app/data /rootfs/app/output /rootfs/app/keys /rootfs/app/chunks \
    && chmod 0700 /rootfs/app/keys

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# 'scratch' is an empty image (no shell, no OS, no CVEs). It has no digest to
# pin: it is not pulled from a registry.
FROM scratch AS runtime

# Copy CA certificates for TLS to PostgreSQL (verify-full against public CAs)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the statically linked binary
COPY --from=builder \
    /build/target/x86_64-unknown-linux-musl/release/skald_pipeline \
    /skald_pipeline

COPY --from=builder --chown=65532:65532 /rootfs/app /app

# Pipeline resolves config/, data/, output/, keys/ and chunks/ relative to CWD
# unless flags or SKALD_* environment variables say otherwise
WORKDIR /app

# Non-root: a compromised or misconfigured run cannot write outside its volumes.
USER 65532:65532

VOLUME ["/app/config", "/app/data", "/app/output", "/app/keys", "/app/chunks"]

# SKALD is a one-shot batch job; the check only proves the binary starts.
HEALTHCHECK --interval=30s --timeout=5s --retries=1 CMD ["/skald_pipeline", "--version"]

ENTRYPOINT ["/skald_pipeline"]
