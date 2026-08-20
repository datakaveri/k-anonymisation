# =============================================================================
# SKALD — Multi-stage Rust build (static musl binary)
#
# Stage 1 (builder): Compiles a fully static binary via musl libc on Alpine.
#                    No glibc dependency — nothing from this stage reaches
#                    the final image except the binary itself.
# Stage 2 (runtime): Uses 'scratch' (empty base) — zero OS packages,
#                    zero CVEs, ~10 MB final image.
#
# I/O contract (same as the legacy Python container):
#   Mount config JSON  →  /app/config/
#   Mount input CSV    →  /app/data/
#   Read results from  →  /app/output/
#
# Flags pass through the entrypoint, so a container can be pointed at a
# specific config or input without rebuilding:
#   docker run … skald --config config/telangana.json --data data/export.csv
# The SKALD_CONFIG / SKALD_DATA / SKALD_OUTPUT environment variables do the
# same. A postgres input or output sink is configured in the config JSON.
# =============================================================================

# ── Stage 1: Build ────────────────────────────────────────────────────────────
# rust:alpine ships Alpine Linux — far fewer CVEs than Debian slim.
# Toolchain floor is set by the multi-tabular dependencies, not by our own code:
# calamine 0.36, rust_xlsxwriter 0.97 and zip 8.6 all declare rustc 1.88 as their
# MSRV, so anything older fails the build outright. Pinned (not `rust:alpine`)
# to keep the image byte-reproducible for attestation.
FROM rust:1.92-alpine AS builder
LABEL org.opencontainers.image.source=https://github.com/datakaveri/k-anonymisation-SKALD

# musl-dev provides headers; gcc on Alpine already targets musl natively —
# no cross-compiler needed. `ring` (the TLS crypto provider behind the
# PostgreSQL connector) compiles C, so gcc is named explicitly rather than
# relied on as a base-image detail. Register the musl target with rustup.
RUN apk add --no-cache musl-dev gcc \
    && rustup target add x86_64-unknown-linux-musl

# Static linking: embed musl crt so the binary has zero runtime deps
ENV RUSTFLAGS="-C target-feature=+crt-static"

WORKDIR /build

# Copy manifests first — dependency layer is cached independently of source
COPY SKALD/Cargo.toml SKALD/Cargo.lock ./

# Stub src so Cargo can fetch + cache all dependencies without the real source
RUN mkdir -p src/pipeline src/bin \
    && echo 'pub mod pipeline { pub mod entry {} }' > src/lib.rs \
    && echo 'fn main() {}' > src/bin/skald_pipeline.rs \
    && cargo build --release --target x86_64-unknown-linux-musl \
                   --bin skald_pipeline 2>/dev/null || true \
    && rm -rf src

# Real source — deps already cached above, only skald_ola2 recompiles
COPY SKALD/src ./src
RUN touch src/lib.rs src/bin/skald_pipeline.rs \
    && cargo build --release --target x86_64-unknown-linux-musl \
                   --bin skald_pipeline

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# 'scratch' is an empty image — no shell, no OS, no CVEs
FROM scratch AS runtime

# Copy CA certificates for any future HTTPS calls (e.g. remote config fetch)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the statically linked binary
COPY --from=builder \
    /build/target/x86_64-unknown-linux-musl/release/skald_pipeline \
    /skald_pipeline

# Pipeline resolves config/, data/, output/ relative to CWD unless flags or
# SKALD_* environment variables say otherwise
WORKDIR /app

VOLUME ["/app/config", "/app/data", "/app/output"]

ENTRYPOINT ["/skald_pipeline"]
