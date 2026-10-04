# syntax=docker/dockerfile:1.7

FROM rust:1.85.0-bookworm AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --locked --release \
    -p oryvael-cli \
    -p oryvael-supervisor \
    --bins

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bubblewrap \
        ca-certificates \
        git \
        libgcc-s1 \
        openssl \
        python3 \
        tini \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/oryvael

COPY --from=builder /src/target/release/oryvael /usr/local/bin/oryvael
COPY --from=builder /src/target/release/oryvael-service /usr/local/bin/oryvael-service
COPY examples ./examples
COPY docker/demo-job.json ./docker/demo-job.json
COPY docker/entrypoint.sh /usr/local/bin/oryvael-entrypoint

RUN chmod 0755 /usr/local/bin/oryvael-entrypoint \
    && mkdir -p /var/lib/oryvael /workspace /run/oryvael

ENV ORYVAEL_STATE_DIR=/var/lib/oryvael \
    ORYVAEL_SOCKET=/run/oryvael/trusted.sock \
    ORYVAEL_ROOT_POLICY=/var/lib/oryvael/control/root-policy.json \
    ORYVAEL_ROOT_POLICY_MIN_EPOCH=1

VOLUME ["/var/lib/oryvael", "/workspace"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD oryvael-service status --socket "$ORYVAEL_SOCKET" >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/oryvael-entrypoint"]
CMD ["serve"]
