# syntax=docker/dockerfile:1.6

FROM debian:bookworm-slim

ARG TARGETARCH
ARG TARGETVARIANT
ARG BINARY_NAME=pushgo-gateway

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY dist /dist

RUN set -eux; \
    case "${TARGETARCH}/${TARGETVARIANT}" in \
        amd64/) suffix="amd64" ;; \
        arm64/) suffix="arm64" ;; \
        arm/v7) suffix="armv7" ;; \
        *) echo "Unsupported TARGETARCH/TARGETVARIANT=${TARGETARCH}/${TARGETVARIANT}" >&2; exit 1 ;; \
    esac; \
    cp "/dist/${BINARY_NAME}-${suffix}-musl" "/usr/local/bin/${BINARY_NAME}"; \
    chmod +x "/usr/local/bin/${BINARY_NAME}"; \
    rm -rf /dist

ENV RUST_BACKTRACE=1
ENV PUSHGO_HTTP_ADDR=0.0.0.0:6666
ENV PUSHGO_TOKEN=
ENV PUSHGO_DB_URL=
ENV PUSHGO_TOKEN_SERVICE_URL=http://pushgo-token-service:6766
ENV PUSHGO_PRIVATE_CHANNEL_ENABLED=false
ENV PUSHGO_PRIVATE_QUIC_BIND=127.0.0.1:5223
ENV PUSHGO_PRIVATE_QUIC_PORT=443
ENV PUSHGO_PRIVATE_TLS_CERT=
ENV PUSHGO_PRIVATE_TLS_KEY=
ENV PUSHGO_PRIVATE_TCP_BIND=127.0.0.1:5223
ENV PUSHGO_PRIVATE_TCP_PORT=5223
ENV PUSHGO_PRIVATE_TCP_TLS_OFFLOAD=false

EXPOSE 6666
EXPOSE 5223/tcp
EXPOSE 5223/udp

ENTRYPOINT ["/usr/local/bin/pushgo-gateway"]
