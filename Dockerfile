FROM rust:1.83.0-slim-bookworm AS build

LABEL org.opencontainers.image.source=https://github.com/woodruffw/zizmor

# Zizmor version to install (set as an argument to pair with zizmor releases)
ARG ZIZMOR_VERSION

RUN set -eux && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN cargo install --version ${ZIZMOR_VERSION} zizmor

# ------------------------------------------------------------------------------
# Runtime image
# ------------------------------------------------------------------------------

# https://hub.docker.com/_/debian/tags?name=bookworm-slim
FROM debian:bookworm-slim

COPY --from=build /usr/local/cargo/bin/zizmor /usr/local/bin/zizmor
WORKDIR /app
ENTRYPOINT ["/bin/bash"]
