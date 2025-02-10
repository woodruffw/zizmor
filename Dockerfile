FROM python:3.12-slim-bookworm AS build

LABEL org.opencontainers.image.source=https://github.com/woodruffw/zizmor

# Zizmor version to install (set as an argument to pair with zizmor releases)
ARG ZIZMOR_VERSION

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Add Rust to PATH
ENV PATH="/root/.local/bin:${PATH}"

RUN set -eux && \
    apt-get update && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pip install uv && \
    uv tool install zizmor=="${ZIZMOR_VERSION}" && \
    which zizmor

# ------------------------------------------------------------------------------
# Runtime image
# ------------------------------------------------------------------------------

FROM python:3.12-slim-bookworm

# Copy necessary files from build stage
COPY --from=build /root/.local/bin/zizmor /root/.local/bin/zizmor

# Set the entrypoint to zizmor
ENTRYPOINT ["/root/.local/bin/zizmor"]