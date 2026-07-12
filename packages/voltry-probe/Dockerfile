# syntax=docker/dockerfile:1
#
# Voltry Probe container on the NVIDIA CUDA base. Scan and cert read device state
# without mutating it and make no network requests; submit is a separate opt-in command.
# Multi-arch (amd64 + arm64; arm64 covers Grace). Build from the REPO ROOT so the
# workspace copy of the evidence-schema contract is in the build context (the container
# installs the workspace versions, not the PyPI releases):
#
#   docker buildx build -f packages/voltry-probe/Dockerfile \
#     --platform linux/amd64,linux/arm64 \
#     -t ghcr.io/voltry/voltry-probe:0.3.1 .
#
# Collects no personal data: bundles carry device identifiers (serial, GPU UUID);
# account linkage happens server-side. No secrets are baked in (no keys/.env copied;
# see .dockerignore). Image is signed (cosign) and CVE-scanned (Trivy) in CI.
ARG CUDA_TAG=12.6.2-base-ubuntu22.04
FROM nvcr.io/nvidia/cuda:${CUDA_TAG}

# Pinned uv binary from the official image (no `curl | sh`).
COPY --from=ghcr.io/astral-sh/uv:0.11.21 /uv /uvx /usr/local/bin/

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3.12 python3.12-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/voltry
# evidence-schema (the contract) must be installed before the probe that depends on it.
COPY packages/evidence-schema /opt/voltry/evidence-schema
COPY packages/voltry-probe    /opt/voltry/voltry-probe
RUN uv pip install --system --python python3.12 ./evidence-schema ./voltry-probe

# Run unprivileged; scan reads device state without mutating it and collects no
# personal data.
RUN useradd --create-home --uid 10001 voltry
USER voltry
WORKDIR /home/voltry

ENTRYPOINT ["voltry"]
CMD ["--help"]
