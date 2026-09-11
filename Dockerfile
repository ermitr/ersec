# ERSEC 29.1.1 reproducible container contract.
# Build only with an explicit digest-pinned base image:
#   podman/docker build --build-arg ERSEC_BASE_IMAGE=python:3.12-slim@sha256:<64-hex> .
ARG ERSEC_BASE_IMAGE=python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
FROM ${ERSEC_BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/ersec
COPY . /opt/ersec
RUN python -m pip install --no-cache-dir --no-deps .
ENTRYPOINT ["ersec"]
