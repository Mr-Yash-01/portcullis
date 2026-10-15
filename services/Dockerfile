# One Dockerfile for all three Python microservices; each build contains only its own code.
#   docker build --build-arg SERVICE=auth --build-arg VERSION=v1 -t auth:v1 services/
FROM python:3.14.8-slim

ARG SERVICE
ARG VERSION=v1
ENV SERVICE=${SERVICE} APP_VERSION=${VERSION} \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
# --require-hashes: a tampered or substituted package fails the build (supply-chain protection).
RUN test -n "$SERVICE" && pip install --no-cache-dir --require-hashes -r requirements.txt

COPY common/ common/
COPY ${SERVICE}/ ${SERVICE}/

# Unprivileged user with no home directory or shell login; the code is root-owned and read-only to it.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001:10001

EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn \"$SERVICE.main:app\" --host 0.0.0.0 --port 8000 --no-server-header --timeout-graceful-shutdown 10"]
