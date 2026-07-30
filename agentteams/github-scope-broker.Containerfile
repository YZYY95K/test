FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# The content plane uses only this fixed OpenSSL executable for Ed25519
# receipt signing. No Python package manager or build tool is installed.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/devflow
COPY --chown=65532:65532 scripts/github_scope_broker.py /opt/devflow/github_scope_broker.py

ENTRYPOINT ["python3", "-S", "/opt/devflow/github_scope_broker.py"]
