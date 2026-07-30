FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Bubblewrap provides the fixed network/filesystem namespace boundary and
# OpenSSL performs Ed25519 receipt signing. The final image digest, rather than
# a mutable tag, is the deployment trust root.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends bubblewrap openssl util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-dev.lock.txt /opt/devflow/build/requirements-dev.lock.txt
RUN python3 -m pip install --no-cache-dir --require-hashes \
      --requirement /opt/devflow/build/requirements-dev.lock.txt

COPY repository/ /opt/devflow/build/repository-install/
RUN python3 -m pip install --no-cache-dir --no-deps --no-build-isolation \
      /opt/devflow/build/repository-install

# Keep the tested repository byte-for-byte separate from the copy used by the
# package build backend, which may create metadata in its input tree.
COPY repository/ /var/lib/devflow/agentteams-cicd/repository/

COPY tester_server.py /opt/devflow/agentteams-cicd/tester_server.py
COPY materialize_demo_assignments.py /opt/devflow/agentteams-cicd/materialize_demo_assignments.py
COPY start_service.py /opt/devflow/agentteams-cicd/start_service.py
COPY finalize_image.py /opt/devflow/build/finalize_image.py
COPY receipt-ed25519.pub /opt/devflow/build/receipt-ed25519.pub
COPY release-template.json /opt/devflow/build/release-template.json
RUN mkdir -p /etc/devflow/agentteams-cicd \
             /var/lib/devflow/agentteams-cicd/assignments \
             /var/lib/devflow/agentteams-cicd/workspaces \
    && python3 -S -m py_compile /opt/devflow/agentteams-cicd/tester_server.py \
    && rm -rf /opt/devflow/agentteams-cicd/__pycache__ \
    && chmod 0555 /opt/devflow/agentteams-cicd/tester_server.py \
                  /opt/devflow/agentteams-cicd/materialize_demo_assignments.py \
                  /opt/devflow/agentteams-cicd/start_service.py \
                  /var/lib/devflow/agentteams-cicd/repository \
    && find /var/lib/devflow/agentteams-cicd/repository -type f -exec chmod 0444 {} + \
    && find /var/lib/devflow/agentteams-cicd/repository -type d -exec chmod 0555 {} + \
    && python3 -S /opt/devflow/build/finalize_image.py \
    && cp /opt/devflow/build/receipt-ed25519.pub \
          /etc/devflow/agentteams-cicd/receipt-ed25519.pub \
    && chmod 0444 /etc/devflow/agentteams-cicd/receipt-ed25519.pub \
    && find /opt/devflow/agentteams-cicd/demo-assignment-templates \
         -type f -exec chmod 0444 {} + \
    && chmod 0555 /opt/devflow/agentteams-cicd/demo-assignment-templates \
    && rm -rf /opt/devflow/build \
    && groupadd --gid 10001 devflow-ci \
    && useradd --uid 10001 --gid 10001 --no-create-home \
         --home-dir /nonexistent --shell /usr/sbin/nologin devflow-ci \
    && chown 10001:10001 /var/lib/devflow/agentteams-cicd/assignments \
                         /var/lib/devflow/agentteams-cicd/workspaces \
    && chmod 0770 /var/lib/devflow/agentteams-cicd/assignments \
                  /var/lib/devflow/agentteams-cicd/workspaces \
    && chmod 0555 /opt/devflow /opt/devflow/agentteams-cicd \
                  /etc/devflow /etc/devflow/agentteams-cicd

EXPOSE 8080

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/python3.12", "-S", "/opt/devflow/agentteams-cicd/start_service.py"]

# Operators export these exact image-generated files and pass them to the
# reconciler.  Building this target does not include or require the private
# receipt key.
FROM scratch AS policy-export
COPY --from=runtime /etc/devflow/agentteams-cicd/policy.json /policy.json
COPY --from=runtime /etc/devflow/agentteams-cicd/test-receipt-policy.json /test-receipt-policy.json
COPY --from=runtime /etc/devflow/agentteams-cicd/receipt-ed25519.pub /receipt-ed25519.pub
COPY --from=runtime /etc/devflow/agentteams-cicd/release.json /release.json

# The runnable digest-pinned artifact is the default final stage.
FROM runtime AS production
