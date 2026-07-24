# Server runtime audit

Audit date: 2026-07-24 (Asia/Shanghai)

## Verified available

- DevFlow source and its Python environment can run on the supplied server.
- The project test, lint, type, Skill static, and behavior-suite validation
  commands can execute there.
- The DevFlow CI/CD MCP service can bind only to loopback and expose its MCP and
  Prometheus endpoints without publishing provider credentials.

## Docker installation trial

The supplied environment is an openEuler 24.03 restricted container, not a
Docker/Kubernetes host. On 2026-07-24, the openEuler repositories successfully
installed Moby Engine and client 25.0.3 plus Docker Compose 1.22.0. A diagnostic
daemon could start only with the `vfs` storage driver and bridge, iptables, and
IP forwarding disabled. Docker Hub was unreachable from the server, while
GHCR and Quay responded.

The decisive local test did not depend on an external registry: a BusyBox
root filesystem was created from installed server files and streamed to the
daemon. Image import failed with `unshare: operation not permitted`. Direct
user, mount, and PID namespace tests failed with the same kernel denial. The
outer container runs with seccomp filtering, excludes `CAP_SYS_ADMIN`, denies
mounts, and exposes no host Docker, containerd, or Podman socket. Systemd is
offline because the container entrypoint is PID 1. The diagnostic daemon was
stopped after the test; the installed Docker and Compose packages remain.

## Verified AgentTeams blocker

The official AgentTeams deployment requires Docker Engine/Desktop or a
Kubernetes cluster. Therefore this environment cannot truthfully produce a
Team Room, AgentTeams task-state reconciliation, or live AgentTeams pause and
approval recording. DevFlow does not substitute its local event bus and label
that as an AgentTeams run.

## Resource required to close this item

Provide either:

- an Ubuntu/Debian VM with Docker Engine and Compose enabled; or
- access to a Kubernetes 1.24+ cluster with permission to install AgentTeams.

Once supplied, the acceptance recording will include Team Room membership,
delegation state changes, a worker failure returned to TeamLeader, a T4 pause,
the human approval event, resumed execution, and the final audit correlation
id.
