# Executable infrastructure and trust boundaries

This document is an evidence map for the infrastructure that is executed by
DevFlow. A YAML declaration alone is not treated as an implementation.
Evidence is separated into local verification, candidate/deployment preflight,
historical live records, and current server evidence still pending.

## CI/CD MCP

The AgentTeams candidate surface is `agentteams/cicd/tester_server.py`, a
Streamable HTTP MCP intended for a separate `devflow-tester-cicd` Deployment.
The desired state gives the Tester Worker only its ClusterIP URL and declares
the signing-key mount only on the independent main CI container. This is a
candidate manifest, not current live mount evidence. It exposes exactly one
tool, `run_tests`; no
Agent can select a shell command, executable, repository root, workspace,
network mode, suite, or resource limit. Those values come from canonical
policies mounted at `/etc/devflow/agentteams-cicd/policy.json` and
`/etc/devflow/agentteams-cicd/test-receipt-policy.json`, bound to the exact
image-fixed runtime, clean repository commit, repository manifest, server
bytes, isolation executable, and acknowledged `test-runner` assignment.

The server validates the source HandoffEnvelope, task/run/trace identity,
candidate digest, immutable revision, and one policy-derived workspace binding
before copying baseline and candidate trees. It executes the fixed test adapter
inside the configured isolation wrapper with an empty allowlisted environment,
bounded time/CPU/memory/process/file descriptors/output, then returns integrity-
bound baseline and candidate evidence. Test or manifest mutation, an unacked or
cross-task assignment, a wrong candidate/revision, unknown JSON fields, an
extra MCP tool, or placement on any non-Tester role fails closed.

The current deployable image is truthfully limited to two fixed finals demo
assignments and one image-fixed clean DevFlow repository fixture. It provides
one T2 focused-suite route and one T3 full-suite route. `/readyz` identifies
that source as `image-fixed-demo-fixture/v1` and explicitly reports that it is
not a live AgentTeams task projection. Arbitrary repositories and real-time
controller assignments are not implemented or claimed. The image/reconciler
path is locally tested but remains candidate evidence until a digest-pinned
cluster deployment and post-apply preflight are recorded. Even a successful
preflight is not end-to-end evidence: a separate real
`run_tests -> signed receipt -> Leader accept -> dual readback -> retry`
record is required before `ciServiceVerified`, `endToEndReady`, or `verified`
may be true.

`src/devflow/mcp/cicd_server.py` is a different, explicitly local contract:
`devflow-cicd-portable`, configured only by
`config/mcp_servers.portable.yaml`. It accepts a typed Patch but no suite flag;
the HMAC-authenticated local context supplies `risk_tier`, which selects one of
two fixed server-owned argv profiles. Its policy identity is
`portable-immutable-baseline/v1` and its execution profile is
`portable-process-only/v1`, so its evidence cannot be mistaken for the
AgentTeams Bubblewrap profile. Lower-level pipeline and rollback primitives
remain separately unit-tested in the library but are not registered by either
one-tool server. Repository publication, deployment, and rollback remain
external.

## Observability

- `configure_otlp_tracing` installs an OTLP/gRPC exporter with a batch span
  processor and an explicit `service.name` resource. The production exporter is
  exercised over a real loopback gRPC connection against an OTLP TraceService
  receiver in `test_trace_provider_reaches_a_real_otlp_grpc_collector`; this is
  local network evidence, not an external production-collector claim.
- `/metrics` renders Prometheus 0.0.4 text from thread-safe counters, gauges,
  and histograms, and the integration test retrieves that text over HTTP.
- The metric listener refuses non-loopback binds. External access belongs at a
  separately authenticated collector or reverse proxy.
- Pipeline activity is represented by the `devflow_pipeline_active` gauge.

## Audit integrity

The JSONL MCP audit log is a SHA-256 hash chain. On startup the full
existing chain is verified, including sequence, predecessor digest, record
digest, and link continuity. A single modified historical record makes the log
fail closed unless an attacker can rewrite the whole evidence store; production
deployments must therefore ship the log to append-only external storage.
`verify_audit_chain` is also available for offline evidence checks.

## Credential broker

In the locally tested portable credential-broker path, the caller receives a
signed, short-lived capability handle rather than the mapped provider secret.
This does not claim that every current OpenClaw Worker workspace is free of MCP
consumer/configuration material. The trusted adapter resolves a handle only
when all of these match:

1. HMAC signature and expiry;
2. expected Agent identity;
3. exact capability;
4. current grant (revocation is checked at resolution time); and
5. server-side capability-to-environment-variable mapping.

The handle carries no token, API key, or environment variable value.

`test_fastmcp_rollback_closes_policy_credential_health_and_audit_loop` joins
FastMCP dispatch, signed identity, digest-bound approval, one-shot replay
protection, credential resolution inside the trusted adapter, provider health,
atomic release state and offline audit-chain verification in one local
integration. It does not replace a clean-server run against a real deployment
provider.

## RAG modes

`openai-compatible` uses the configured embedding provider. `local-hash` is a
deterministic, normalized, credential-free degraded mode for offline operation;
it is deliberately described as feature hashing rather than semantic model
quality. ChromaDB remains the persistent vector store and is loaded only when
the `rag` extra is installed.

## Reproducible quality gate

```bash
python -m pytest --cov=devflow --cov-report=term --cov-fail-under=80 -q
python -m ruff check .
python -m mypy src scripts tests
```

The same 80% aggregate coverage threshold is enforced in GitHub Actions on
Python 3.10 and 3.12.
