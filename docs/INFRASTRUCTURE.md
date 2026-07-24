# Executable infrastructure and trust boundaries

This document is an evidence map for the infrastructure that is executed by
DevFlow. A YAML declaration alone is not treated as an implementation.

## CI/CD MCP

`devflow.mcp.cicd_server` is a FastMCP server with five callable tools:

| Tool | Owner | Runtime boundary | Evidence |
|---|---|---|---|
| `run_tests` | TesterAgent / `test-runner` | Applies a typed patch in a disposable repository copy and runs server-owned argv | `tests/test_mcp_adapter.py`, `tests/test_mcp_policy.py` |
| `trigger_pipeline` | TesterAgent / `test-runner` | Runs a registered test command in a disposable copy; clients cannot send shell text | `tests/test_infrastructure.py` |
| `get_test_results` | TesterAgent / `test-runner` | Reads only an opaque pipeline id | `tests/test_mcp_adapter.py` |
| `get_coverage` | TesterAgent / `test-runner` | Parses `coverage.json` produced by that isolated run | `tests/test_infrastructure.py` |
| `rollback_deployment` | TeamLeader / `team-orchestration` | Requires a digest-bound human approval, invokes server-owned argv, health-checks, then atomically changes the release registry | `tests/test_infrastructure.py`, `tests/test_mcp_policy.py` |

Every call is re-authorized inside the server from a signed Agent/Skill/task
context. Unknown tools, mismatched ownership, stale contexts, unsafe branches,
protected paths, and unapproved destructive calls fail before execution. Audit
records contain argument digests rather than secret values.

## Observability

- `configure_otlp_tracing` installs an OTLP/gRPC exporter with a batch span
  processor and an explicit `service.name` resource.
- `/metrics` renders Prometheus 0.0.4 text from thread-safe counters, gauges,
  and summaries.
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

Agents receive a signed, short-lived capability handle, never a provider
secret. The trusted adapter resolves a handle only when all of these match:

1. HMAC signature and expiry;
2. expected Agent identity;
3. exact capability;
4. current grant (revocation is checked at resolution time); and
5. server-side capability-to-environment-variable mapping.

The handle carries no token, API key, or environment variable value.

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
