# DevFlow

DevFlow is an auditable multi-agent system for resolving software issues from
intake to verified candidate evidence. It is built for the **Agent Infra** track of
the Global Open-source AI Challenge and maps its domain agents onto the
[AgentTeams](https://github.com/agentscope-ai/AgentTeams) Manager–Team–Worker
runtime.

The project is intentionally a controlled workflow rather than an unrestricted
agent swarm:

```text
Issue → Triage → GitHub evidence → Locate → Code → Test → Review
                                              ↑       │       │
                                              └───────┴───────┘ retry via Leader
Review → verified candidate / T4-T5 external approval pause
```

Every stage has a structured input/output contract, explicit failure behavior,
security boundaries, and an event trail. T4/T5 changes stop for recorded human
approval.

## What works now

- Six domain agents: Team Leader, Triage, Locator, Coder, Tester, Reviewer.
- Typed event bus and lifecycle events for local execution.
- AST-aware code indexing and an experience store backed by ChromaDB.
- OpenAI-compatible LLM client with Pydantic response validation.
- Default-deny MCP boundaries that authorize the exact Agent + active Skill,
  validate arguments and write hash-chained audit evidence. The current
  AgentTeams profile grants no repository write, merge, deploy, or rollback.
- Structured logs, batched OTLP/gRPC trace export, and a loopback-only
  Prometheus metrics endpoint.
- Tester-only AgentTeams CI/CD MCP exposing exactly one policy-owned
  `run_tests` action with immutable-revision and acknowledged-task binding;
  no Agent supplies commands, executable paths, suites, or repository roots.
  The locally tested candidate CI service is designed to sign a short-lived
  Ed25519 execution receipt. TeamHarness verifies the fixed public key and full
  result binding before Leader acceptance. Within the active Leader Pod
  incarnation, an exact retry carrying the same JTI and the same accept
  request/result binding returns the committed result idempotently; a
  conflicting binding is rejected, and an uncertain authoritative state stays
  `pending` and fails closed. The ledger does not survive Pod replacement, and
  receipts expire after 120 seconds.
  The deployable candidate is explicitly limited to one image-fixed clean
  repository and two fixed finals demo assignments; it is not yet a live,
  arbitrary AgentTeams task projection.
- A locally tested credential-broker path whose short-lived capability handles
  keep the mapped provider secret inside the trusted adapter. This is not a
  claim that every current OpenClaw Worker workspace is free of credential or
  MCP consumer material.
- Credential-free offline demo that applies a real candidate patch in a
  temporary repository, executes a real regression test, reviews the result,
  and writes a JSON evidence report plus a durable SQLite route ledger whose
  digest-only audit chain is recomputed before reporting success.
- AgentTeams `Team` manifest and six role-scoped Worker packages containing
  only each role's self-contained, versioned Skill set, with
  typed contracts, deterministic validators, UI metadata, examples, and
  release/rollback policy.
- Historical paired GLM behavior evaluation for six earlier Skills against a
  no-Skill baseline on positive and adversarial routing cases. The current
  seven-Skill version has 14 structural behavior cases and still requires a
  fresh external-model rerun before claiming seven-Skill behavioral coverage.
- Integrity-checked `HandoffEnvelope` collaboration with versioned artifacts,
  explicit consumer/Skill ownership, parent-causal result binding, transport
  status semantics, idempotency keys, and SHA-256.

## Quick start

Python 3.10–3.12 is recommended.

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\devflow validate
.\.venv\Scripts\devflow demo
.\.venv\Scripts\python -m pytest
```

The demo does not need an API key or GitHub token. It:

1. classifies the bundled calculator issue;
2. retrieves and identifies the faulty function;
3. produces a structured one-line patch;
4. copies the fixture repository to a temporary sandbox;
5. proves that the baseline fails and the candidate passes;
6. performs the review/approval gate;
7. distills and stores a provenance-linked reusable experience;
8. seals six routed tasks and verifies the collaboration audit hash chain;
9. stores the event, result, and SQLite route evidence under `.devflow/runs/`.

The fixed logical request and machine-checkable expected assertions are in
[`examples/prelim_sample`](examples/prelim_sample). The report timestamp and
content-derived digests vary by run; the acceptance fields in
`expected_output.json` are stable and are enforced by `tests/test_demo.py`.

Production mode uses variables from `.env.example`. Copy it to `.env` and
provide only the credentials required by the integrations you enable.
Install the persistent ChromaDB-backed RAG implementation with
`python -m pip install -e ".[rag]"`; the credential-free demo does not require
that heavier optional dependency. Production semantic retrieval requires the
configured embedding model to be enabled and funded. Set
`EMBEDDING_PROVIDER=local-hash` only for deterministic offline/degraded
retrieval; it is not presented as equivalent semantic quality.
Production RAG additionally requires a server-held `DEVFLOW_RAG_HMAC_KEY` of
at least 32 bytes and an exact tenant/repository/revision scope. Missing keys,
branch-like revisions, stale records, cross-tenant results, and modified
content, metadata, or vectors fail closed.

## AgentTeams deployment

The checked-in deployment manifest targets the exact AgentTeams `v1.2.0-beta.1`
`agentteams.io/v1beta1` contract, not a floating `main` branch. The upstream
tag, commit and Team-CRD digest are recorded in
[`agentteams/upstream.lock.yaml`](agentteams/upstream.lock.yaml); the current
upstream membership-only API is treated as an explicit future migration.
The competition's five mandatory design mappings—role orchestration, task
decomposition, context transfer, collaborative execution, and state
tracking—are mapped to AgentTeams native objects and clearly separated from
DevFlow extensions in
[`docs/submission/AGENTTEAMS_MAPPING_CN.md`](docs/submission/AGENTTEAMS_MAPPING_CN.md).

```powershell
.\.venv\Scripts\python scripts\verify_agentteams_upstream.py
.\.venv\Scripts\python scripts\build_agentteams_package.py
```

Publish the six role-scoped archives through the private in-cluster package
Service. The versioned ConfigMap is made immutable before any Pod can consume
it; changing package bytes therefore requires a new release version.

```bash
kubectl create configmap devflow-worker-packages-v2-1-0 -n agentteams-system \
  --from-file=dist/devflow-lead-v2.1.0.zip \
  --from-file=dist/devflow-triage-v2.1.0.zip \
  --from-file=dist/devflow-locator-v2.1.0.zip \
  --from-file=dist/devflow-coder-v2.1.0.zip \
  --from-file=dist/devflow-tester-v2.1.0.zip \
  --from-file=dist/devflow-reviewer-v2.1.0.zip
kubectl patch configmap devflow-worker-packages-v2-1-0 \
  -n agentteams-system --type=merge -p '{"immutable":true}'
kubectl apply -n agentteams-system -f agentteams/package-server.yaml
kubectl rollout status -n agentteams-system deployment/devflow-package
kubectl apply -n agentteams-system -f agentteams/team.yaml
```

The manifest creates one Team Leader and five workers. AgentTeams supplies the
Matrix room topology, task delegation, heartbeat/state reconciliation, and
shared storage. DevFlow supplies the software-engineering roles, reusable
Skills, schemas, gates, and evidence. Credential boundaries are integration-
specific: the historical scoped GitHub path kept the upstream provider token
behind its Broker, while the current OpenClaw audit still reports workspace
credential/configuration material and `strongBoundaryEnforceable=false`.

## Project layout

```text
agentteams/        AgentTeams v1beta1 Team manifest and package template
config/            agent, skill, security, MCP, observability configuration
docs/              research notes and competition scorecard
examples/          deterministic regression scenario
skills/            distributable SKILL.md specifications
src/devflow/       runtime, agents, models, RAG, CLI
tests/             unit, contract, and local integration tests
```

## Verification

```powershell
.\.venv\Scripts\python -m devflow.cli validate
.\.venv\Scripts\python scripts\verify_agentteams_upstream.py
.\.venv\Scripts\python -m ruff check .
.\.venv\Scripts\python -m mypy src scripts tests
.\.venv\Scripts\python -m pytest -ra --cov=devflow --cov-report=term-missing --cov-fail-under=80 -q
.\.venv\Scripts\python scripts\evaluate_skills.py
.\.venv\Scripts\python scripts\run_behavior_evals.py --validate-only
.\.venv\Scripts\python scripts\run_repository_benchmark.py --repair-manifest benchmarks\repository_repair\tasks.yaml --repos-root .devflow\benchmark-repos --validate-only
.\.venv\Scripts\devflow demo --output-dir .devflow\runs\finals-demo
git diff --check
```

See [the research basis](docs/RESEARCH.md), [competition scorecard](docs/SCORECARD.md),
[finals acceptance matrix](docs/finals/ACCEPTANCE_MATRIX_CN.md),
[Skill engineering standard](docs/SKILL_ENGINEERING.md),
[behavior evaluation protocol](docs/SKILL_BEHAVIOR_EVAL.md), and
[AgentTeams mapping](docs/AGENTTEAMS.md) for design rationale and remaining work.
The executable responsibility matrix and MCP trust model are documented in
[Agent boundaries and MCP trust model](docs/BOUNDARIES_AND_MCP.md).
The latest model-run evidence is recorded in
[GLM-5.2 Skill behavior evidence](docs/evidence/SKILL_BEHAVIOR_GLM52.md).
Executable provider boundaries are mapped in
[Infrastructure and trust boundaries](docs/INFRASTRUCTURE.md). Historical
server/AgentTeams evidence, current local MCP and failure-path evidence, and
their remaining gaps are consolidated in
[AgentTeams live evidence](docs/evidence/AGENTTEAMS_LIVE_20260727.md); the
quantitative evaluation design is in [Repository benchmark](docs/BENCHMARK.md).
Finals-facing source material lives under `docs/finals/`; rendered PPT/PDF files
live under `outputs/`. `scripts/build_finals_submission.py` assembles the exact
allowlisted source, material, evidence, dependency locks, SBOM, license ledger,
checksums, and provenance from a clean tagged Git object. It refuses to treat a
dirty worktree or the historical preliminary ZIP as a finals release.

## Security

- On the scoped GitHub path, Workers receive a gateway consumer credential, not
  the upstream GitHub token. This does not establish that all Worker workspaces
  contain no credential/configuration material.
- Generated paths must remain repository-relative.
- Managed DevFlow validators and MCP paths reject their configured
  secret-shaped output and dangerous execution patterns; this is not a global
  hostile-runtime data-loss-prevention guarantee.
- Test execution occurs in a temporary copy in the offline demo.
- CI failure and high/critical findings block promotion.
- T4/T5 issues pause until a trusted external authority signs the exact
  revision/candidate/test/review target; chat text and Agent-authored approval
  are never authority.

Never commit `.env`, runtime evidence containing private code, or real tokens.

## License

Apache-2.0. See [LICENSE](LICENSE).
