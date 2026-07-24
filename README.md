# DevFlow

DevFlow is an auditable multi-agent system for resolving software issues from
intake to a reviewed pull request. It is built for the **Agent Infra** track of
the Global Open-source AI Challenge and maps its domain agents onto the
[AgentTeams](https://github.com/agentscope-ai/AgentTeams) Manager–Team–Worker
runtime.

The project is intentionally a controlled workflow rather than an unrestricted
agent swarm:

```text
Issue → Triage → Locate → Code → Test → Review → Approval / PR
                    ↑        │       │
                    └────────┴───────┘ feedback loop
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
  validate arguments, require digest-bound approval for dangerous operations,
  and write hash-chained audit evidence.
- Structured logs, batched OTLP/gRPC trace export, and a loopback-only
  Prometheus metrics endpoint.
- Five-tool CI/CD MCP with disposable test execution, coverage evidence,
  digest-approved rollback, and full hash-chain audit verification.
- Short-lived credential capability handles that keep provider secrets inside
  trusted adapters.
- Credential-free offline demo that applies a real candidate patch in a
  temporary repository, executes a real regression test, reviews the result,
  and writes a JSON evidence report.
- AgentTeams `Team` manifest and six self-contained Skill v2 packages with
  typed contracts, deterministic validators, UI metadata, examples, and
  release/rollback policy.
- Paired GLM behavior evaluation that compares each Skill against a no-Skill
  baseline on positive and adversarial routing cases.
- Integrity-checked `HandoffEnvelope` collaboration with versioned artifacts,
  explicit consumer/Skill ownership, retry status, idempotency keys, and
  SHA-256.

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
8. stores the full event and result evidence under `.devflow/runs/`.

Production mode uses variables from `.env.example`. Copy it to `.env` and
provide only the credentials required by the integrations you enable.
Install the persistent ChromaDB-backed RAG implementation with
`python -m pip install -e ".[rag]"`; the credential-free demo does not require
that heavier optional dependency. Production semantic retrieval requires the
configured embedding model to be enabled and funded. Set
`EMBEDDING_PROVIDER=local-hash` only for deterministic offline/degraded
retrieval; it is not presented as equivalent semantic quality.

## AgentTeams deployment

DevFlow targets AgentTeams `agentteams.io/v1beta1`.

```powershell
.\.venv\Scripts\python scripts\build_agentteams_package.py
```

Copy `dist/devflow-worker.zip` into the AgentTeams Manager/controller at
`/tmp/devflow-worker.zip`, then apply:

```bash
agentteams-apply.sh -f agentteams/team.yaml
```

The manifest creates one Team Leader and five workers. AgentTeams supplies the
Matrix room topology, task delegation, heartbeat/state reconciliation, shared
storage, and credential isolation. DevFlow supplies the software-engineering
roles, reusable Skills, schemas, gates, and evidence.

## Project layout

```text
agentteams/        AgentTeams v1beta1 Team manifest and package template
config/            agent, skill, security, MCP, observability configuration
docs/              research notes and competition scorecard
examples/          deterministic regression scenario
skills/            distributable SKILL.md specifications
src/devflow/       runtime, agents, models, RAG, CLI
tests/             unit and end-to-end tests
```

## Verification

```powershell
.\.venv\Scripts\python -m ruff check src tests examples
.\.venv\Scripts\python -m mypy src
.\.venv\Scripts\python -m pytest --cov=devflow --cov-report=term --cov-fail-under=80 -q
.\.venv\Scripts\python scripts\evaluate_skills.py
.\.venv\Scripts\python scripts\run_behavior_evals.py --validate-only
.\.venv\Scripts\devflow demo
```

See [the research basis](docs/RESEARCH.md), [competition scorecard](docs/SCORECARD.md),
[Skill engineering standard](docs/SKILL_ENGINEERING.md),
[behavior evaluation protocol](docs/SKILL_BEHAVIOR_EVAL.md), and
[AgentTeams mapping](docs/AGENTTEAMS.md) for design rationale and remaining work.
The executable responsibility matrix and MCP trust model are documented in
[Agent boundaries and MCP trust model](docs/BOUNDARIES_AND_MCP.md).
The latest model-run evidence is recorded in
[GLM-5.2 Skill behavior evidence](docs/evidence/SKILL_BEHAVIOR_GLM52.md).
Executable provider boundaries are mapped in
[Infrastructure and trust boundaries](docs/INFRASTRUCTURE.md); the supplied
server's AgentTeams compatibility audit is recorded in
[Server runtime audit](docs/evidence/SERVER_RUNTIME_AUDIT.md).

## Security

- Workers receive gateway-scoped consumer credentials, not raw provider keys.
- Generated paths must remain repository-relative.
- Secret-shaped output and dangerous execution patterns are blocked.
- Test execution occurs in a temporary copy in the offline demo.
- CI failure and high/critical findings block promotion.
- T4/T5 issues always require a human approval event.

Never commit `.env`, runtime evidence containing private code, or real tokens.

## License

Apache-2.0. See [LICENSE](LICENSE).
