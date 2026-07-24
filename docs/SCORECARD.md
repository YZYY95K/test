# Agent Infra competition scorecard

Official source: [Global Open-source AI Challenge — Agent Infra](https://www.goaihz.com/tracks).
This working scorecard translates the published rubric into verifiable
engineering deliverables.

| Dimension | Weight | Current evidence | Remaining highest-value work |
|---|---:|---|---|
| Scenario value and replicability | 25% | End-to-end software issue resolution; explicit users and risk tiers; three fixed OSS revisions with 24 repository-grounded tasks; 24/24 exact decisions, measured latency, tokens, safety, and human-gate rate | Add full standardized patch-resolution and three organization personas |
| Multi-Agent collaboration and autonomous closure | 25% | 6 non-interchangeable roles, DAG plan, digest-bound hand-offs that validate consumer + owned Skill, explicit READY/RETRY/BLOCKED routing, T4/T5 human gate, AgentTeams Team manifest | Run and record the full scenario inside an installed AgentTeams Matrix room |
| Skill engineering and ecosystem reuse | 25% | 6 self-contained v2 Skills; typed contracts, triggers/refusals, exact MCP tool declarations, failures, hand-offs, evidence gates, examples, official package validation, release/rollback policy; reproducible 100/100 static gate; post-boundary GLM-5.2 paired evaluation scored 1.000 with Skill vs 0.500 baseline, 1.000 safety, zero errors | Extend the paired evaluation to blinded repository tasks, repeated trials, and signed releases |
| Engineering, verification, security, audit | 20% | CLI; default-deny Agent + Skill MCP authorization; protected path/branch and secret guards; digest-bound approval; full hash-chain verification; five-tool CI/CD MCP with disposable execution and server-owned rollback; capability credential broker; OTLP/gRPC export; loopback Prometheus endpoint; 82.73% tested coverage; live signed pipeline and atomic rollback evidence | Add a telemetry collector dashboard and external deployment provider |
| Open/open-source contribution | 5% | Apache-2.0, README, reproducible demo, interface docs | Add contribution guide, releases, dependency SBOM, public examples |

## Mandatory checklist

- [x] At least three distinct Agent roles.
- [x] Agent Identity, boundaries, and relationships documented.
- [x] AgentTeams is the collaboration design and deployment basis.
- [x] Task input, decomposition, context passing, tools, verification, evidence,
      approval/rollback, and experience flow are represented.
- [x] Skills are first-class reusable artifacts.
- [x] Skill contract graph, boundaries, release policy, and 90-point quality gate
      are executable and tested.
- [x] Agent/Skill/MCP grants are exact-match and drift-checked; unknown or
      mismatched capabilities fail closed before transport.
- [x] At least two of memory, knowledge RAG, shared state, trajectory
      observability: RAG, experience memory, shared state/events, traces.
- [x] Runnable entry point, dependencies, sample input/output, and evidence.
- [ ] Recorded live AgentTeams run.
- [x] Production-shaped MCP HTTP implementation with real CI, coverage,
      rollback, audit-chain, credential-broker, OTLP, and Prometheus adapters.
- [ ] Live external provider and telemetry-collector integration evidence.
- [x] Three-repository, 24-case quantitative collaboration/boundary evaluation.
- [ ] Standardized multi-repository patch-resolution evaluation.

## Demo acceptance criteria

A valid offline run must prove:

1. the original test fails;
2. Triage emits a typed T2 classification;
3. Locator identifies `calculator.py`;
4. Coder emits a repository-relative structured Patch;
5. the candidate is applied only to a temporary copy;
6. the same test passes;
7. Reviewer returns `approved`;
8. Experience Distiller stores a redacted, digest-linked pattern;
9. the JSON report contains the complete event trail.
