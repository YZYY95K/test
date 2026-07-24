# Agent Infra competition scorecard

Official source: [Global Open-source AI Challenge — Agent Infra](https://www.goaihz.com/tracks).
This working scorecard translates the published rubric into verifiable
engineering deliverables.

| Dimension | Weight | Current evidence | Remaining highest-value work |
|---|---:|---|---|
| Scenario value and replicability | 25% | End-to-end software issue resolution; explicit users, risk tiers, repeatable fixture | Add measured time/cost reduction on real repositories and 3 organization personas |
| Multi-Agent collaboration and autonomous closure | 25% | 6 clear roles, DAG plan, structured hand-offs, failure feedback, T4/T5 human gate, AgentTeams Team manifest | Run and record the full scenario inside an installed AgentTeams Matrix room |
| Skill engineering and ecosystem reuse | 25% | 6 self-contained v2 Skills; typed contracts, triggers/refusals, dependencies, permissions, failures, hand-offs, evidence gates, examples, validators, UI metadata, release/rollback policy; reproducible 100-point static gate | Run paired with/without-Skill evaluation on pinned real repositories and publish signed releases |
| Engineering, verification, security, audit | 20% | CLI, config loader, real sandboxed regression test, JSON event report, logs/traces/metrics, credential gateway design | Implement production CI/CD MCP server, OpenTelemetry export dashboard, approval and rollback integration test |
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
- [x] At least two of memory, knowledge RAG, shared state, trajectory
      observability: RAG, experience memory, shared state/events, traces.
- [x] Runnable entry point, dependencies, sample input/output, and evidence.
- [ ] Recorded live AgentTeams run.
- [ ] Production MCP server deployment.
- [ ] Multi-repository quantitative evaluation.

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
