# Research basis

This note records the design evidence used for DevFlow. It is not a claim that
benchmark numbers from different papers are directly comparable; models,
datasets, dates, and evaluation harnesses differ.

## Primary open-source runtime: AgentTeams

The competition requires AgentTeams (formerly HiClaw) as the collaboration
design basis. The current upstream architecture is a Manager–Workers platform
using Matrix rooms for visible collaboration, a controller for desired-state
reconciliation, shared object storage, and Higress for scoped credentials.
The live deployment baseline is pinned to the official prerelease
`v1.2.0-beta.1`, commit `78d0ceda336befa6e62bf89fc1a6b08b965e128d`.
`agentteams/upstream.lock.yaml` additionally binds the exact v1beta1 Team CRD
bytes and SHA-256; `scripts/verify_agentteams_upstream.py` can recheck the
official raw source. This release still supports the deprecated inline
`spec.leader` / `spec.workers` path used by the live DevFlow manifest after the
documented beta compatibility patch.

The 2026-07-28 review of upstream `main` found that the current Team API instead
references independently managed Worker resources through
`spec.workerMembers`. DevFlow therefore does not claim that its pinned beta
manifest is current-main compatible. A migration must render and server-side
validate separate Worker CRs and a membership-only Team before changing the
runtime baseline.

DevFlow maps onto its native Team topology:

- Manager selects the DevFlow team.
- Team Leader decomposes the issue and owns the project/task DAG.
- Workers own triage, localization, coding, testing, and review.
- Team Room carries assignments and results.
- Worker Rooms carry focused delegation.
- shared task/project storage carries large artifacts rather than repeatedly
  copying them into messages.
- T4/T5 approval remains visible to a human Team Admin.

Upstream sources:

- [AgentTeams repository](https://github.com/agentscope-ai/AgentTeams)
- [Architecture](https://github.com/agentscope-ai/AgentTeams/blob/main/docs/architecture.md)
- [Kubernetes-native orchestration and CRDs](https://github.com/agentscope-ai/AgentTeams/blob/main/docs/k8s-native-agent-orch.md)
- [Pinned v1.2.0-beta.1 Team CRD](https://raw.githubusercontent.com/agentscope-ai/AgentTeams/v1.2.0-beta.1/hiclaw-controller/config/crd/teams.agentteams.io.yaml)

## Software-engineering agent literature

### MetaGPT, ChatDev, and AgentScope

[MetaGPT](https://arxiv.org/abs/2308.00352) reports that naively chaining model
outputs can propagate inconsistent logic, and uses role-specific SOPs plus
intermediate verification to reduce that failure mode. DevFlow therefore makes
TeamLeader the single workflow writer and turns every stage boundary into a
versioned artifact contract rather than an unstructured chat continuation.

[ChatDev](https://arxiv.org/abs/2307.07924) separates *what* agents communicate
through its chat chain from *how* they communicate through a dehallucination
mechanism. DevFlow applies the same distinction without copying its framework:
Matrix messages carry short assignment/status summaries, while immutable
artifacts, digests, validators, and explicit failure codes carry execution
authority. Conversation alone cannot authorize work or prove completion.

[AgentScope](https://arxiv.org/abs/2402.14034) treats message exchange as the
core multi-agent mechanism and pairs it with customizable fault tolerance and
distributed execution support. DevFlow maps that idea to AgentTeams' Matrix
rooms, but keeps retry/replan/blocked semantics in TeamHarness project state so
that transport delivery and business completion remain separate facts.

[UA-ChatDev](https://arxiv.org/abs/2607.02186) is a recent preprint, not a
release benchmark for this project. Its central warning—unverified uncertainty
in an early agent can propagate downstream—supports DevFlow's fail-closed
design: confidence is typed where meaningful, but executable evidence and
independent validation, not self-reported confidence, decide whether a result
advances.

### SWE-agent

[SWE-agent: Agent-Computer Interfaces Enable Automated Software Engineering](https://arxiv.org/abs/2405.15793)
shows that the interface exposed to an agent materially changes performance.
DevFlow therefore exposes narrow, typed operations (retrieve code, produce a
Patch, run isolated tests, create/review PR) instead of a generic shell for
every role.

### AutoCodeRover

[AutoCodeRover: Autonomous Program Improvement](https://arxiv.org/abs/2404.05427)
uses program structure and iterative search rather than treating a repository
as an unstructured bag of files. DevFlow's indexer extracts AST-level
class/function chunks and the Locator broadens retrieval only when needed.

### MASAI

[MASAI: Modular Architecture for Software-engineering AI Agents](https://arxiv.org/abs/2406.11638)
assigns well-defined objectives and strategies to specialized sub-agents,
reducing long trajectories and irrelevant context. DevFlow follows that
principle with six bounded identities and Pydantic hand-off contracts.

### Agentless

[Agentless: Demystifying LLM-based Software Engineering Agents](https://arxiv.org/abs/2407.01489)
demonstrates the strength of a simple localization–repair–validation pipeline
and warns against unnecessary autonomous complexity. DevFlow keeps the normal
path linear and deterministic; events add recovery edges, approval, and audit
semantics rather than open-ended conversation.

### SWE-bench

[SWE-bench: Can Language Models Resolve Real-World GitHub Issues?](https://arxiv.org/abs/2310.06770)
motivates repository-level evaluation against executable tests. DevFlow records
baseline/current test outcomes and treats executable validation as the primary
correctness gate.

### CodeTeam

[CodeTeam: An LLM-Powered Multi-Agent Framework for Repository-Level Code Generation](https://arxiv.org/abs/2606.22082)
separates planning, decision making, and implementation; uses machine-checkable
file/interface contracts, dependency-aware scheduling, bounded context,
Git-based coordination, and QA-driven iterative repair. DevFlow applies the
same principle at issue-resolution scale: the Leader owns a typed DAG, Coder
owns only candidate changes, and Tester evidence drives bounded repair loops.

### ProjDevBench

[ProjDevBench: Benchmarking AI Coding Agents on End-to-End Project Development](https://arxiv.org/abs/2602.01655)
reports that current agents struggle particularly with complex system design,
time-complexity optimization, and resource management. DevFlow therefore does
not treat its small offline fixture as a quality benchmark; the evaluation plan
requires larger project tasks, resource measurements, and explicit architecture
criteria.

## Design decisions derived from the evidence

| Evidence | DevFlow decision | Verification |
|---|---|---|
| AgentTeams | Release-locked Team manifest; Leader delegates to five workers; API migration is explicit | `agentteams/upstream.lock.yaml`, `scripts/verify_agentteams_upstream.py` |
| SOPs reduce cascading inconsistency | One Leader-owned state machine and versioned stage contracts | TeamHarness transition and contract tests |
| Communication needs both content and protocol rules | Small Room summaries; large versioned, digest-bound artifacts plus references; chat is never authority, and storage immutability is not assumed | conformance notification tests and Handoff validators |
| Intermediate model confidence is not proof | Validate types, source bindings, tests, signatures, and terminal readback independently | Skill validators, Tester evidence, approval replay tests |
| Good interfaces matter | Typed models and narrow MCP calls | model and agent tests |
| Structure improves retrieval | AST code chunks plus targeted broadening | indexer tests |
| Modular roles shorten context | Role-specific identity, capabilities, boundaries | agent configs and Skills |
| Simple pipelines are competitive | Fixed normal path with explicit feedback edges | offline demo event trail |
| Tests are the ground truth | baseline/candidate execution and regression gate | demo JSON evidence |
| Production autonomy needs control | secret scanning, path confinement, CI/security gates, human approval | security tests |

## Evaluation plan

The offline fixture proves plumbing, not general software repair quality.
Competition-ready evaluation should include:

1. execute the checked-in 21-task mutation-repair set across three exact
   repository commits in isolated work copies; fixture prevalidation alone is
   not a solution result;
2. resolved rate and test pass rate;
3. localization top-1/top-5 accuracy;
4. regression rate;
5. median latency, tokens, and tool calls;
6. approval/rollback correctness for injected high-risk cases;
7. ablations: no RAG, no experience store, single-agent, no reviewer;
8. complete trace/log evidence for every run.
