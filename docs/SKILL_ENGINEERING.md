# DevFlow Skill engineering standard

This document records the evidence behind DevFlow's Skill design and the
project-specific quality gate. A `100/100` result means only that the package
satisfies the structural rubric below; it is **not release qualification** and
does not claim that the Skill improves task success. Semantic contract gates,
deployment reachability, adversarial validator tests, and paired evaluation on
real repositories remain mandatory.

## Evidence reviewed

- The [Agent Infra competition rubric](https://www.goaihz.com/en/tracks?track=infra)
  assigns 25% to Skill engineering and explicitly examines inputs, outputs,
  invocation conditions, dependent tools, failure handling, reuse, versioning,
  release, rollback, quality evaluation, and AgentTeams integration.
- The [Agent Skills specification](https://agentskills.io/specification)
  defines discoverable metadata, optional scripts/references/assets,
  progressive disclosure, shallow references, and structural validation.
- OpenAI's
  [skill-creator](https://github.com/openai/skills/blob/main/skills/.system/skill-creator/SKILL.md)
  uses the stricter Codex convention of `name` plus `description` frontmatter,
  recommends `agents/openai.yaml`, and reserves scripts for deterministic
  operations.
- Anthropic's [public Skill repository](https://github.com/anthropics/skills)
  demonstrates self-contained packages and explicitly warns that critical
  Skills still require testing in their actual environment.
- *Toward User Comprehension Supports for LLM Agent Skill Specifications*
  ([arXiv:2605.19362](https://arxiv.org/abs/2605.19362)) motivates four
  comprehension anchors: operational basis, output contract, boundary
  disclosure, and capability examples.
- *From Anatomy to Smells*
  ([arXiv:2607.01456](https://arxiv.org/abs/2607.01456)) catalogues recurring
  specification smells such as missing validation, unclear output form,
  hard-coded command sequences, and rationalization loopholes.
- *A Framework for Evaluating Agentic Skills at Scale*
  ([arXiv:2606.17819](https://arxiv.org/abs/2606.17819)) evaluates Skills with
  realistic tasks, instruction-following rubrics, and goal-completion rubrics.
- *SWE-Skills-Bench*
  ([arXiv:2603.15401](https://arxiv.org/abs/2603.15401)) shows why static
  quality is insufficient: it uses fixed repository revisions, explicit
  requirements, deterministic tests, and paired with/without-Skill runs.

## 100-point static gate

| Dimension | Points | Required evidence |
|---|---:|---|
| Specification compliance | 15 | Exact Codex frontmatter, matching package identity, UI metadata |
| Trigger precision | 10 | Positive `Use when` trigger plus machine-readable invoke/refuse cases |
| Contract clarity | 15 | Versioned, distinct input/output artifacts, dependencies, release/rollback |
| Operational basis | 10 | Short procedure, decision rules, deterministic validator |
| Boundary and security | 15 | Allowed surface and at least three explicit forbidden actions |
| Failure handling | 10 | Bounded retry/fail-closed matrix with owner and event |
| Collaboration | 10 | Typed success and non-success hand-offs |
| Validation | 10 | At least three evidence gates plus success/failure/boundary examples |
| Context efficiency | 5 | Lean core file and one-level progressive disclosure |

The release gate is 90. Invalid identity/frontmatter or missing executable
validation is a blocking failure regardless of total points. Run:

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_skills.py
```

## Semantic release blockers

Structural scoring cannot detect a validator that accepts plausible-looking
nonsense or a Skill that declares a tool absent from its deployed role. A
Skill release is therefore blocked unless all of these machine-checkable facts
also hold:

1. every declared success and failure artifact can be represented, submitted,
   and independently validated by TeamHarness;
2. validators reject unknown fields, duplicate keys, non-finite values, wrong
   enums/types, broken cross-field constraints, stale source bindings, and
   digest/signature tampering;
3. every declared MCP tool is reachable only from the owning deployed role,
   and no undeclared server/tool is visible there;
4. a producer's output and its consumer's input are field-compatible, or a
   named TeamLeader-owned adapter has its own schema and tests;
5. external receipts are verified against a deployment-attested trust root,
   not accepted because they merely look like a signature; and
6. positive, failure, boundary, replay, and cross-task negative cases execute
   the real validator/control path rather than only inspecting text.

The historical `7/7 = 100/100` report predates these semantic blockers. It is
retained only as structural evidence and must not be used as the current Skill
quality conclusion until the semantic suite passes.

## Collaboration invariant

The normal typed artifact chain is:

```text
IssueIntake
  -> ClassifiedIssue
  -> LocatedContext
  -> PatchCandidate
  -> TestEvidence
  -> ReviewDecision
  -> ExperiencePattern
```

`IssueIntake` and integrity-checked `SkillInvocation` are the only external
entry artifacts. The latter drives bounded helper work such as revision-pinned
GitHub evidence, which returns to TeamLeader for the next typed assignment;
it is not treated as an undeclared domain-Skill output.

Every inter-agent transfer uses `HandoffEnvelope` v1 with producer, consumer,
task identity, trace identity, idempotency key, artifact schema version, and
SHA-256. The recipient rejects a stale, mismatched, or corrupted envelope.
Failure routes are explicit and never masquerade as success.

Role separation is deliberate:

- Triage decides classification, not workflow.
- Locator reads and localizes, never executes or edits.
- Coder proposes a candidate, never applies, tests, or promotes it.
- Tester executes only in isolation and reports evidence, never approval.
- Reviewer independently gates promotion and cannot bypass human/security
  policy.
- Distiller operates only after a terminal reviewed outcome and cannot trigger
  operational work.
- TeamLeader owns orchestration and conflict routing, not domain execution.

## Release and outcome evaluation

Contracts use semantic versions. Breaking artifact or policy semantics require
a major version. Each contract declares compatibility, change policy, and a
fail-safe rollback action. Worker packages should be signed and retained so a
release can restore the prior bundle without rewriting historical artifacts.

Static qualification must be followed by:

1. pinning a real repository revision and explicit acceptance criteria;
2. running at least ten representative, edge, and adversarial tasks per Skill;
3. comparing the same agent/model with and without the Skill;
4. measuring acceptance pass rate, unsafe-action rate, retries, tokens, cost,
   latency, and hand-off defects;
5. blocking release when safety regresses or task success fails to improve.
