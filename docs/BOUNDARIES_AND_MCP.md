# Agent boundaries and MCP trust model

DevFlow uses a capability-oriented team, not a group of interchangeable
chatbots. An Agent may accept only the hand-off Skills it owns, and an MCP
tool call is allowed only when both the Agent identity and active Skill match
an explicit grant. Every unspecified combination is denied.

## Responsibility matrix

| Actor | Owns | Accepts | Produces | MCP authority | Explicit non-responsibilities |
|---|---|---|---|---|---|
| TeamLeader | `team-orchestration` capability | issue and worker lifecycle events | plan, assignment, retry, escalation | read/comment on issues; human-approved rollback | no code generation, testing, review, merge, or approval substitution |
| TriageAgent | `issue-classifier` | new or materially changed issue | `ClassifiedIssue` for TeamLeader | none | no repository read/write, patching, or tier above T5 |
| LocatorAgent | `code-root-cause` | classified task | `LocatedContext` for CoderAgent | `github:get_file_contents` only | no source modification, code execution, or test execution |
| CoderAgent | `patch-generator` | located context or retry evidence | `PatchCandidate` for TesterAgent | none | no canonical file write, test execution, PR operation, review, or approval |
| TesterAgent | `test-runner` | patch candidate | `TestEvidence` for ReviewerAgent, or bounded retry for CoderAgent | isolated CI/CD test tools only | no agent-supplied shell command, canonical checkout mutation, review, or merge |
| ReviewerAgent | `pr-reviewer`, `experience-distiller` | passing test evidence | review decision, PR/review record, or human gate | create PR and add review only | no merge, deployment, rollback, test execution, or self-authored approval |
| Human reviewer | approval authority, not an Agent | T4/T5 evidence bundle | digest-bound approval or rejection | no ambient MCP grant | approval cannot be inferred from chat text or supplied by an Agent |

The TeamLeader's orchestration capability is deliberately not a distributable
domain Skill. It controls workflow state and escalation but cannot perform a
worker's domain work. Publishing or merging a candidate is also deliberately
outside the current autonomous closure boundary: ReviewerAgent may open and
review a PR, while repository branch protection and a human or external release
process retain merge authority.

## Enforced hand-off contract

Each domain transition is a `HandoffEnvelope` containing the producer,
consumer, Skill, status, artifact type, inline payload, idempotency key, and
SHA-256 digest. Before an Agent executes, the runtime verifies:

1. the named consumer is the executing Agent;
2. the named Skill is owned by that Agent;
3. status is `READY` or `RETRY`;
4. the payload digest is intact;
5. the artifact is inline and typed at the receiving stage.

A failed review returns a retry envelope to CoderAgent. Failed tests do the
same. A T4/T5 review emits a blocked envelope for `HumanReviewer`; it is not
silently converted into success. Duplicate delivery is safe because the
envelope carries a deterministic idempotency key.

## MCP trust boundary

```text
HandoffEnvelope
  -> Agent consumer/Skill/digest validation
  -> MCPCallContext (run, issue, task, Agent, Skill, trace, idempotency, risk)
  -> server-held signature over the complete internal MCP context
  -> default-deny Agent + Skill grant
  -> argument and repository-boundary validation
  -> digest-bound approval check for dangerous operations
  -> hash-chained audit record (argument digest only)
  -> MCP transport
  -> DevFlow-owned server repeats authorization
```

The policy wrapper authorizes before the transport is reachable. It rejects
unknown tools, wrong Agent/Skill pairs, protected-branch writes, repository
path escapes, secret-shaped arguments, malformed patches, and dangerous calls
without matching approval evidence. Human approvals are signed outside the
Agent boundary with a server-held HMAC key and bind the action, canonical
target, arguments digest, approver, and timestamp. Invalid, expired, modified,
or unverifiable evidence fails closed. Calls to a DevFlow-owned MCP server
also carry an HMAC-signed context, so a local caller cannot forge its Agent or
Skill identity; the server rejects unsigned or modified context. Audit entries contain identity, trace
and argument digests, but never raw credentials or raw arguments.

For `cicd:run_tests`, the server owns the test command as an argument vector.
It accepts a typed Patch, copies the repository to a disposable directory,
checks stale original content, applies create/modify/delete operations there,
and runs with `shell=False` and a bounded timeout. The canonical repository is
never mutated by the test service.

## Sources of truth and drift prevention

- `config/agents.yaml` declares identities, capabilities, watched events, and
  human-readable boundaries.
- `skills/*/references/contract.yaml` declares each Skill's exact MCP tools.
- `config/mcp_servers.yaml` declares the corresponding Agent + Skill grants.
- `config/security.yaml` declares credential capabilities, branch protection,
  approval, and rollback policy.
- `src/devflow/agents/base.py` enforces hand-offs and constructs trusted MCP
  call context.
- `src/devflow/mcp/policy.py` enforces grants and emits audit evidence.
- `src/devflow/mcp/cicd.py` enforces isolated, server-owned test execution.

`scripts/evaluate_skills.py` fails when configured Agent ownership, Skill
ownership, declared tools, and MCP grants are not an exact match. Tests
additionally prove wrong-Agent, wrong-Skill,
tampered-payload, path-escape, protected-branch, stale-patch, and missing-
approval denial paths.

## Operational invariants

1. Default deny: no tool exists for an Agent unless explicitly granted to both
   its identity and active Skill.
2. One owner per stage: an Agent emits an artifact; the next Agent validates
   and consumes it. It does not perform the next stage itself.
3. Evidence before promotion: tests precede review; review precedes a PR or
   approval gate; merge is outside autonomous authority.
4. No agent-held secrets: credentials stay in the gateway/server environment
   and secret-shaped arguments fail before transport.
5. Human authority is authenticated and artifact-bound: a dangerous action
   requires fresh server-signed evidence whose action, target, and SHA-256
   digest match the exact MCP arguments.
6. Internal servers do not trust the caller wrapper alone; they independently
   authenticate and authorize the propagated call context, and bind only to a
   loopback address.
