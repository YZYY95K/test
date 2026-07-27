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
| LocatorAgent | `code-root-cause`, `github-evidence` | classified task with fixed revision/scope | `LocatedContext` or digest-bound repository evidence | `github:get_file_contents` only | no source modification, code execution, test execution, or scope expansion |
| CoderAgent | `patch-generator` | located context or retry evidence | `PatchCandidate` for TesterAgent | none | no canonical file write, test execution, PR operation, review, or approval |
| TesterAgent | `test-runner` | patch candidate | `TestEvidence` for ReviewerAgent, or bounded retry for CoderAgent | isolated CI/CD test tools only | no agent-supplied shell command, canonical checkout mutation, review, or merge |
| ReviewerAgent | `pr-reviewer`, `experience-distiller` | passing test evidence | review decision, PR-ready record, or human-gate escalation | no GitHub write in the current AgentTeams deployment | no merge, deployment, rollback, test execution, or self-authored approval |
| Human reviewer | approval authority, not an Agent | T4/T5 evidence bundle | digest-bound approval or rejection | no ambient MCP grant | approval cannot be inferred from chat text or supplied by an Agent |

The TeamLeader's orchestration capability is deliberately not a distributable
domain Skill. It controls workflow state and escalation but cannot perform a
worker's domain work. Publishing or merging a candidate is also deliberately
outside the current autonomous closure boundary. The portable core can place
PR creation/review behind explicit grants, but the current AgentTeams Reviewer
has no GitHub write capability; repository branch protection and a human or
external release process retain merge authority.

## Runtime Skill policy boundary

The live `final4.4` apply and a separate read-only check converged the fixed
seven-Skill DevFlow policy across four surfaces: controller archive cache,
controller persistent Skill cache, Worker-local trees, and MinIO. A Locator
replacement retained exactly `code-root-cause` and `github-evidence`, and all
six Pods remained Ready. This evidence is deliberately scoped:
`devflowPolicyVerified=true` and
`completeRoleSkillBoundaryVerified=false`. It does not assert a complete
boundary over built-in, platform, or unknown Skills, and it does not imply a
hostile-root or OS sandbox.

MinIO updates use a staged tree, backup tree, phase manifest, and byte readback
so an interrupted operation can recover or fail closed. This is
crash-recoverable application-level transaction handling, not atomic
replacement of an S3 object tree and not a cross-Pod atomic transaction.

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

The guarded TeamHarness path independently binds collaboration state. Project
risk is read from the root-owned ledger, source is read from persistent project
state, and every relevant action cross-checks those authorities. Task-room
creation and readback require Matrix private/invite-only state and the exact
actual member set. Returned `invite`/`members` fields are labeled as the
non-creator requested-worker projection; the full set is represented by its
verified count and digest. Idempotent retry and conflict evidence bind both
`taskId` and submission digests. The final operator-driven T2 run exercised
these bindings; it remains separate from the earlier honest failed task.

### Guarded TeamHarness surface

| Runtime role | Direct TeamHarness tools |
|---|---|
| Leader | `health`, `message`, `roomflow`, `filesync`, `artifact`, `projectflow`, `taskflow` |
| Worker or remote-member | `health`, `taskflow` |
| Manager | `health`, `message` |

Worker and remote-member runtimes cannot directly invoke `artifact` or
`filesync`. Their boundary ends at an idempotent `taskflow` submission; Leader
owns the final bounded synchronization.

The filesync schema accepts only required `action`/`path` plus optional
`dryRun`. Caller exclusions and unknown fields fail closed. Canonical requested
paths and recursive child segments use the same allowlist, `global-shared` is
read-only, and the resolved real workspace must exactly match the attested
runtime identity. Push rejects symlinks, hardlinks, empty directories, more
than 32 files, more than 10,000 entries, or more than 64 MiB. Its local tree
fingerprint includes each entry's size and nanosecond mtime plus each regular
file's SHA-256. A non-dry-run success requires every expected object to return
a separately path/workspace-bound `stat exists=true`, with an unchanged local
tree before and after. An existing pull target must show a provable change.

### 2026-07-28 bounded live follow-up

The operator retained six attempts as separate records: Run 1 returned no
result; Run 2 exposed a mismatch between the real ACK field and the driver's
precondition; Run 3 found a misconfigured role-scoped shared path; Run 4
completed the core project path but failed filesync binding; Run 5 reached an
internal guarded push result of two verified objects out of two but the outer
minimal executor had not admitted the independent `stat` operation; Run 6 used
the final pins and completed the bounded T2 path. No actual project, room,
capability, endpoint, credential, or raw repository content is retained here.

The final record has project state `completed`, requester `pending=false`, and
`validatorPassed`, `firstSubmit`, `idempotentRetry`, `conflictRetry`,
`postConflictReadbackBound`, and `leaderCheckEffective` all `true`; the altered
retry was rejected and Leader read back `effective=true`. Push returned
`expectedObjectCount=2` and
`verifiedObjectCount=2`; independent stats for `meta.json` and `plan.md` each
returned `exists=true`. All six Pods were Ready. The role-policy check found
zero drift and retained `devflowPolicyVerified=true` with
`completeRoleSkillBoundaryVerified=false`.

The deployed TeamHarness `final4` and driver `final7` tree SHA-256 values were,
respectively,
`263681c7526daa09940bc3b2c754957f6cd7341ed0f38bfa3f78af5a06f12d40`
and
`10aa2f3bc09d90970229c997dab595de52557b84b1d6719cf4191b968e129781`.
The Leader TeamHarness canonical schema pin was 28,909 bytes at
`985fbb53710bc62f34e0194783a68852e4a7400bea794b6600023f96bf730eea`.
Locator pins remained 1,742 bytes at
`2588f5c5d201588468e86c93899f22ff913b98c7c6784173b23640b1718ab887`
for the read-only GitHub MCP schema and 4,203 bytes at
`a4243ba99239622210efd749ac06e30d3d7d1673c4cbf07db80720ed5859b69a`
for TeamHarness.

Remote stat proves existence at a bound object path, not a digest of the remote
bytes. The in-process pre/post checks cannot eliminate a same-UID
swap-and-restore race, and a failure detected after an upstream call does not
prove that no external write occurred. Consequently
`strongBoundaryEnforceable=false` remains the correct system result. This T2
record is not the six-stage repair, a signed T4 approval/resume, or a
Tester-to-Coder failure/retry loop.

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

The hardened AgentTeams success driver does not pass sensitive MCP inputs on a
child command line. TeamHarness uses direct pinned stdio JSON-RPC and Locator
uses Streamable HTTP directly; sensitive fields stay in process memory and
protocol bodies/headers. Before execution the driver attests the exact
role×server configuration and schema, enforces a remote deadline shorter than
the host deadline, bounds captured diagnostics, and performs cleanup. The
operator-driven T2 run above completed through this path; it is not a claim of
an autonomous or general six-stage success.

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
