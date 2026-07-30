# Agent boundaries and MCP trust model

DevFlow uses a capability-oriented team, not a group of interchangeable
chatbots. An Agent may accept only the hand-off Skills it owns, and an MCP
tool call is allowed only when both the Agent identity and active Skill match
an explicit grant. Every unspecified combination is denied.

## Responsibility matrix

| Actor | Owns | Accepts | Produces | MCP authority | Explicit non-responsibilities |
|---|---|---|---|---|---|
| TeamLeader | framework-native orchestration capability (not a Skill) | issue and worker lifecycle events | plan, assignment, retry, pause, escalation | guarded AgentTeams TeamHarness only; no repository or CI/CD MCP | no code generation, testing, review, repository mutation, merge, rollback, or approval substitution |
| TriageAgent | `issue-classifier` | new or materially changed issue | `ClassifiedIssue` for TeamLeader | none | no repository read/write, patching, or tier above T5 |
| LocatorAgent | `code-root-cause`, `github-evidence` | classified task with fixed revision/scope | `LocatedContext` or digest-bound repository evidence for TeamLeader | only `github-evidence` may call one revision/path-scoped read tool; `code-root-cause` has none | no source modification, code execution, test execution, direct GitHub from root-cause analysis, or scope expansion |
| CoderAgent | `patch-generator` | located context or retry evidence | `PatchCandidate` for TeamLeader validation | none | no canonical file write, test execution, PR operation, review, or approval |
| TesterAgent | `test-runner` | patch candidate | integrity-attested `TestEvidence` or bounded failure evidence for TeamLeader | exactly one policy-owned isolated `run_tests` action | no agent-supplied command/path, canonical checkout mutation, direct Coder routing, review, or merge |
| ReviewerAgent | `pr-reviewer`, `experience-distiller` | passing test evidence or a verified terminal bundle | review/experience result for TeamLeader, including a typed human-gate request | no GitHub write in the current AgentTeams deployment | no merge, deployment, rollback, test execution, or self-authored approval |
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

In the portable Python runtime, failed tests return through TeamLeader
mediation. The result is sanitized first; TeamLeader verifies one digest over
the complete sanitized result and forwards only bounded
`TestFailureEvidence`, never the raw result or a raw-result digest. Local tests
exercise the automatic Coder-to-Tester-to-Leader-to-Coder loop. A failed
review is deliberately different: Reviewer addresses a typed decision to
TeamLeader, which validates it and fails closed for human re-planning until a
formal retry contract binds review feedback to the exact candidate. No bare
review dictionary is executable.

Generic execution failures carry a canonical route claim
`(handoff_sha256, execution_attempt)`. One TeamLeader instance claims that
route before its first asynchronous yield, audits every distinct failure
event, and emits at most one retry route. Coder failures instead stay in the
generation domain. Every canonical Coder route leases exactly one
`model_call_attempt`; TeamLeader issues ordinals 1 through 3 sequentially and
never a fourth. Candidate-validation failures and semantic test retries consume
the same issue-global budget, so their worst case is three model calls rather
than two stacked three-attempt loops. `PatchCandidate` 1.2 echoes the ordinal
and binds it to the exact retained source route.

The portable runtime can place these claims in `DurableRouteLedger`, a
SQLite/WAL authority outside every Worker. Registration is immutable by
`task_id` and canonical envelope digest; `BEGIN IMMEDIATE` serializes scheduler
claims across processes; bounded leases allow recovery after a dead scheduler;
only the lease owner can seal success/failure. Its digest-only audit rows form
an independently recomputable hash chain. The bundled offline six-stage demo
enables this ledger and reports its aggregate snapshot and verified chain head.
Repository tests cover competing processes, expired-lease recovery, immutable
route conflict, terminal replay denial, audit tampering, and one-shot approval
consumption.

The ledger provides durable at-most-one-active-lease semantics, not magical
exactly-once side effects: a Worker can still perform an external action and
die before sealing its lease. Such tools need their own idempotency key and
read-after-write reconciliation. Integrations that instantiate TeamLeader
without `DurableRouteLedger` deliberately fall back to process-local claims
and must not claim restart or multi-replica safety.

A T4/T5 review emits a blocked Reviewer result to TeamLeader; it is never
addressed directly to a human and is not silently converted into success.
TeamLeader validates the exact parent route and canonical evidence, enters
`PAUSED`, and publishes a `HumanApprovalTarget` binding run, issue, tier,
revision, candidate, test result, review and source task digests. Only an
external approval authority may issue fresh evidence for that exact target.
The evidence is verified and consumed once before TeamLeader creates the final
approved review and routes experience capture. Repository tests cover wrong
signature/scope denial, successful T4 resume, terminal receipt binding and
cross-process replay denial. Live AgentTeams evidence still covers only pause
and rejection of an unapproved resume, not a human signature followed by a
successful resume.

Coder accepts `patch-generator` envelopes only from TeamLeader, requires exact
initial/retry input fields, and binds a retry to the previous candidate. Before
calling the model it redacts supported credential shapes from issue and located
context. Before emitting a candidate it enforces repository-relative paths,
the Locator-derived file allowlist, change-type/diff-header consistency,
Python syntax for Python outputs, dangerous-pattern denial, and a whole-artifact
secret scan.

The guarded TeamHarness path independently binds collaboration state. Project
risk is read from the root-owned ledger, source is read from persistent project
state, and every relevant action cross-checks those authorities. Task-room
creation and readback require Matrix private/invite-only state and the exact
actual member set. Returned `invite`/`members` fields are labeled as the
non-creator requested-worker projection; the full set is represented by its
verified count and digest. Idempotent retry and conflict evidence bind both
`taskId` and submission digests. The final operator-driven T2 run exercised
these bindings; it remains separate from the earlier honest failed task.

The same guard validates a packaged Skill before either Worker submission or
Leader acceptance mutates AgentTeams state. Transport status is mandatory and
unambiguous: a `ready` result must be `SUCCESS`; `retry` and `blocked` must be
`FAILED`. Test `ready` additionally requires zero failures/errors, no baseline
regression and a verified integrity attestation; test `retry` requires bounded
failure evidence. Reviewer status is bound to its typed decision, and only a
T4/T5 `human_approval_required` decision may be `blocked`. This prevents an
AgentTeams task from laundering domain failure into transport success.

For a signed Tester result, validation is deliberately separated from
consumption. The Leader first verifies the fixed Ed25519 trust, handoff,
semantic result and packaged validator, then atomically reserves the receipt;
it never permanently consumes the JTI before the upstream transition. The
reservation lock remains held while AgentTeams is called and while both real
state authorities are read back. In pinned AgentTeams commit
`78d0ceda336befa6e62bf89fc1a6b08b965e128d`, `taskflow.check_task` proves the
unchanged submitted result while `projectflow.resolve_project` proves the plan
node acceptance and requester-report binding. Only their canonical composite
digest can move the ledger from `pending` to `committed`. Non-applied failures
are retryable, response loss is recovered idempotently, and conflicts remain
pending/fail-closed. Receipt-bound acceptance forbids `publishArtifacts=true`
because publication is a separate external side effect that this reservation
does not cover. A failed DevFlow test acknowledgement is mapped only after
validation from `FAILED` to AgentTeams' real `REVISION_NEEDED` enum; the
original DevFlow status remains bound in the accept-request digest.

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

The portable MCP policy wrapper, as exercised by repository tests, authorizes
before the transport is reachable. It rejects
unknown tools, wrong Agent/Skill pairs, protected-branch writes, repository
path escapes, secret-shaped arguments, malformed patches, and dangerous calls
without matching approval evidence. Its local approval authority signs outside
the Agent boundary with a server-held HMAC key and binds the action, canonical
target, arguments digest, approver, and timestamp. Invalid, expired, modified,
or unverifiable evidence fails closed in those tests; this is not evidence that
the live AgentTeams T4 approval/resume has occurred. Calls to a DevFlow-owned
MCP server also carry an HMAC-signed context, so a local caller cannot forge
its Agent or Skill identity; the server rejects unsigned or modified context.
Audit entries contain identity, trace and argument digests, but never raw
credentials or raw arguments.

The hardened AgentTeams success driver does not pass sensitive MCP inputs on a
child command line. TeamHarness uses direct pinned stdio JSON-RPC and Locator
uses Streamable HTTP directly; sensitive fields stay in process memory and
protocol bodies/headers. Before execution the driver attests the exact
role×server configuration and schema, enforces a remote deadline shorter than
the host deadline, bounds captured diagnostics, and performs cleanup. The
operator-driven T2 run above completed through this path; it is not a claim of
an autonomous or general six-stage success.

The two CI MCP profiles intentionally have different names and wire protocols.
AgentTeams `devflow-cicd:run_tests` accepts only
`taskId/revision/workspaceBinding` and resolves the ACKed candidate and suite
server-side. Local `devflow-cicd-portable:run_tests` accepts only
`issue_id/patch`; a signed local `risk_tier` selects one of two fixed argv
profiles. Local integration tests show that the portable service copies the
repository to disposable directories, rejects stale content, applies the typed
patch there, and runs with `shell=False` and a bounded timeout. Its explicit
`portable-process-only/v1` profile is not AgentTeams isolation evidence.

## Sources of truth and drift prevention

- `config/agents.yaml` declares identities, capabilities, watched events, and
  human-readable boundaries.
- `skills/*/references/contract.yaml` declares each Skill's exact MCP tools.
- `config/mcp_servers.yaml` declares the canonical AgentTeams grants and wire
  contract; `config/mcp_servers.portable.yaml` separately declares local-only
  adapters.
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
4. Scoped credential paths, not universal secret isolation: the historical
   GitHub/Broker path kept the upstream provider token behind the Broker, and
   the local credential-broker tests pass only a short-lived capability handle.
   Current OpenClaw Worker workspaces still contain MCP consumer/configuration
   material, so `strongBoundaryEnforceable=false` remains the system result.
   Managed DevFlow transports reject configured secret-shaped arguments; this
   is not a global hostile-runtime DLP guarantee.
5. Approval authority is profile-specific and artifact-bound. The portable
   local profile uses fresh HMAC evidence issued by its trusted local authority.
   AgentTeams T4/T5 requires an external Human Authority Ed25519 signature over
   the exact approval target. Historical live evidence proves only pause and
   denial without approval; a human-signed cluster resume remains pending.
6. Internal servers do not trust the caller wrapper alone; they independently
   authenticate and authorize the propagated call context, and bind only to a
   loopback address.
