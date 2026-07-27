# AgentTeams live evidence — 2026-07-27 (updated 2026-07-28)

This record distinguishes observed runtime evidence from local tests and from
remaining operational limitations. Secrets, access tokens, passwords, Matrix
room identifiers, public host addresses, and raw credential-bearing responses
are deliberately omitted.

## Environment and pinned components

- Ubuntu 24.04.4, Docker 29.6.2, Compose 5.3.1, k3s v1.36.2, Helm 3.21.3.
- AgentTeams `v1.2.0-beta.1`, upstream commit
  `78d0ceda336befa6e62bf89fc1a6b08b965e128d`.
- One Team Leader and five OpenClaw Workers using the real GLM-5.2 gateway.
- Higress Console `2.2.1`, audited image digest
  `sha256:90ccdbb078375aad42f874feddba9d964eca34f192ee8dbab7d9a22079b580a4`.

### Worker package evidence

Six role-scoped DevFlow Worker packages at version `1.2.0` were built as
deterministic `ZIP_STORED` archives, published through the immutable
`devflow-worker-packages-v1-2-0` ConfigMap, and checked in-cluster by exact byte
length and SHA-256:

| Runtime role | Bytes | SHA-256 |
|---|---:|---|
| `devflow-lead` | 2,163 | `88ec2ea1a908b26ab1603467df890821417507503687c5eaf55ba772d399d769` |
| `devflow-triage` | 14,599 | `0282da4fa9bdf3cc6e111c159cffbfafa4ae090e63f9398ad16ac9b986b398ba` |
| `devflow-locator` | 56,419 | `aedd5c4cedfd359c6810059458ccb48f4ec6a26a41e0e014ef22f09a8b20cebc` |
| `devflow-coder` | 15,008 | `5d7a7f8db0239ecb1ffdea2acd2022669372ca3aec797d7cd3283df835c9aabc` |
| `devflow-tester` | 15,048 | `d7c72fd365a60abe032282f56b9487f78b40f648a16782d2c3012fe7d32b59e1` |
| `devflow-reviewer` | 28,074 | `463a7de6f42653aa22dfd0a60b9fac531ad1c32b09a57cb39ee45fa0908a4f96` |

The Team became Active with all six replacement Pods Ready. Package rollout
does not by itself prove that the persistent role workspace matches the
package; the later GitHub task exposed exactly that distinction.

## Peer communication regression

The beta-generated OpenClaw configuration originally dropped bot-authored
messages because Matrix `allowBots` was unset. Enabling bot mentions exposed a
second defect: partial streaming emitted a short base event followed by Matrix
replacement events, so downstream routing observed the mention without a
complete executable assignment.

The compatibility reconciler now enforces only these two fields while
preserving allowlists and `requireMention`:

- `channels.matrix.allowBots = "mentions"`
- `channels.matrix.streaming = "off"`

After reconciliation, a single complete Leader handoff started Triage at
09:56:50 UTC. Triage completed at 09:57:46, mentioned Leader in one final base
event, and automatically started the Leader at 09:57:57. Leader completed at
09:58:29. This was a model-backed bot-to-bot path, not an injected transcript.

## Guarded TeamHarness boundary

The upstream TeamHarness stdio MCP was installed behind DevFlow's process-role
guard. Observed tool surfaces were:

- Leader: `health`, `message`, `roomflow`, `filesync`, `artifact`,
  `projectflow`, `taskflow`.
- Worker and remote-member: `health`, `taskflow`. Neither role can call
  `artifact` or `filesync` directly.
- Manager: `health`, `message`.

A Worker attempted `taskflow.delegate_task` while supplying `role=leader`.
The guard replaced the untrusted argument with the process role and returned a
`forbidden_tool` result. Runtime mcporter configuration contained only
non-secret paths and role facts; credentials remained inherited from the
AgentTeams process.

The first live GitHub delegation after this installation also exercised a
projected ServiceAccount-token path. Kubernetes exposed the token beneath
`/var/run`, while canonical path resolution mapped that parent to `/run`.
The guard originally canonicalized the child but compared it with the
uncanonicalized parent, so it rejected a legitimate projected-token alias
before any GitHub request was attempted. The fix canonicalizes both the
configured parent and child before containment checking. Its focused suite
passed 73 tests with 2 skipped, the immutable overlay was redeployed, and all
six roles then passed TeamHarness reconciliation. This is a path-validation
compatibility fix; it does not weaken the exact-parent containment rule.

This is a collaboration misuse guard, not a hostile-tenant sandbox. The hard
boundaries remain Kubernetes identity/RBAC, Higress Consumers, NetworkPolicy,
and scoped credentials. The current OpenClaw TeamHarness overlay also requires
the documented post-reconcile installation step after a Team is recreated;
automatic recreation recovery is not claimed.

### 2026-07-28 guard implementation/test follow-up

The current TeamHarness guard and focused tests now derive each collaboration
claim from its designated authority instead of trusting request fields:

- project risk is bound to the root-owned ledger;
- project source is read back from persistent project state;
- Matrix task rooms must be private and invite-only, with the exact actual
  member set verified from Matrix state;
- returned `invite`/`members` fields are explicitly labeled as the
  non-creator requested-worker projection, while the full set is represented
  by its verified count and digest; and
- idempotent retry and conflict results bind `taskId` and submission digests.

The guarded filesync surface now exposes only `action`, `path`, and optional
`dryRun`; `action` and `path` are required and extra properties fail closed.
Any caller-supplied `exclude`, including an empty list, is rejected. Requested
paths and every recursive source segment use the same conservative allowlist,
`global-shared` remains read-only, and the local root must be the resolved real
directory exactly bound to the runtime identity. A directory push must contain
between one and 32 ordinary files; the guarded tree is capped at 10,000 entries
and 64 MiB and rejects symlinks and hardlinks. Its pre/post fingerprint includes
size, nanosecond mtime, and each regular file's SHA-256. A non-dry-run push is
reported as successful only after every expected object receives a separately
bound `stat` response with `exists=true` and the local tree remains unchanged.
An existing pull target must show a provable post-operation change.

These controls were first implementation/test facts. The later operator-driven
run below exercised the final push/readback path without changing the narrower
scope of the earlier honest failure.

## Real project lifecycle

An earlier live project used one dedicated task room and two dependent nodes:

1. T1 — Triage classification.
2. T2 — independent Reviewer verification of T1 evidence.

Observed lifecycle, China Standard Time (UTC+8):

- Reviewer joined the task room at 18:13:07.
- Because the earlier assignment predated room membership, Leader used
  TeamHarness to resend one complete, bounded T2 instruction at 18:22:16.
- Reviewer started at 18:22:29 and acknowledged T2 at 18:23:20.755.
- Reviewer submitted `SUCCESS` at 18:24:25.233; TeamHarness returned success
  and published the result at 18:24:25.895.
- The first completion notification met `Matrix sync entered STOPPED during
  startup`; the channel automatically retried successfully at 18:24:50.068.
- Leader accepted the result at 18:25:10.676; the node became complete at
  18:25:11.270.
- Leader completed the project at 18:25:31.633; TeamHarness confirmed
  `completed` at 18:25:32.205.
- The completion report was sent at 18:25:44.464 and marked sent at
  18:25:52.165. A final filesync push repaired a detected local/object-storage
  lag without changing project semantics.

Final authoritative state:

- Project: `completed`; requester report `pending=false`.
- T1 and T2 project nodes: `completed`.
- T1 and T2 Worker task results: `submitted`, `SUCCESS`, `effective=true`,
  `validationErrors=[]` (the separate Worker-task and accepted-project-node
  states are expected TeamHarness semantics).
- Reviewer GitHub, `git`, and `gh` tool/command calls: zero.
- T1 artifact SHA-256: `b3d09cfb2faa5361...e71046b`.
- T2 artifact SHA-256: `43ba42a2e0f3263...b908741d`.
- Project result SHA-256: `022ecb32533ddf8...21da8d4`.
- Project metadata SHA-256: `624bea9462a3f914...cf8f97a`.

## T4 pause and approval boundary

A separate live T4 project was created and then paused. The authoritative
project state reported `paused`. Attempting to resume it without an external
approval produced the stable fail-closed result:

```text
approval_denied:approval must contain exactly evidence and signature
```

The Leader approval ledger was mode `0600`, bound to that project and `T4`
risk tier, and recorded no used nonces. Only the public verification key was
present in the Pods; no human approval signature was generated or copied into
the runtime. Therefore this evidence proves pause plus denial of an
unapproved resume. It does **not** prove a signed human approval or a
successful approved resume; both remain pending.

## Higress MCP session storage

The AgentTeams beta configuration contained only Redis placeholders, which
blocked real OpenAPI-to-MCP creation. DevFlow deployed the official Higress
Redis Stack image pinned to the audited amd64 digest, with a persistent 2 GiB
`local-path` volume, AOF (`everysec`), health probes requiring `PONG`, no
ServiceAccount token, non-root execution, dropped capabilities, and a private
ClusterIP Service.

Observed state after deployment:

- Ready: true; restarts: 0.
- PVC: Bound, 2 GiB, `local-path`.
- AOF enabled; last write status `ok`.
- Existing Higress gateway Pod could connect to TCP 6379.
- A DevFlow Worker Pod could not connect, demonstrating the intended
  gateway-only NetworkPolicy path in this cluster.
- The Redis configurator applied the canonical address with empty optional
  username/password and a second check reported `compliant`.

## Scope-bound GitHub MCP

The GitHub read path was exercised through the deployed Broker and Higress MCP
route after both runtime artifacts were pinned:

- Broker image:
  `devflow/github-scope-broker@sha256:af42d610e635b5a186717e7bf8b42bb1d1a602bbacb3f874769e4ade7d788712`.
- Higress MCP Wasm plugin:
  `oci://higress-registry.cn-hangzhou.cr.aliyuncs.com/plugins/mcp-server@sha256:ee81701617d6fe5ceaab1d094a23a82a0a1ee7307918ae1031022be62fb5e4cd`.
- The live Wasm resource used `FAIL_CLOSE`.

The positive read used exactly this non-secret scope:

- repository: `YZYY95K/test`;
- revision: `cc6a79d6b633be640a78eadf081469d0038f2dd5`;
- path: `README.md`.

The response identified Git object
`46e21a78b325810240ef6699de10e9441091b351`. The decoded content SHA-256 was
`2ffb00a778946b5a4477174222f7a3b7a39ffe1d8074fd477e3cafb8f7bad9b8`, and the
receipt response digest recomputed to the same value carried by the receipt.
The capability, its signature, the upstream credential, and the Higress
Consumer credential are intentionally not recorded here.

Three negative checks exercised different enforcement layers:

1. Reusing the same capability for a path outside its exact scope returned
   HTTP 403 from the Broker path.
2. Calling the Higress MCP route as Reviewer returned HTTP 403; only the
   Locator Consumer is admitted to this read route.
3. A Locator Pod could not connect directly to the content Broker because the
   NetworkPolicy admits the gateway data plane, not Worker Pods. The positive
   read succeeded only through Higress.

Together these observations verify exact scope binding, MCP Consumer identity,
fail-closed Wasm configuration, receipt digest integrity, and network-path
separation. They do not prove the six-stage software-repair workflow, a T4
human approval, or a post-update role-package rollout.

## Real GitHub task: honest failure and retry semantics

After the projected-token fix, Leader delegated a real, digest-bound GitHub
evidence task to Locator. The canonical handoff identified the producer,
consumer, task, and `github-evidence` Skill; Locator received and acknowledged
it. A short-lived capability was present but was never printed or written into
this evidence record.

The task then exposed a persistent-workspace version mismatch before the
GitHub tool call. The role package contained the current 12,925-byte
`authorize_tool.py`, but MinIO restored an older 1,892-byte runtime copy whose
CLI lacked the required `--envelope` and `--capability` arguments. The Worker
submitted `FAILED` with the stable summary
`SKILL_RUNTIME_VERSION_MISMATCH`. Repeating the identical submission returned
`idempotent=true`; retrying with a different result was rejected as
`submit_result_conflict`. Leader's task check reported
`resultStatus=FAILED`, `effective=true`, and no validation errors.
Here `effective=true` means the submitted result was structurally valid and
authoritative; it does not turn the failed task into a success.

This run proves canonical handoff/ACK, version-drift detection, honest failure
return, idempotent replay, and conflicting-result rejection. It does not prove
a successful AgentTeams GitHub task or a six-stage repair.

## 2026-07-28 fixed-policy convergence and restart evidence

The immutable `final4.4` apply converged the fixed seven-Skill DevFlow policy
across four runtime surfaces: the controller archive cache, controller
persistent Skill cache, Worker-local trees, and MinIO. An independent
read-only check then reported `devflowPolicyVerified=true` with no changed
roles. Locator was replaced and retained exactly its two expected DevFlow
Skills, `code-root-cause` and `github-evidence`; all six Pods were Ready and
the replacement Worker's restart count remained zero.

This result is deliberately narrower than a complete role boundary. The same
summary states `completeRoleSkillBoundaryVerified=false`: built-in, platform,
and unknown Skills are outside the fixed-seven comparison and are not deletion
targets. It also does not alter the OpenClaw result
`strongBoundaryEnforceable=false` or establish hostile-root/OS isolation.

The current reconciler implements MinIO changes as a staged/backup protocol
with a phase manifest and readback, allowing interrupted operations to recover
or refuse tampered state. This is crash-recoverable transaction handling, not
an atomic S3 tree replacement or a cross-Pod atomic transaction. Sensitive
MinIO configuration is kept out of child-process arguments, and the bounded
remote helper payload/archive is delivered over stdin. These implementation
properties describe the hardened reconciler; the live convergence evidence
above is the independently verified fixed-policy result.

## 2026-07-28 operator-driven T2 success follow-up

Six operator-driven attempts were retained as distinct evidence rather than
collapsing partial progress into a success claim:

| Attempt | Observed outcome |
|---|---|
| Run 1 | Returned no result; no task or project success was inferred. |
| Run 2 | Stopped because the real ACK response field did not match the driver's precondition. |
| Run 3 | Stopped on an incorrectly configured role-scoped shared-path binding. |
| Run 4 | Completed the core scoped task and project path, but failed final filesync role/workspace binding. |
| Run 5 | TeamHarness push internally verified both expected objects, but the outer minimal executor did not permit its independent `stat` calls. |
| Run 6 | Used the final pinned TeamHarness and driver trees and completed the full bounded T2 path. |

Run 6 is the accepted fresh success record. It deliberately omits the actual
project, room, capability, infrastructure endpoint, credential, and repository
content. The verified non-secret facts are:

- risk tier was T2; the project reached `completed` and the requester report
  read back `pending=false`;
- proof fields `validatorPassed`, `firstSubmit`, `idempotentRetry`,
  `conflictRetry`, `postConflictReadbackBound`, and `leaderCheckEffective`
  were all independently `true`; the conflict proof denotes rejection of the
  altered retry and the Leader check returned `effective=true`;
- filesync push returned `expectedObjectCount=2` and
  `verifiedObjectCount=2`, after which independent bound `stat` calls for
  `meta.json` and `plan.md` each returned `exists=true`;
- all six AgentTeams Pods were Ready;
- the independent role-policy check found zero changed roles and retained
  `devflowPolicyVerified=true` together with the deliberately narrower
  `completeRoleSkillBoundaryVerified=false`;
- the TeamHarness `final4` deployed-tree SHA-256 was
  `263681c7526daa09940bc3b2c754957f6cd7341ed0f38bfa3f78af5a06f12d40`,
  and the success-driver `final7` deployed-tree SHA-256 was
  `10aa2f3bc09d90970229c997dab595de52557b84b1d6719cf4191b968e129781`;
- the Leader TeamHarness canonical schema was 28,909 bytes with SHA-256
  `985fbb53710bc62f34e0194783a68852e4a7400bea794b6600023f96bf730eea`;
  the unchanged Locator pins remained 1,742 bytes with SHA-256
  `2588f5c5d201588468e86c93899f22ff913b98c7c6784173b23640b1718ab887`
  for the read-only GitHub MCP schema and 4,203 bytes with SHA-256
  `a4243ba99239622210efd749ac06e30d3d7d1673c4cbf07db80720ed5859b69a`
  for its TeamHarness schema.

The two remote `stat` results prove object existence at the exact bound paths;
they are not remote byte-digest attestations. The in-process guard also cannot
eliminate a same-UID swap-and-restore race between checks, and a failure found
after an upstream write does not prove that no external write occurred. The
native OpenClaw result therefore remains
`strongBoundaryEnforceable=false`. This T2 evidence is not a six-stage software
repair, a signed T4 approval/resume, or a Tester-to-Coder failure/retry loop.

## OpenClaw native tool-boundary audit

The read-only audit ran against all six Ready role Pods and intentionally
returned non-zero with `verified=false` and
`strongBoundaryEnforceable=false`. It reported these six stable blockers:

1. `ROOT_RUNTIME_SHARED_WITH_AGENT_TOOLS`
2. `FS_WORKSPACE_ONLY_HAS_NO_SENSITIVE_PATH_EXCLUSIONS`
3. `OPENCLAW_POLICY_IS_STORED_IN_AGENT_WORKSPACE`
4. `EXEC_APPROVAL_STATE_IS_STORED_IN_AGENT_WORKSPACE`
5. `MCP_CREDENTIAL_CONFIG_IS_STORED_IN_AGENT_WORKSPACE`
6. `MCP_REQUIRES_GENERAL_PURPOSE_EXEC`

Observed facts behind the result were consistent across all six roles:
OpenClaw ran as UID 0, role workspaces were writable, and OpenClaw policy,
exec-approval state, and MCP client configuration were colocated with the
agent-visible workspace. Consequently DevFlow may claim logical/process-role,
Higress Consumer, NetworkPolicy, and capability boundaries, but must not call
the current OpenClaw layout a strong hostile-root or OS sandbox.

## Submission artifact QA

The current preliminary presentation artifacts are complete local candidates:

- `DevFlow_GOAI_2026_初赛方案_20260727.pptx`: 51,885 bytes, SHA-256
  `ffc838971097db2d6909c901a6684f7324daaca51e060a4bd7596ef2be321e6f`.
- `DevFlow_GOAI_2026_初赛方案_20260727.pdf`: 1,242,343 bytes, SHA-256
  `c350edda5880b23ae93f2ff045a0833e492960f793b5df32f64aefac4378db07`.

Both contain 12 pages. The PDF is version 1.7, unencrypted, and contains no
forms or JavaScript. All 12 pages were rendered at 1920×1080 and inspected for
clipping, overlap, and garbled text; no visual defect was found. Presentation
notes retain source references, and the artifact credential-shape scan found
zero matches. This local QA is not an official upload receipt and does not
prove that the final code commit/tag or optional ZIP has been submitted.

## Local release gates

At an earlier release checkpoint, the repository passed strict configuration
validation, Ruff, mypy, behavioral-suite validation, deterministic package
reproduction, and the coverage gate. Every shipped Skill scored 100/100 under
the structural Skill evaluator. All seven validators execute under
`python -S`, proving that the Worker does not need PyYAML for artifact
validation. Because the branch changed afterward, that older coverage result
must not be presented as the final release-candidate gate; a clean-commit full
rerun is still required.

The GitHub MCP checks above are complete for the stated repository, revision,
path, and negative cases. The six role-specific v1.2.0 archives, replacement
Pods, T4 pause/unapproved denial, honest failed-task semantics, the fresh
operator-driven T2 success, OpenClaw audit, scoped four-surface convergence of
the fixed seven-Skill policy including a Locator replacement check, and
12-page presentation QA are verified only at their stated scopes. A
Tester-to-Coder failure/retry, the six-stage repair, signed T4 resume, final
clean-commit release gates and package, official upload, and video remain
incomplete; no pending result is represented here as complete.
