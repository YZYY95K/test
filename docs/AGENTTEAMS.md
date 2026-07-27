# AgentTeams mapping

DevFlow targets AgentTeams `agentteams.io/v1beta1` and uses a native `Team`
instead of pretending that an internal Python event bus is the production
multi-agent transport.

| AgentTeams concept | DevFlow role |
|---|---|
| Manager | Receives the human request and selects `devflow-swe` |
| Team Leader | TeamLeader: decomposes, tracks the DAG, handles conflicts |
| Worker | Triage, Locator, Coder, Tester, Reviewer |
| Team Room | Visible assignment/result/status collaboration |
| Worker Room | Focused task context and feedback |
| shared/projects | canonical issue plan and lifecycle |
| shared/tasks | located context, patch, tests, review evidence |
| shared/knowledge | distilled post-merge experience |
| Higress consumer credentials | scoped GitHub/LLM/CI access without raw keys |
| Human Team Admin | T4/T5 approval, intervention, rollback authorization |

## Deployment

1. Install AgentTeams following upstream instructions.
2. Build the six deterministic, role-scoped Worker packages:

   ```bash
   python scripts/build_agentteams_package.py
   ```

   Version `1.2.0` deliberately gives each runtime only its owned DevFlow
   Skills; built-in AgentTeams Skills are unaffected:

   | Runtime | DevFlow Skills | SHA-256 |
   |---|---|---|
   | `devflow-lead` | none | `88ec2ea1a908b26ab1603467df890821417507503687c5eaf55ba772d399d769` |
   | `devflow-triage` | `issue-classifier` | `0282da4fa9bdf3cc6e111c159cffbfafa4ae090e63f9398ad16ac9b986b398ba` |
   | `devflow-locator` | `code-root-cause`, `github-evidence` | `aedd5c4cedfd359c6810059458ccb48f4ec6a26a41e0e014ef22f09a8b20cebc` |
   | `devflow-coder` | `patch-generator` | `5d7a7f8db0239ecb1ffdea2acd2022669372ca3aec797d7cd3283df835c9aabc` |
   | `devflow-tester` | `test-runner` | `d7c72fd365a60abe032282f56b9487f78b40f648a16782d2c3012fe7d32b59e1` |
   | `devflow-reviewer` | `pr-reviewer`, `experience-distiller` | `463a7de6f42653aa22dfd0a60b9fac531ad1c32b09a57cb39ee45fa0908a4f96` |

3. Preflight the source-attested archives, create the immutable ConfigMap,
   and publish it on the private namespace-local package service:

   ```bash
   python scripts/reconcile_agentteams_packages.py
   python scripts/reconcile_agentteams_packages.py --apply
   kubectl apply -n agentteams-system -f agentteams/package-server.yaml
   kubectl rollout status deployment/devflow-package -n agentteams-system
   ```

   The Service is `ClusterIP` only, the container has no service-account token,
   runs non-root with a read-only filesystem, and accepts traffic only from the
   `agentteams-system` namespace. It must not be exposed through Higress.
   The package ConfigMap is `devflow-worker-packages-v1-2-0`. Package object
   names are versioned so a controller cannot silently reuse a previously
   downloaded ZIP after a Skill bundle upgrade. Reusing the version with
   different bytes fails; publish a new version instead.
4. Confirm the configured model ID and GitHub MCP server.
5. Apply `agentteams/team.yaml` with
   `kubectl apply -n agentteams-system -f agentteams/team.yaml`. The manifest carries
   the release controller label explicitly; without it, a label-filtered
   AgentTeams controller accepts the CR but does not reconcile it.
6. Wait until `kubectl get team devflow-swe -n agentteams-system -o json`
   reports an active/ready status and all six team Pods are ready.
7. In Element, give the Manager a repository issue and request a DevFlow run.

For a remote server, install
`agentteams/systemd/agentteams-gateway-port-forward.service`. It listens only
on server loopback. Reach it through an SSH local-forward; do not open port
18080 in the public firewall and do not expose MinIO, Tuwunel, the controller,
or the Higress console.

The hardened live manifest exposes a dedicated gateway endpoint only to
`devflow-locator`, and that `devflow-github-readonly` endpoint contains only
`get_file_contents`. Its custom Skill applies a narrower local scope authorizer
before every call. Reviewer, Coder, and all other Workers receive no GitHub MCP
capability. Configure and verify this boundary with
`scripts/configure_higress_github_readonly.py`; see
[`HIGRESS_GITHUB_READONLY.md`](HIGRESS_GITHUB_READONLY.md) for the pinned API
contract, credential handling, and fail-closed runbook.
The AgentTeams controller maps runtime `devflow-locator` to Higress Consumer
`worker-devflow-locator`; the MCP allowlist uses the latter because that is the
identity bound to the Worker's injected gateway key.
Worker-specific `agents` instructions state which Skill each Worker owns,
preventing responsibility drift.

AgentTeams supplies the collaboration rooms and delivery lifecycle; DevFlow
does not treat a room message as trusted authorization. Every delivered domain
artifact is wrapped in a digest-bound `HandoffEnvelope`, and the receiving
Worker verifies its consumer and Skill ownership before execution. MCP access
then requires the same Agent + Skill pair. See the
[responsibility matrix and MCP trust model](BOUNDARIES_AND_MCP.md).

The bundled MCP URL intentionally uses the in-cluster `higress-gateway`
Service. Do not replace it with a public Console or gateway URL in this server
profile.

## Guarded TeamHarness OpenClaw overlay

`scripts/teamharness_openclaw.py` installs the TeamHarness MCP behind
DevFlow's process-role guard and merges one small, DevFlow-owned collaboration
contract into the target workspace's `AGENTS.md`. It does not paste the broad
upstream TeamHarness prompts into `AGENTS.md`. Those upstream prompt files are
copied only under `.teamharness/prompts`; the effective workspace instruction
is the section between these stable markers:

```text
<!-- BEGIN DEVFLOW TEAMHARNESS COLLABORATION -->
<!-- END DEVFLOW TEAMHARNESS COLLABORATION -->
```

The Leader contract requires an explicit immutable `T1`–`T5` risk tier, a
bounded assignment/ACK exchange, and external Ed25519 approval for T4/T5
resume, acceptance, and completion. Reporting follows mark, push, then a
`pending=false` readback. The Worker and remote-member contract is deliberately
one-way: idempotently acknowledge, produce the assigned artifact, submit the
same result idempotently, then stop. A retry whose result digest differs is
rejected. It explicitly
forbids project, room, delegation, acceptance, completion, and assignment
message actions. Manager receives an intake-only contract and cannot operate
either lifecycle.

The effective guarded MCP surface is role-specific:

| Runtime role | Direct TeamHarness tools |
|---|---|
| Leader | `health`, `message`, `roomflow`, `filesync`, `artifact`, `projectflow`, `taskflow` |
| Worker or remote-member | `health`, `taskflow` |
| Manager | `health`, `message` |

Worker and remote-member runtimes cannot call `artifact` or `filesync`
directly. They return their assigned artifact through `taskflow`; Leader owns
the bounded final publication/synchronization step.

The live T4 check currently proves only the fail-closed half of this contract:
Leader created and paused a T4 project, and a resume without an external
approval was rejected with
`approval_denied:approval must contain exactly evidence and signature`. The
ledger remained bound to the project and risk tier with no used nonce, and only the public
verification key was present in the Pods. A human-signed approval and the
subsequent approved resume have not yet been executed and must not be claimed.

The current guard implementation and focused tests additionally bind three
different authorities instead of trusting caller-supplied fields: project risk
comes from the root-owned ledger, project source comes from persistent project
state, and task replay/conflict decisions bind `taskId` to submission digests.
For a task room, the guard reads Matrix state, requires a private invite-only
room, and verifies the exact actual member set. Its `invite`/`members` response
is explicitly labeled as the non-creator requested-worker projection; the
full verified membership is represented separately by its count and digest.
The final operator-driven T2 run described below exercised these bindings. It
does not retroactively turn the earlier failed GitHub task into a success; the
failed and successful executions remain separate records.

`--replace` updates only that marked section and preserves every surrounding
workspace instruction. It rejects unbalanced or duplicate markers. Without
`--replace`, an existing section is an error. Verification requires the exact
role-specific section, matching role facts in `mcporter.json`, the runtime
config, and the externally installed runtime binding, plus a valid hash entry
for `AGENTS.md` in the installation manifest.
It also re-hashes every file recorded by the manifest, so post-install prompt,
Skill, MCP, guard, configuration, or collaboration-contract drift is visible.

In production, the executable trust chain is not loaded from the writable
role workspace. `mcporter` invokes `/usr/bin/python3` with
`/opt/devflow/teamharness/guarded_server.py`; the adapter and pinned upstream
MCP implementation also live under `/opt/devflow/teamharness`. Runtime
binding, install manifest, approval policy, and the Leader public key live
under `/etc/devflow/teamharness`. The installed files are owned by root and
made read-only, while the replay/risk ledger is the only writable state under
`/var/lib/devflow/teamharness`. The external manifest records and rechecks the
exact guard, adapter, server, runtime-binding, policy, and public-key hashes.
A workspace manifest is retained only as non-authoritative diagnostic
evidence and cannot select `sourcePolicy=test-only` for the production guard.

This is integrity hardening, not a sandbox: an agent process retaining UID 0
and sufficient mount/filesystem capability can still replace or remount the
trust chain. Production isolation therefore still requires non-root Workers,
read-only mounts controlled outside the Pod, and a separately privileged
credential broker.

The accepted source is fixed to AgentTeams commit
`78d0ceda336befa6e62bf89fc1a6b08b965e128d` and TeamHarness `0.1.0`.
Installation fails before modifying a workspace unless all four critical
source files match:

| File | SHA-256 |
|---|---|
| `plugin.yaml` | `40121114d1f2a5897e90e21f819f34491bd8062eae25634825f9e7b50b61d518` |
| `mcp/server.py` | `cb9971baae3545f440821ecf1fd18c76078962a1fe1591141cc88026bf5b684f` |
| `mcp/message_tool.py` | `03e8fcfcaf002c5d9dd0c023b85bd4d2f4641b83cb59c6d89be08a9c1689c47c` |
| `mcp/roomflow_tool.py` | `db127d550cf9155c133657ab7c89fee48292c07587a061954bd60b4c14991680` |

PyYAML is optional. When it is absent, the adapter accepts only the
hash-verified upstream `plugin.yaml` and a strict two-space mapping subset for
the runtime config. `member.role` remains mandatory and must equal the install
role; duplicate keys, unsupported YAML structures, embedded runtime
credentials, or ambiguous indentation fail closed. The production CLI has no
hash-bypass flag.

The runtime name and Pod hostname are distinct identities. For example,
`runtimeName=devflow-lead` maps to
`hostname=agentteams-worker-devflow-lead`. The reconciler derives this mapping
unambiguously from Team status, the Pod worker label, and Pod metadata, then
installs the exact binding at `/etc/devflow/teamharness/runtime-binding.json`.
The guard never assumes those two names are equal.

Projected ServiceAccount token paths need the same canonical-path discipline.
On the live cluster, `/var/run` resolved to `/run`; comparing a canonical token
child with an uncanonicalized configured parent caused a false rejection. The
guard now resolves both parent and child before enforcing containment. The
focused regression passed 73 tests with 2 skipped, and the immutable overlay
then reconciled successfully on all six roles. This handles a filesystem alias
without broadening the permitted token parent.

For a direct installation, provide that reconciler-produced binding explicitly:

```bash
python scripts/teamharness_openclaw.py install \
  --plugin-dir /opt/AgentTeams-src/plugins/teamharness \
  --workspace /root/hiclaw-fs/agents/devflow-worker \
  --role worker \
  --runtime-config /root/hiclaw-fs/agents/devflow-worker/runtime/runtime.yaml \
  --runtime-binding /run/devflow-policy/runtime-binding.json \
  --replace

python scripts/teamharness_openclaw.py verify \
  --workspace /root/hiclaw-fs/agents/devflow-worker \
  --role worker
```

For the fixed six-role `devflow-swe` Team, the host-side reconciler performs
that post-rebuild operation consistently across all Pods:

```bash
python scripts/reconcile_teamharness_openclaw.py \
  --agentteams-repo /opt/AgentTeams-src \
  --approval-public-key /operator-policy/approval-ed25519.pub
```

It requires the AgentTeams checkout at commit
`78d0ceda336befa6e62bf89fc1a6b08b965e128d`, a clean tracked
`plugins/teamharness` tree, and the four pinned critical hashes above. Before
copying anything, it requires exactly one active, Running and Ready OpenClaw
Pod for each of the Leader and five Worker roles. It preflights all six
workspaces, stages only tracked upstream plugin files plus the two DevFlow
overlay files, verifies every staged hash, installs Leader as `leader` and all
others as `worker`, passes the public key only to Leader installation, and
requires the adapter's final verification in every Pod. The Ed25519 private
key must remain with the external human approver and must never be copied to
the repository, package, host staging tree, or Pod. Any missing, duplicate,
terminating replacement without a Ready successor,
unready, unknown, or drifted role/source fails the run.

The reconciler reads only Team/Pod metadata and status and uses `pods/exec` to
stage and run the adapter. It never reads Secrets, prints runtime
configuration, creates Kubernetes resources, or applies/patches RBAC. Its
ServiceAccount or operator identity therefore needs only the already approved
Team/Pod `get` and target-Pod `exec` permissions; do not grant broader rights
for this workflow.

Do not treat successful overlay verification as a replacement for the
Kubernetes, Higress, NetworkPolicy, or human-approval boundaries.

## Role-scoped Skill reconciliation after a Pod rebuild

The AgentTeams MinIO workspace is persistent. A replacement Pod can therefore
restore DevFlow Skills that were intentionally omitted from its role package.
Run the fail-closed reconciler after every Team creation, package upgrade, or
Pod replacement, first in read-only check mode:

```bash
python scripts/reconcile_agentteams_role_skills.py
```

The only accepted policy is the fixed six-role, seven-Skill map: Lead has no
DevFlow Skill; Triage owns `issue-classifier`; Locator owns
`code-root-cause` and `github-evidence`; Coder owns `patch-generator`; Tester
owns `test-runner`; and Reviewer owns `pr-reviewer` and
`experience-distiller`. The command requires exactly one Running and Ready Pod
for every role and validates the role identity, `HOME`, current directory,
workspace path, runtime trust chain, local tree, and exact MinIO object keys.
The object-store trust root is also fixed: the authoritative prefix must be
exactly `agentteams/agentteams-storage`, the endpoint must be the in-cluster
AgentTeams MinIO service, and `/usr/local/bin/mc.bin` must match the recorded
release version and SHA-256. Every helper invocation creates a private `0700`
configuration directory, initializes and reads back only the `agentteams`
alias, and never consults the worker's writable `$HOME/.mc` configuration.
Before contacting Kubernetes it validates all six `dist/*-v1.2.0.zip` files,
their sidecars, canonical ZIP and internal manifests, exact per-file hashes,
the current release source reconstruction, and six version-pinned outer ZIP
hashes. Changing source while retaining version `1.2.0` therefore fails; a
different release requires a version and pinned-digest update.
Its JSON result exposes only the fixed known-Skill sets, counts, and
`needsApply`; it does not return Skill contents, MinIO configuration, or
credentials to the host. `devflowPolicyVerified=true` means only that the
fixed seven-Skill DevFlow policy agrees across the controller archive cache,
controller persistent Skill cache, Worker-local trees, and MinIO.
`completeRoleSkillBoundaryVerified=false` remains explicit because built-in,
platform, and unknown Skills are outside that complete-boundary claim and are
never deletion targets.

After reviewing all six role results, apply the fixed plan with:

```bash
python scripts/reconcile_agentteams_role_skills.py --apply
```

Apply mode repeats the full six-Pod check and requires identical snapshot
digests before changing any role. It then runs a non-production temporary
filesystem preparation on all six Pods and requires working directory `fsync`,
Linux `RENAME_EXCHANGE`, and `RENAME_NOREPLACE` (including collision behavior)
with unchanged Skill snapshots before the first MinIO or local mutation. For
each drifted Pod it deletes only a
disallowed member of the known seven-Skill set, first at the exact authoritative
`<storage-prefix>/agents/<role>/skills/<skill>/` component-bounded prefix and
then at the exact local `skills/<skill>` directory. Missing, partial, stale,
extra-file, or mode-drifted allowed trees are not trusted or preserved: the
host streams only that role's pinned archive over Pod stdin, the Pod verifies
its outer hash, manifest self-hash, paths, sizes, and file hashes before any
mutation. MinIO replacement uses staged and backup trees plus a phase manifest
and readback so an interrupted run can recover or refuse inconsistent state;
this is crash recovery, not native atomic replacement of an S3 object tree.
The local tree is swapped with Linux `renameat2(RENAME_EXCHANGE)`, and the
displaced tree must retain its preflight identity before it can be deleted.
Complete allowed, built-in, and unknown Skills remain unchanged. A final
content and manifest readback must show the exact policy on all six Pods. The
command does not create Kubernetes resources, patch RBAC, or read Kubernetes
Secrets. All `kubectl` and MinIO subprocesses have fixed deadlines; captured
output and object reads are bounded before parsing. Sensitive MinIO values are
kept out of child-process arguments, and the remote helper body and archive are
sent through bounded stdin rather than command-line arguments.

A remote deployment cannot contain only this script and `dist`. The minimal
release overlay is:

- `scripts/reconcile_agentteams_role_skills.py`,
  `scripts/reconcile_agentteams_packages.py`,
  `scripts/build_agentteams_package.py`,
  `scripts/reconcile_agentteams_mcporter_policy.py`, and
  `scripts/reconcile_teamharness_openclaw.py`;
- `agentteams/worker-package/`;
- all seven directories under `skills/` named by the fixed policy; and
- all six `dist/devflow-*-v1.2.0.zip` files and their `.sha256` sidecars.

Keep their repository-relative layout. Package loading reconstructs the
release from the source root derived from the package reconciler's own path;
copying only the archives would intentionally fail source attestation.

This is a deterministic repair and integrity check, not a cross-Pod atomic
transaction or a sandbox. A Pod failure can leave a multi-Pod run to be
resumed or rerun. The staged/backup MinIO protocol is crash-recoverable, but
S3 still offers no atomic tree swap and concurrent privileged writers remain
outside the claim. A privileged process can also race a local path after its
last metadata check. Mounts at or below `skills/` are rejected, but workers
still remain UID 0 with workspace credentials. A hostile root process can
race or replace the otherwise hash-pinned client after attestation or tamper
with runtime state; this is not a hostile-root integrity claim. OS-level
isolation still requires non-root containers, a read-only pinned client and
policy mount, disabled mount/ptrace capabilities, and a separately role-scoped
credential broker.

Live follow-up on 2026-07-28 closed the previously recorded reconciliation
failure. The immutable `final4.4` apply converged the fixed seven-Skill DevFlow
policy across all four runtime surfaces: controller archive cache, controller
persistent Skill cache, Worker-local trees, and MinIO. An independent
read-only check then returned `devflowPolicyVerified=true` with no changed
roles. After Locator replacement, it retained exactly `code-root-cause` and
`github-evidence`; all six Pods were Ready. The deliberately narrower result
also returned `completeRoleSkillBoundaryVerified=false`: this verifies the
named seven DevFlow Skills, not a complete boundary over built-in, platform,
or unknown Skills, and not strong OS isolation.

That distinction was confirmed by a real Locator task: the package held the
current 12,925-byte GitHub authorizer, while persistent storage restored an
older 1,892-byte copy without the required envelope/capability CLI. Locator
returned `SKILL_RUNTIME_VERSION_MISMATCH` as `FAILED`; an identical retry was
idempotent and an altered retry was rejected as `submit_result_conflict`.
This remains valid failure/retry evidence, distinct from the later successful
task.

### 2026-07-28 operator-driven success sequence

The fresh success path required six attempts. Run 1 returned no result. Run 2
failed closed when the real ACK field did not match the driver's precondition.
Run 3 found a misconfigured role-scoped shared path. Run 4 completed the core
task/project path but failed filesync role/workspace binding. In Run 5 the
TeamHarness push guard internally verified both expected objects, but the outer
minimal executor had not allowlisted the independent `stat` operation. Run 6
used the final pinned trees and completed the bounded T2 path. No partial run
is counted as the final success.

Run 6 verified all of the following without retaining the actual project,
room, capability, endpoint, credential, or repository content in this record:

- the project was `completed` and its requester report read back
  `pending=false`;
- `validatorPassed`, `firstSubmit`, `idempotentRetry`, `conflictRetry`,
  `postConflictReadbackBound`, and `leaderCheckEffective` were all `true`; the
  altered retry was rejected and Leader read back `effective=true`;
- push reported `expectedObjectCount=2` and `verifiedObjectCount=2`, followed
  by independent `stat exists=true` responses for `meta.json` and `plan.md`;
- all six Pods were Ready, and an independent role check reported zero changed
  roles, `devflowPolicyVerified=true`, and
  `completeRoleSkillBoundaryVerified=false`.

The deployed TeamHarness `final4` tree SHA-256 was
`263681c7526daa09940bc3b2c754957f6cd7341ed0f38bfa3f78af5a06f12d40`;
the deployed success-driver `final7` tree SHA-256 was
`10aa2f3bc09d90970229c997dab595de52557b84b1d6719cf4191b968e129781`.
The Leader TeamHarness schema pin was 28,909 canonical bytes at
`985fbb53710bc62f34e0194783a68852e4a7400bea794b6600023f96bf730eea`.
Locator's pins were unchanged: 1,742 bytes at
`2588f5c5d201588468e86c93899f22ff913b98c7c6784173b23640b1718ab887`
for the read-only GitHub MCP schema and 4,203 bytes at
`a4243ba99239622210efd749ac06e30d3d7d1673c4cbf07db80720ed5859b69a`
for TeamHarness. See
[`AGENTTEAMS_LIVE_20260727.md`](evidence/AGENTTEAMS_LIVE_20260727.md).

Filesync rejects caller exclusions and unknown arguments, binds the resolved
real workspace to the runtime identity, rejects symlinks/hardlinks and empty or
oversized push trees, fingerprints file size/mtime/content, and stats every
expected object before returning a verified count. The separate remote stats
prove only that objects exist at the bound paths, not that their remote bytes
match a digest. A same-UID process can still race checks, and detecting a
failure after an upstream operation cannot prove that no external write
occurred. These constraints remain part of
`strongBoundaryEnforceable=false`.

This success is one operator-driven T2 evidence workflow. It is not the
six-stage repair, a signed T4 approval/resume, or a Tester-to-Coder retry.

## OpenClaw native tool-boundary audit

`scripts/reconcile_openclaw_tool_policy.py` is intentionally read-only. The
audit was derived from the schema and TypeScript source shipped in OpenClaw
`2026.4.14 (2f35b6f)`, rather than from assumed option names. It verifies all
six Ready role Pods, the exact runtime version, the relevant source semantics,
the runtime JSON schema, both live and MinIO-authoritative configs, and
`openclaw config validate --json`. Only digests, policy states, booleans, and
fixed blocker codes return to the host; config and command output stay inside
the Pod.

The 2026-07-27 live run exited non-zero with `verified=false` and
`strongBoundaryEnforceable=false` for all six Ready roles. The exact blockers
were:

1. `ROOT_RUNTIME_SHARED_WITH_AGENT_TOOLS`
2. `FS_WORKSPACE_ONLY_HAS_NO_SENSITIVE_PATH_EXCLUSIONS`
3. `OPENCLAW_POLICY_IS_STORED_IN_AGENT_WORKSPACE`
4. `EXEC_APPROVAL_STATE_IS_STORED_IN_AGENT_WORKSPACE`
5. `MCP_CREDENTIAL_CONFIG_IS_STORED_IN_AGENT_WORKSPACE`
6. `MCP_REQUIRES_GENERAL_PURPOSE_EXEC`

This non-zero result is the correct audited outcome, not a broken test. Until
the listed OS-layout conditions are removed, documentation and demos must say
that DevFlow enforces logical/process-role and MCP/network boundaries, while a
strong hostile-root boundary is unavailable.

The audited semantics are:

- `tools.allow` is an absolute allowlist at its policy stage and `tools.deny`
  wins, but an absent/empty allowlist is not a restriction.
- `tools.fs.workspaceOnly=true` contains `read`, `write`, `edit`, and
  `apply_patch` to the whole workspace; it has no sensitive-subpath exclusion.
- a non-sandbox `exec` falls back to `security=full` and `ask=off` unless a
  stricter config/approval policy is effective. `safeBins` is only a narrow
  stdin-safe bypass, while `strictInlineEval` covers interpreter inline-eval
  forms rather than all shell behavior.
- `apply_patch` is workspace-contained by default, but this still includes
  policy and credentials when those files share the workspace.
- elevated execution has a separate enable/sender gate and should be disabled
  explicitly; denying the `gateway`, `nodes`, `cron`, browser, web, session,
  and subagent tools does not repair a writable policy root.

The current AgentTeams Worker layout cannot honestly turn those settings into
a strong security boundary. OpenClaw runs as UID 0, and `openclaw.json`, the
default exec-approval path, MinIO client material, and `config/mcporter.json`
are colocated with the role workspace. Roles need workspace file access, and
TeamHarness/GitHub MCP calls currently pass through the general-purpose
`mcporter` executable. Therefore a role able to read/write that workspace can
reach credential or policy material, while auto-allowing `mcporter` would not
bind it to one immutable server/config.

Run the reproducible audit with:

```bash
python scripts/reconcile_openclaw_tool_policy.py
```

An unsafe system exits non-zero and reports `strongBoundaryEnforceable=false`.
`--apply` still preflights every Pod, then exits with code 2 without writing.
This prevents a defense-in-depth recommendation (`tools.allow`, explicit
denies, workspace-only files, elevated off, and approval-gated exec) from
being mislabeled as enforcement.

Before an apply mode can be added, run Workers as non-root; mount config and
exec-approval state read-only outside the agent-visible workspace; replace
workspace credential files with a scoped broker/sidecar; provide an immutable,
operation-scoped MCP invocation surface; and separate writable code/artifact
paths from policy and runtime state at the OS boundary.

## Evidence expected from a live run

- Matrix messages showing assignment and result boundaries.
- Project/task state from AgentTeams tools.
- shared task artifacts for localization, patch, tests, and review.
- DevFlow JSON report and OpenTelemetry trace ID.
- PR URL or an explicit dry-run result.
- For T4/T5, record pause, unapproved-resume denial, the exact approved
  evidence digest/signature, and approved resume as separate events.

The current live record contains the earlier two-node lifecycle, task-room
communication, role-guard rejection, scoped GitHub MCP positive/negative
checks, one honest GitHub task failure with replay/conflict behavior, the fresh
operator-driven T2 success with filesync/readback evidence, T4 pause plus
unapproved denial, and scoped four-surface convergence of the fixed seven
DevFlow Skills including a Locator replacement check. The hardened driver uses
direct stdio/Streamable HTTP, keeps sensitive values out of child arguments,
attests the role×server configuration/schema, and enforces hard deadlines. The
record still does not contain a signed T4 resume, Tester-to-Coder retry, or a
six-stage repair. See
[`AGENTTEAMS_LIVE_20260727.md`](evidence/AGENTTEAMS_LIVE_20260727.md).
