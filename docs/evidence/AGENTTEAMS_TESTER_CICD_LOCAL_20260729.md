# AgentTeams Tester CI local candidate evidence — 2026-07-29

## Claim boundary

This record covers local source, policy, deployment-manifest, receipt-contract,
and negative-boundary tests only. It is **not** a container image build,
registry digest, Kubernetes rollout, NetworkPolicy packet test, real
Bubblewrap namespace execution, or live AgentTeams task-projection receipt.

The candidate image is deliberately limited to:

- one clean-commit, image-fixed DevFlow repository fixture;
- one fixed T2 focused-suite assignment;
- one fixed T3 full-suite assignment;
- fixed image-generated focused/full argv; and
- `assignmentSourceLiveAgentTeams=false`.

It must not be described as a generic repository runner or a real-time
AgentTeams controller assignment source.

## Locally verified properties

- The runnable image stage is based on an exact base-image digest and contains
  the server, OpenSSL, Bubblewrap, fixed repository tree, fixed test argv,
  policy finalizer, and fixed assignment materializer.
- The public build context excludes `.git` and private-key inputs. Execution
  and receipt policies are generated inside the image after runtime executable
  hashes are known.
- Kubernetes desired state uses one independent Deployment, ServiceAccount,
  ClusterIP Service, immutable release ConfigMap, default-deny NetworkPolicy,
  and Tester-label-only ingress policy.
- ConfigMap policy bytes are mounted at the exact server paths
  `/etc/devflow/agentteams-cicd/policy.json` and
  `/etc/devflow/agentteams-cicd/test-receipt-policy.json`.
- The receipt key is referenced only through the pre-created Kubernetes Secret
  and mounted only by the main `ci-mcp` container. The init container does not
  receive it. Reconciliation scans current normal/init/ephemeral containers and
  common workload templates. This proves only the observed consumers; it does
  not enforce a Secret ACL against a namespace principal that can create or
  mutate Pods.
- The same immutable-image public key and canonical receipt policy are
  installed into all six TeamHarness role Pods at fixed verifier paths. Their
  manifests bind the policy/key hashes and report
  `replayScope=pod-incarnation`,
  `replayLedgerPersistentAcrossPodReplacement=false`, and
  `receiptLifetimeSeconds=120`.
- The `0600` JTI ledger is Pod-local, not PVC/MinIO-backed. A Leader Pod
  replacement loses that history, leaving a possible replay window for the
  unexpired portion of a receipt's 120-second lifetime.
- The current local guard upgrades that ledger to v2 `pending`/`committed`
  reservations. A reservation binds receipt/run/task and canonical accept
  request/result digests, retains one upstream submitter under the same
  cross-process lock, and commits only after exact `taskflow.check_task` plus
  `projectflow.resolve_project` readback. This split is required by the pinned
  AgentTeams source: task meta remains `submitted` after acceptance while the
  project plan node becomes terminal.
- Targeted local fault tests cover failure-before-mutation and same-receipt
  retry, response loss after mutation and idempotent recovery, concurrent
  calls reaching the upstream transition once, conflicting authoritative
  state retained as pending, and expired crash-reservation recovery. They are
  deterministic local fault injection, not live Team Room evidence.
- The init container uses the same digest-pinned image, probes the exact
  namespace-isolation prefix, materializes only the two fixed assignment
  templates into a fresh volume, and seals it before the main container starts.
- `/readyz` names the fixed repository, command, and assignment sources and
  reports that the assignment source is not live AgentTeams.
- Endpoint and mcporter post-apply checks originate only from the discovered
  Tester Worker and require exactly one `run_tests` tool with the canonical
  three-field input schema.
- The reconciler keeps desired NetworkPolicy object readback distinct from CNI
  observation. A real release needs one Tester positive probe and five
  non-Tester negative probes; no such cluster packet result is claimed here.

## Checks executed

The pre-reservation TeamHarness installer/reconciler/receipt group completed
with `142 passed`; the isolated-CI reconciler group completed with `15 passed`.
Targeted Ruff, strict mypy, and `git diff --check` completed successfully for
the public-trust installation and isolated-CI reconciliation files. These
local tests do not substitute for a Linux image build or live CNI probes.
The 2026-07-30 receipt-state update separately completed `97 passed` for the
full TeamHarness adapter file and `32 passed` for the receipt verifier/state
machine file. The complete `test_teamharness_*` group completed `235 passed,
6 skipped`, with Ruff clean for the changed guard, installer and tests.

The available local Docker client had no running daemon, so no image digest or
runtime result is claimed here. A release claim requires building and pushing
the exact clean commit, extracting policies from that exact image digest,
pre-creating the signing Secret, applying through the reconciler, and
capturing its complete post-apply readback.
