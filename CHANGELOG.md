# Changelog

All notable changes follow semantic versioning.

## 2.1.0 - Unreleased finals candidate (2026-07-30 worktree)

- Standardized Worker failures as strict, source-bound `SkillFailure` results
  mediated only by TeamLeader; strengthened Triage, Locator, Reviewer, and
  Distiller validators against plausible but ungrounded evidence.
- Replaced shape-only GitHub receipts with a deployment-bound Ed25519 receipt
  v2 bindings over run, task, trace, repository, revision, complete paths,
  scope, capability, and content digests. The v2 signer and verification path
  remain candidate code until a digest-pinned redeployment is recorded.
- Added the independent Tester-only `devflow-cicd:run_tests` Streamable HTTP
  MCP with acknowledged TeamHarness assignment binding, fixed commands,
  immutable repository policy, a Bubblewrap isolation profile, bounded
  resources, and short-lived Ed25519 execution receipts. Source, policy, and
  negative paths are locally tested; no current image build, namespace run, or
  cluster end-to-end receipt is claimed. Within one Leader Pod incarnation an
  exact same-binding retry is idempotent, while conflicting bindings fail
  closed; the ledger is not durable across Pod replacement.
- Added a fail-closed offline server experiment runner with systemd
  `DynamicUser`, capability removal, private-network policy, hash-linked
  receipts, completion sealing, and an independent copied-output verifier. Its
  Linux isolation properties remain pending real server execution.
- Replaced deterministic redaction-pass fixtures with scans of the exact
  persisted experience text: secret or email-PII matches are rejected, and a
  scanner failure cannot emit passing evidence. Tester MCP identity now reports
  the same `2.1.0` candidate version as the project and role packages.
- Removed Reviewer GitHub writes, direct root-cause GitHub access, orphan
  TeamLeader Skill grants, pipeline controls, deployment, and rollback from the
  released autonomous MCP surface.
- Built deterministic AgentTeams role-package candidates `2.1.0` locally;
  retained distinct `2.0.0` archives without overwriting them. Neither version
  is represented here as a tagged or deployed finals release.

## 2.0.0 - Unreleased development milestone (2026-07-28 worktree)

- Made Agent identity executable: every local LLM call now receives a
  runtime-built role, capability, Skill, and hard-boundary system instruction;
  AgentTeams keeps the corresponding role package as deployment authority.
- Added durable collaboration leases, causal hand-offs, signed human-approval
  targets, test-integrity gates, fail-closed MCP execution, and auditable
  local six-stage recovery semantics.
- Added an exact AgentTeams upstream/CRD compatibility lock, deterministic
  role-package reconstruction, production observability integrations, and
  explicit separation between local, live-cluster, and not-yet-proven claims.
- Added three fixed open-source repositories with 21 deterministic mutation-
  repair fixtures/tasks, source/license/fixture digests, a safe patch-execution
  kernel, and resumable evidence reports without exposing the mutation oracle.
  Fixture prevalidation is complete; Agent attempted/executed counts remain 0.
- Added finals-facing PPT/PDF sources, acceptance and identity appendices, and
  a clean-Git deterministic submission builder with dependency, SBOM, license,
  manifest, checksum, and provenance gates.

## 1.3.0 - 2026-07-28

- Added a typed Tester-to-TeamLeader-to-Coder repair route with sanitized,
  digest-bound failure evidence, one route claim per execution attempt, and a
  three-call issue-global Coder model budget shared by validation and test
  retries.
- Hardened Coder input/output boundaries with shared credential redaction,
  Locator-derived file scope, patch consistency checks, syntax validation, and
  whole-candidate secret scanning.
- Upgraded `patch-generator` to 2.3.0 and `test-runner` to 3.2.0 with strict
  runtime-aligned contracts, PatchCandidate 1.2 evidence scopes and model-call
  ordinals, standalone
  source-bound validators, and cross-Skill mediation checks.
- Added a canonical local task router, Leader-owned dispatch claims, deep-copy
  event isolation, bounded test-result ingress, and generic named-credential
  redaction.
- Bound T4/T5 resume approval to a deployment domain, policy key, project
  incarnation, action, task, risk, target, and one exact request digest; added
  legacy-policy and cross-deployment replay rejection tests, race-safe key
  creation cleanup, and stale approval-ledger lock recovery.
- Prepared deterministic 1.3.0 release-candidate role packages and updated the
  package server, controller cache policy, source attestation, CI artifacts,
  and deployment documentation. Final commit/tag binding and server deployment
  evidence remain separate release gates.

## 1.2.0 - 2026-07-27

- Built and deployed six deterministic, role-scoped AgentTeams Worker packages
  in the dated 2026-07-27 AgentTeams environment, and added a seventh
  `github-evidence` Skill with an envelope-bound local authorizer.
- Added guarded TeamHarness role enforcement, idempotent task transitions,
  digest-bound T4/T5 approval, and scope-bound GitHub capability issuance.
- Added a pinned Higress read-only MCP route, Broker receipts, NetworkPolicy,
  Redis-backed MCP sessions, and live positive/negative boundary evidence.
- Added package, runtime, MinIO, Matrix compatibility, and native OpenClaw
  boundary reconcilers with fail-closed checks.
- Added the final preliminary-round PPT/PDF, a fixed sample request and
  machine-checkable expected output, and the complete Apache-2.0 license.

## 1.0.0 - 2026-07-24

- Added a six-agent AgentTeams software-delivery design.
- Added six self-contained Skill v2 packages with executable quality gates.
- Added typed, digest-checked inter-agent hand-offs.
- Added isolated regression testing, security approval policy, audit design,
  and terminal experience distillation.
- Added a credential-free deterministic demonstration and AgentTeams worker
  package builder.
