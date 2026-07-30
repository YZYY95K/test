# DevFlow finals candidate quality gate — 2026-07-30

> **CANDIDATE WORKTREE EVIDENCE — NOT YET A RELEASE ATTESTATION.** All numerical
> results below were regenerated together on the current 2026-07-30 candidate
> worktree. They may be cited as local candidate evidence, but not as a clean
> commit, server execution, official acceptance, tag, or deployed release until
> the same gates pass on the frozen commit and the submission archive binds it.

## Claim boundary

Four evidence layers remain separate: local verification,
candidate/deployment preflight, dated historical live evidence, and
current-version server evidence still pending. This file covers only the first
two. It is not a release tag, official acceptance, live six-stage AgentTeams
run, human-signed cluster T4 resume, or model-backed result on the 21
repository-repair tasks; Agent attempted/executed counts for those tasks remain
0.

## Reproducible environment template

- Record the exact clean Git commit and prove an empty worktree.
- Record CPython and the hash-locked dependency installation environment.
- Revalidate all MCP lock profiles and the declared FastMCP range on that same
  commit.

## Full test and coverage gate

```powershell
$env:PYTHONPATH = "src"
python -m pytest -q --cov=devflow --cov-report=term-missing `
  --cov-report=xml:.tmp/coverage.xml --cov-fail-under=80
```

Candidate result: **1,330 passed / 24 skipped in 192.43 seconds** on CPython
3.10.11 for Windows. Coverage was **84.06%**: 6,325 statements, 1,008 missed,
and 5,317 covered. The JSON and XML reports were written to
`.tmp/final-coverage.json` and `.tmp/final-coverage.xml`. This is the complete
suite, not a focused-test count. The 24 skips are platform/optional-integration
cases reported by pytest; the Linux systemd/DynamicUser/CNI paths still require
server execution. Do not reuse the former `1,033 passed / 17 skipped / 84.79%`
snapshot.

## Static, Skill, upstream, and material gates

- Ruff passed over the repository; mypy passed over 143 source files; compileall
  and `git diff --check` passed.
- Static Skill evaluator: 7/7 packages scored 100/100 under the internal
  structural rubric; all 14 behavior-case structures passed. This is not an
  external semantic-quality score.
- The repository-repair manifest validated 21 execution-ready mutation tasks
  across three exact repositories; Agent attempted/executed remain 0.
- Locked AgentTeams v1.2.0-beta.1 commit, CRD and Apache-2.0 license verification
  passed.
- Rebuilt finals PPTX/PDF passed 12/12 page render inspection, template
  fidelity, notes/source checks, credential-shape scanning, and PDF security
  checks on the current candidate worktree. Exact material hashes are recorded
  in `docs/finals/MATERIAL_QA_20260728.md`; this is not yet a clean-commit, CI,
  tag, or release attestation.
- Dependency lock, SBOM and license evidence must be regenerated from the frozen
  commit.

## Deterministic AgentTeams role-package candidates

The table below is the local v2.1.0 candidate-package snapshot. Two consecutive
builds on 2026-07-30 were byte-identical, including sizes and SHA-256 values.
This is not a tagged or deployed release; CI must repeat the same check on the
frozen commit.

| Role | Bytes | SHA-256 |
|---|---:|---|
| devflow-lead | 3,122 | `7a55f3a8fd8bc9490b03f1d99cea39f420f31a69cf84d19fb6b54851f36c0228` |
| devflow-triage | 30,687 | `b6efdc4d7ca718682c059508054328a314d51f405a2cd463bdf37c7327752adf` |
| devflow-locator | 87,952 | `1aa3cf8a61fec15736bdf3480371e1fffe1f568aada0d899a0420fa761305d7a` |
| devflow-coder | 56,703 | `118836944dc2b244a1b2e05db61c351c7b1b9fe3188571db1ccc8e0b67c8f8ba` |
| devflow-tester | 68,776 | `93ce45aaaa501b4c9c9696b1bbd70b6313782fd5ddc7cfe9956c7866a4f2e7a2` |
| devflow-reviewer | 77,464 | `bb9e194aaab7eebb007b96ad2120616a3bc437c072e44b4c2eac5e07d57bbc08` |

## Open gates

- Authenticate the intended server through the separately approved trust path;
  this draft carries no current host-key assertion.
- Treat previously pasted credentials as compromised and do not reuse them.
- Build/push/reconcile the current Tester CI image, then capture a real
  `run_tests -> signed receipt -> Leader accept -> dual readback -> retry`
  result. Deployment preflight alone is not E2E.
- The final release tag, public upload, video, current six-role/six-stage
  AgentTeams closure, signed T4 resume, and 21 model-backed repair runs remain
  open; the 21-task Agent attempted/executed counts remain 0.
