# DevFlow 1.3.0 local release-candidate evidence

Evidence date: 2026-07-28 (Asia/Shanghai).

> **Superseded snapshot.** The numbers in this file describe the earlier
> pre-finals worktree at the time recorded below. Later finals changes have a
> separate quality gate and must not cite `846 / 17 / 84.40%` as current.

## Claim boundary

This record covers an earlier local, modified release-candidate worktree. It
is not bound to a final commit or tag, does not prove that 1.3.0 is deployed to
AgentTeams, and does not replace the historical 1.2.0 cluster evidence. Repeat
the same gates after freezing the submission commit.

The portable runtime now has a real
Coder-to-Tester-to-TeamLeader-to-Coder repair loop. A live AgentTeams Team Room
record of that loop, a human-signed T4 resume, and the 1.3.0 cluster rollout
remain separate evidence gates. Reviewer rejection is intentionally
fail-closed at TeamLeader pending a candidate-bound remediation contract.
External model-paired behavior evaluation was not rerun because this local
process had no `LLM_API_KEY`; only the complete behavior-suite structure was
validated.

## Full test and coverage gate

Command:

```powershell
python -m pytest --cov=devflow --cov-report=term --cov-report=json:coverage.json --cov-fail-under=80 -q
```

Result:

- 846 passed;
- 17 skipped for environment-specific integrations;
- 84.40% aggregate line coverage (3,874 of 4,590 statements);
- TeamLeader 80%, LLM client 96%, RAG codebase indexer 84%, Tester 94%,
  structured test/failure evidence model 96%, local task router 86%, and
  shared secret policy 97%.

## Static, configuration, and Skill gates

- Ruff: passed.
- Mypy strict check: 103 source files, no issues.
- DevFlow configuration: 6 Agents, 7 Skills, 2 MCP servers, valid.
- Static Skill evaluator: all 7 Skills scored 100/100.
- Behavior-suite validation: 14 cases covering all 7 Skills.
- `git diff --check`: passed with no whitespace errors.

## Deterministic 1.3.0 role packages

All six packages were rebuilt with `SOURCE_DATE_EPOCH=0`, validated against
their canonical manifests and sidecars, and reproduced from the current trusted
source tree.

| Role | Bytes | SHA-256 |
|---|---:|---|
| devflow-lead | 2,862 | `c082670199dcefcbbcaf6afd888c364999ccca5a8cd243979c399238253d97f2` |
| devflow-triage | 15,721 | `7c14a62a0dce3c774b7e0e4fcff969ed9ba8fdcabc4356ef7a080c47dcd51bca` |
| devflow-locator | 57,200 | `b0e9422d16202cdea690deeef3f7629f5b400333b00fbd329d61c6f9da521019` |
| devflow-coder | 56,024 | `23469bd358c0044f20877bb7035734d724742ad8dde34e35ce11035cd502e643` |
| devflow-tester | 55,161 | `011524dc5f839fb9157da82a9a30bdd1debb31e58d9371fda37c0f67a9e1ac7e` |
| devflow-reviewer | 37,151 | `c25b44efee849740f92390d4e9de2773ee6a6392ef0e3301217aa1563994702a` |

Focused publication, cache, role-policy, and TeamHarness reconciliation tests
also passed. The package paths, immutable ConfigMap, package server, Team
manifest, controller audit helpers, source-attestation policy, and CI artifact
upload contract all point to 1.3.0. The upstream AgentTeams controller remains
intentionally pinned to its independent `v1.2.0-beta.1` platform version.
