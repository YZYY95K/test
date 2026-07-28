# DevFlow 1.3.0 local release-candidate evidence

Evidence date: 2026-07-28 (Asia/Shanghai).

## Claim boundary

This record covers the current local, modified release-candidate worktree. It
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
| devflow-lead | 2,163 | `5ec6e76a43a6b4a5cf55fd0321f82be2f81b294c75081c18a139ec32c5757661` |
| devflow-triage | 14,595 | `bcb84afa4004a1b1c208a83bee8fdc7ef8bdea289b740b909677e2f152ca02da` |
| devflow-locator | 56,415 | `2d59b7d1533165009596167bc6470a0ba473895c835a390e083e967cddd2ff53` |
| devflow-coder | 54,690 | `5425868754f5539eb5568fdfb5900d7fa0bcee6f724f92cf26bb2a289ac3de7f` |
| devflow-tester | 49,237 | `68ad37e009c5485230dc38065c2095d751d6298943ebe88bbc471040b2488de2` |
| devflow-reviewer | 28,232 | `6e2c4a4a76b9860e1931275d820cff3f961133257567d6eed417ae7cf896e947` |

Focused publication, cache, role-policy, and TeamHarness reconciliation tests
also passed. The package paths, immutable ConfigMap, package server, Team
manifest, controller audit helpers, source-attestation policy, and CI artifact
upload contract all point to 1.3.0. The upstream AgentTeams controller remains
intentionally pinned to its independent `v1.2.0-beta.1` platform version.
