# DevFlow finals local quality gate — 2026-07-29

## Claim boundary

This record covers the frozen finals release-candidate source identified by the
package provenance commit. It proves repeatable local engineering gates, not a
release tag, official acceptance, a live
six-stage AgentTeams run, a human-signed cluster T4 resume, or model-backed
results on the 21 repository-repair tasks. Repeat every gate after committing
the final tagged release if any source or material changes.

## Reproducible environment

- CPython: 3.12.13 in a fresh isolated environment.
- Dependency installation: `uv pip sync --require-hashes` from
  `requirements/dev.lock.txt` against the official Python package index.
- MCP compatibility: all three lock profiles resolve `mcp==1.29.0`; the
  declared FastMCP dependency is bounded to `>=1.2.0,<2`.

## Full test and coverage gate

```powershell
$env:PYTHONPATH = "src"
python -m pytest -q --cov=devflow --cov-report=term-missing `
  --cov-report=xml:.tmp/coverage.xml --cov-fail-under=80
```

Observed result:

- 1,033 passed;
- 17 skipped for environment-specific integration paths;
- 84.79% aggregate line coverage (6,324 statements / 962 missed);
- TeamLeader 79%, LLM client 96%, RAG indexer 81%, experience store 75%,
  Tester 94%, collaboration ledger 87%, and CI/CD policy 86%.

## Static, Skill, upstream, and material gates

- Ruff: all checks passed.
- Mypy strict: 127 source files, no issues.
- Static Skill evaluator: 7/7 Skills scored 100/100.
- Behavior structure: 14 cases covering all 7 Skills.
- AgentTeams upstream: official repository, release
  `v1.2.0-beta.1`, commit
  `78d0ceda336befa6e62bf89fc1a6b08b965e128d`, Team CRD bytes and
  Apache-2.0 license bytes verified online against their locked hashes.
- Finals materials: 12 PPTX slides, 12 notes pages, 12 `[Sources]` blocks,
  and 12 PDF pages; OOXML relationships and the PDF object graph passed the
  fail-closed semantic gate.
- Dependency license evidence covers all 122 locked package/version identities.
  Exact PEP 639 fields and unambiguous allowlisted PyPI metadata reduced
  `NOASSERTION` from 63 to 7; ambiguous records remain explicitly unresolved.

## Deterministic AgentTeams role packages

Two consecutive builds with `SOURCE_DATE_EPOCH=0` produced byte-identical
results:

| Role | SHA-256 |
|---|---|
| devflow-lead | `82ffe34e3f02162febe4d1e88c5ed68b4676d4917007d6f8a2cf13e0cb9741a5` |
| devflow-triage | `d5297a1741b0279310dc1adbe36cc02c5c33c8cf5897f4ea1532b4761f21630f` |
| devflow-locator | `cab3503cd3100bf42238cf3b53ad65deca95e9e9e6b99551a81bb0f506daf54b` |
| devflow-coder | `a54c323f4599899b8bee7950a759ec0e9cd0c56ae27fd091e559853ed9d41b16` |
| devflow-tester | `684de72825bb0fdc9a0435c7e568934ce85dc8a37d30e17aa67d1eb7d3833563` |
| devflow-reviewer | `e3d5513508f49b288384fbf47b746dbb52760de997388450f5636c640895842a` |

## Open gates

- The two server addresses now present ED25519 fingerprint
  `SHA256:WEeKFd90sfhAztcvbci9bH98kReJlkMNgvlkskxTnJA`, which differs from the
  locally recorded keys. No host-key replacement was accepted.
- No supported model key is present in the process environment. Previously
  pasted credentials are treated as compromised and are not reused.
- The final release tag, public upload, video, live five-role AgentTeams
  closure, signed T4 resume, and 21 model-backed repair runs therefore remain
  open.
