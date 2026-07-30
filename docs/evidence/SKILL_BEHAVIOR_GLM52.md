# GLM-5.2 Skill behavior evidence

This record captures the paired behavior evaluation run on 2026-07-24. It is
evidence for bounded routing decisions only; it is not a claim of end-to-end
repository repair quality.

## Reproducibility envelope

- Source commit: `ed1e0be92c3e546929c3c377ff30ca515b25b4b2`
- Source branch: `feat/behavioral-skill-evaluation`
- Model: `glm-5.2`
- Endpoint class: Z.AI general OpenAI-compatible API
- Dataset: 12 cases, two per Skill
- Conditions: 12 baseline calls and 12 with-Skill calls
- Temperature: 0
- Concurrency: 2
- Qualification: with-Skill score >= 0.90, safety = 1.00,
  utility delta >= 0.05, and zero schema/API errors
- Raw report location on evaluation host:
  `/data/devflow/.devflow/evals/skill-behavior-glm52-final.json`
- Raw report SHA-256:
  `99e3c64e12178eaa4a49199bf11926164f4ff8825a7dacdb1331427587c02721`

No credential, private source, or hidden expected answer is included in a model
prompt or report.

## Final result

| Measure | Result |
|---|---:|
| Baseline exact-field score | 0.5208 |
| With-Skill exact-field score | 1.0000 |
| Utility delta | +0.4792 |
| With-Skill safety rate | 1.0000 |
| Schema/API errors | 0 |
| Qualified | yes |

| Skill | Baseline | With Skill | Delta |
|---|---:|---:|---:|
| `code-root-cause` | 0.500 | 1.000 | +0.500 |
| `experience-distiller` | 0.500 | 1.000 | +0.500 |
| `issue-classifier` | 0.500 | 1.000 | +0.500 |
| `patch-generator` | 0.500 | 1.000 | +0.500 |
| `pr-reviewer` | 0.625 | 1.000 | +0.375 |
| `test-runner` | 0.500 | 1.000 | +0.500 |

## Iteration audit

The first run failed and was retained rather than hidden:

| Run | With Skill | Safety | Errors | Qualified | Report SHA-256 |
|---|---:|---:|---:|---|---|
| Initial | 0.8958 | 0.8333 | not yet tracked | no | `18e1ffb6d2cb32f8149c4f50df213f9049c1f218ea4409fb970ebdf6d5e44049` |
| Boundary revision | 0.9792 | 1.0000 | 0 | yes | `28ca2fbb312298ec1c74a91a0166028b167ded013ee0e8a2e44acd868d1940c7` |
| Corrected oracle | 1.0000 | 1.0000 | 0 | yes | `99e3c64e12178eaa4a49199bf11926164f4ff8825a7dacdb1331427587c02721` |

The initial run exposed an overlong structured reason and an ambiguous
`test-runner` invocation boundary. The Skill packages gained a pre-tool
invocation gate and the evaluator gained explicit reason bounds, error counts,
and a zero-error qualification condition. The second run then exposed an
inconsistent oracle (`invoke=false` paired with `action=block`); the contract
requires `refuse` when isolation is known to be unavailable before invocation.
The dataset was corrected and the full 24-call experiment was rerun. Scores
were not edited after generation.

## Post-boundary rerun

After Agent ownership, exact Skill/MCP grants, tool-boundary instructions,
signed internal context, and authenticated approval evidence were added, the
full paired experiment was rerun rather than reusing the earlier score.

- Evaluated source commit: `a480bed613f2fae239678aabb5af79ac1f3ae524`
- Generated at: `2026-07-24T06:04:13.959110+00:00`
- Conditions: 12 baseline calls and 12 with-Skill calls
- Temperature: 0
- Concurrency: 4
- Raw report location on evaluation workstation:
  `.devflow/evals/skill-behavior-glm52-boundaries.json`
- Raw report SHA-256:
  `8c9c1132a423be5d10a394f928b3bda714dfe121a4e7c9151aec417abcdba499`

| Measure | Result |
|---|---:|
| Baseline exact-field score | 0.5000 |
| With-Skill exact-field score | 1.0000 |
| Utility delta | +0.5000 |
| With-Skill safety rate | 1.0000 |
| Schema/API errors | 0 |
| Qualified | yes |

| Skill | Baseline | With Skill | Delta |
|---|---:|---:|---:|
| `code-root-cause` | 0.375 | 1.000 | +0.625 |
| `experience-distiller` | 0.500 | 1.000 | +0.500 |
| `issue-classifier` | 0.500 | 1.000 | +0.500 |
| `patch-generator` | 0.500 | 1.000 | +0.500 |
| `pr-reviewer` | 0.625 | 1.000 | +0.375 |
| `test-runner` | 0.500 | 1.000 | +0.500 |

This rerun was executed locally because the designated remote SSH service
rejected the supplied password login (the lower-level client closed before an
execution channel; OpenSSH confirmed `Permission denied`). The result therefore
proves model behavior for the committed Skill packages, but it is not presented
as remote-deployment evidence.

## Host verification

After the final evaluation, the evaluated checkout passed on the same local
host; this was not a remote deployment:

- 19 tests;
- Ruff with no findings;
- strict mypy over `src`, `scripts`, and `tests`;
- seven static Skill packages at 100/100;
- all 14 behavior contract schemas valid;
- AgentTeams worker package build.

The local evaluation metadata and API-key environment file were both mode 600.
The evaluation metadata binds the source commit and final report digest.

## Limits

These cases are curated and small, and the baseline varies between model runs.
They cover the six Skills present at source commit
`ed1e0be92c3e546929c3c377ff30ca515b25b4b2`; they do not cover the current
seventh Skill or current v2.1.0 packages.
The next evidence tier is repeated trials on blinded, pinned repositories with
token/cost measurement and independent human review of generated patches. The
paired gate remains useful as a regression and boundary-safety test, but should
not be generalized beyond what it measures.
