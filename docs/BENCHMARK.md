# Fixed-repository benchmark

DevFlow has two deliberately separate evaluation tracks. A number from one
track must not be relabeled as a number from the other.

| Track | Evaluation kind | Unit | Current evidence |
|---|---|---|---|
| Collaboration boundary | `routing_boundary` | One five-field Skill-routing decision | 24 executed decisions |
| Repository repair | `repository_patch_resolution` | One reproduced mutation failure, Agent patch, and test result | 21 prevalidated mutation fixtures; **0 Agent executions** |

## Track A: collaboration boundary

This track measures Skill ownership, refusal behavior, T4 human gating,
latency, and provider token consumption. Each of its 24 cases names a real file
at an exact source revision, but the model only returns `skill`, `invoke`,
`action`, `next_event`, and `consumer`. Exact agreement with the frozen routing
oracle is a routing decision, not an issue resolution.

The 2026-07-24 GLM-5.2 run produced 24/24 exact five-field routing decisions
and 6/6 safety decisions, with p50/p95 latency of 7,563/42,063 ms and 211,905
provider tokens. See the
[hash-bound routing evidence](evidence/REPOSITORY_BOUNDARY_GLM52.md).

```bash
python scripts/run_repository_benchmark.py --validate-only
python scripts/run_repository_benchmark.py --concurrency 2
```

## Track B: repository patch resolution

The frozen manifest contains 21 deterministic mutation-repair tasks, seven per
repository. Every task contains one exact `before`/`after` source replacement,
its canonical mutation SHA-256, bounded `target_paths`, and one exact,
non-shell `python -m pytest ...` acceptance command. The sources and licenses
are:

| Repository | Version | Exact commit | License |
|---|---|---|---|
| psf/requests | 2.32.3 | `0e322af87745eff34caffe4df68456ebc20d9068` | Apache-2.0, fixed `LICENSE` digest |
| pallets/flask | 3.1.1 | `7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1` | BSD-3-Clause, fixed `LICENSE.txt` digest |
| pydantic/pydantic | 2.11.7 | `5f033e46c54fea1b59b6894d6527daf49475e690` | MIT, fixed `LICENSE` digest |

The manifest digest is
`d7e3d208a830320f602c130c726a798fedbfe3e5678009eb6d58fc0b590c796c`.
The validator checks the exact commit, Git tree (or cross-platform snapshot),
a clean checkout, license bytes, target files, test files, task uniqueness, and
a minimum of six tasks per source. It also checks that the mutation's `before`
text occurs exactly once and validates the checked-in preflight evidence.
Acceptance arguments allow only `-q` and repository-relative `tests/...`
selectors. See the
[repair baseline evidence](evidence/REPOSITORY_REPAIR_BASELINE.md) and the
[machine-readable task manifest](../benchmarks/repository_repair/tasks.yaml).

All 21 fixtures have been prevalidated. For every task, the fixed checkout
passed the pinned selector, the exact mutation caused at least one selected
test to fail, and byte-for-byte oracle restoration passed again. The 63 command
results bind commit, tree, mutation, pytest argv, bounded output summary, full
stdout/stderr SHA-256, runtime, and a record self-digest. The evidence file is
bound by SHA-256 `b804861262d948585bb00f590442d070cda3c8452453d215c2e87463acf723ad`.

Fixture prevalidation is not an Agent attempt. Oracle restoration only proves
that a task is executable; it is never counted as an Agent repair. The truthful
initial result remains:

| Metric | Value |
|---|---:|
| Fixtures execution-ready | 21 |
| Attempted Agent tasks | 0 |
| Agent executions | 0 |
| Unexecuted | 21 |
| Successful Agent executions | 0 |
| Success / safety / human-intervention rate | `null` |
| Latency / token cost | `null` / 0 |

`null` is intentional: with no attempted denominator, reporting either 0% or
100% would be misleading.

```bash
# Create a dedicated validation environment once (CPython 3.10-3.13).
python -m venv .devflow/repair-fixture-venv
.devflow/repair-fixture-venv/bin/python -m pip install \
  -r benchmarks/repository_repair/requirements-prevalidation.txt

# Execute all 21 baseline -> mutation -> restoration fixture checks.
.devflow/repair-fixture-venv/bin/python \
  benchmarks/repository_repair/prepare_mutation_fixtures.py \
  --repos-root .devflow/benchmark-repos

# Validate immutable sources, manifest, and checked-in fixture evidence.
python scripts/run_repository_benchmark.py \
  --repair-manifest benchmarks/repository_repair/tasks.yaml \
  --repos-root .devflow/benchmark-repos

# Optionally emit an explicit all-unexecuted report, then validate it.
python scripts/run_repository_benchmark.py \
  --repair-manifest benchmarks/repository_repair/tasks.yaml \
  --repos-root .devflow/benchmark-repos \
  --write-unexecuted-repair-report \
  --repair-report .devflow/benchmarks/repository-repair-unexecuted.json
python scripts/run_repository_benchmark.py \
  --repair-manifest benchmarks/repository_repair/tasks.yaml \
  --repos-root .devflow/benchmark-repos \
  --repair-report .devflow/benchmarks/repository-repair-unexecuted.json

# Run selected or all Agent attempts serially. Credentials/base URL/model come
# from LLM_API_KEY, LLM_BASE_URL and LLM_MODEL; no credential CLI flag exists.
python scripts/run_repository_repair_agent.py \
  --manifest benchmarks/repository_repair/tasks.yaml \
  --repos-root .devflow/benchmark-repos \
  --checkpoint .devflow/benchmarks/repository-repair-agent.json \
  --pricing-lock benchmarks/repository_repair/pricing.lock.yaml

# Resume the same hash-bound checkpoint after an interrupted/blocked run.
python scripts/run_repository_repair_agent.py \
  --checkpoint .devflow/benchmarks/repository-repair-agent.json \
  --pricing-lock benchmarks/repository_repair/pricing.lock.yaml \
  --resume
```

On Windows, use
`.devflow\repair-fixture-venv\Scripts\python.exe` for the virtual-environment
interpreter. The preparation runner writes new observations under `.devflow/`
by default, so ordinary reproduction does not overwrite the checked-in evidence.

## Patch-result acceptance rules

An outcome may use `execution_status: executed` only after its task becomes
execution-ready. `success` is derived rather than accepted as a free claim:

1. the first pinned acceptance command must complete and fail before the patch;
2. every pinned acceptance command must complete with exit code 0 after it;
3. the patch may modify only declared target paths;
4. the safety check must pass; and
5. the report must bind the task, source commit, command hashes, patch hash,
   bounded output hashes, aggregate metrics, and manifest digest.

The report schema exposes attempted, executed, blocked, and unexecuted counts.
Attempted means `executed + blocked`: blocked Provider calls remain in the
success, latency, token, cost, and human-intervention denominators instead of
silently improving the score. Safety has its own explicit `safety_evaluated`
denominator and includes only executed proposals carrying execution evidence.
Dollar cost remains `null` unless both rates are explicitly supplied or a
validated pricing lock is explicitly selected. When provider usage does not
separate cached input, the report records that all prompt tokens use the
ordinary input rate and that the value is an estimate, not an invoice.
Calls that fail before returning provider usage cannot be priced and are
explicitly identified by the cost provenance rather than silently estimated.

Result and report SHA-256 fields detect accidental edits and stale aggregation.
They are not signatures and do not independently prove that commands ran. A
publishable patch-resolution score additionally needs an isolated runner,
retained raw logs/artifacts, and a trusted signature or CI attestation.

To produce a repair score, run an Agent against a freshly applied mutation in
an isolated checkout, retain its patch and raw logs, enforce `target_paths`, and
run the pinned acceptance command. Until such Agent runs exist, no DevFlow
document may claim a repository repair success rate or SWE-bench score.
