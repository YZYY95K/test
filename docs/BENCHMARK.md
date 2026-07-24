# Repository-grounded collaboration boundary benchmark

This benchmark measures routing, Skill ownership, refusal behavior, human-gate
behavior, latency, and provider token consumption. It does **not** claim
SWE-bench issue-resolution performance because the supplied server cannot run
the Docker-based SWE-bench harness.

## Fixed inputs

| Repository | Version | Commit | Cases |
|---|---|---|---:|
| psf/requests | 2.32.3 | `0e322af87745eff34caffe4df68456ebc20d9068` | 8 |
| pallets/flask | 3.1.1 | `7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1` | 8 |
| pydantic/pydantic | 2.11.7 | `5f033e46c54fea1b59b6894d6527daf49475e690` | 8 |

Each case names a real file at the fixed revision. The validator checks the
local clone's commit and Git tree. A cross-platform server snapshot is accepted
only when its provenance marker matches and the sorted path+content SHA-256
matches the manifest. Repository text is wrapped as untrusted evidence.

The 24 cases cover every packaged Skill in a positive route, plus three
adversarial boundary cases and three T4 approval-gate cases. Exact success
requires matching Skill, invocation, action, next event, and consumer.

## Metrics

- exact task success rate and mean five-field score;
- safety rate over adversarial and T4 cases;
- expected and actual human-intervention rate;
- provider errors and p50/p95 wall-clock latency;
- provider-reported input, output, and total tokens.

Currency cost is calculated only when explicit official input/output rates are
passed to the runner. A subscription quota or an unpublished model rate is not
converted into a fabricated dollar value.

```bash
python scripts/run_repository_benchmark.py --validate-only
python scripts/run_repository_benchmark.py --concurrency 2
```

For full patch-resolution claims, use the official SWE-bench harness on the
same fixed instance list once a Docker host is available; that harness applies
generated patches and runs repository tests in standardized containers.

## Latest measured run

The 2026-07-24 GLM-5.2 run achieved 24/24 exact decisions and 6/6 safety
decisions, with p50/p95 latency of 7,563/42,063 ms and 211,905 total provider
tokens. See the [hash-bound result summary](evidence/REPOSITORY_BOUNDARY_GLM52.md)
and its hash-bound raw JSON report.
