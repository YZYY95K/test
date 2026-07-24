# GLM-5.2 repository-grounded boundary benchmark evidence

Run completed: 2026-07-24T08:30:10.311923Z

Model: `glm-5.2`

Cases: 24 across 3 fixed repository revisions

Raw report: `repository-boundary-glm52-v2.json`
Raw report SHA-256:
`4b34379f9b95d1757a25e4f0961ed954dfe0153a8073c583872bcca458f245ce`

## Result

| Metric | Measured value |
|---|---:|
| Exact five-field task success | 24/24 (100%) |
| Mean field score | 1.000 |
| Safety cases | 6/6 (100%) |
| Expected human intervention | 3/24 (12.5%) |
| Actual human intervention | 3/24 (12.5%) |
| Provider errors | 0 |
| Latency p50 / p95 | 7,563 / 42,063 ms |
| Prompt / completion / total tokens | 193,217 / 18,688 / 211,905 |
| Monetary cost | Not calculated: no explicit official GLM-5.2 per-token rate was supplied |

| Repository | Exact success | Safety | Total tokens |
|---|---:|---:|---:|
| Requests 2.32.3 | 8/8 | 2/2 | 69,218 |
| Flask 3.1.1 | 8/8 | 2/2 | 71,842 |
| Pydantic 2.11.7 | 8/8 | 2/2 | 70,845 |

Exact success requires all of `skill`, `invoke`, `action`, `next_event`, and
`consumer` to match the frozen oracle. Safety cases are the three adversarial
boundary tasks and three T4 human-gate tasks.

## Failed first run retained

The first run completed all 24 calls but produced 24 schema validation errors:
the model placed a free-form execution description in the enum-only `action`
field. Its reported task and safety scores were therefore zero. The runner was
changed to state every enum and exact-copy rule explicitly, retain token usage
on parse failures, and measure request latency after semaphore acquisition.
The complete fixed suite was then rerun; no cases were removed or changed.

## Claim boundary

This is a repository-grounded collaboration and safety benchmark. It reads
real files at fixed, verified revisions, but it does not ask the model to create
and execute full issue patches. It must not be presented as a SWE-bench
resolution score. Standardized patch-resolution evaluation remains dependent
on a Docker-capable host.
