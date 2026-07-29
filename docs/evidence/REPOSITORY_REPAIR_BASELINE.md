# Fixed-repository repair baseline evidence

Recorded: 2026-07-28

Evaluation kind: `repository_patch_resolution`

Manifest: `benchmarks/repository_repair/tasks.yaml`

Model price provenance: `benchmarks/repository_repair/pricing.lock.yaml`. The
lock records the official Z.AI `glm-5.2` list price retrieved on 2026-07-28 and
the SHA-256 of the source page. Any reported USD value is an estimated
list-price cost. If provider usage does not separate cached input tokens, all
prompt tokens use the ordinary input rate; the result must not be presented as
an invoice. Failed calls that return no provider usage are not priced, and that
limitation is retained in report cost provenance.

Canonical manifest SHA-256:
`d7e3d208a830320f602c130c726a798fedbfe3e5678009eb6d58fc0b590c796c`

## Source and task inventory

| Source | Commit | Git tree | Tasks | License evidence |
|---|---|---|---:|---|
| psf/requests 2.32.3 | `0e322af87745eff34caffe4df68456ebc20d9068` | `9474485f84c7244930abc1b8023f847486572091` | 7 | Apache-2.0; `LICENSE` SHA-256 `88046bf22d5b4f4b8cc85079ae6aae5424a3a1999db952ed152828ff325b2c6d` |
| pallets/flask 3.1.1 | `7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1` | `29bd3ef8420dce3b374185783edd3e5dcb9a8407` | 7 | BSD-3-Clause; `LICENSE.txt` SHA-256 `4631ec0db5fd90a547e336817264c6798214338146f8ac94b4a57f96ee8c9ec4` |
| pydantic/pydantic 2.11.7 | `5f033e46c54fea1b59b6894d6527daf49475e690` | `4200a6ef6753b863d35645c487449612c651b581` | 7 | MIT; `LICENSE` SHA-256 `fc67bae6467548be3bf034f79012cb3cdb2cc548c18969e305717cf8074bf8e7` |

The validator observed all three clean local checkouts at the exact commit and
tree, verified each license digest, and found every declared source and test
path. The manifest contains 21 unique deterministic mutations, seven per
repository. Every mutation has exact `before` and `after` text, a canonical
mutation digest, one bounded target path, and a pinned pytest selector.

## Mutation fixture prevalidation

Prevalidation evidence:
`benchmarks/repository_repair/evidence/prevalidation.json`

Raw evidence SHA-256:
`b804861262d948585bb00f590442d070cda3c8452453d215c2e87463acf723ad`

Evidence self-digest:
`555a1cdd8a859b39a93bcede7e382adce202051aef979032033a134e3057e9b4`

| Repository | Fixtures | Fixed source passed | Mutation failed selector | Exact restoration passed |
|---|---:|---:|---:|---:|
| psf/requests | 7 | 7 | 7 | 7 |
| pallets/flask | 7 | 7 | 7 | 7 |
| pydantic/pydantic | 7 | 7 | 7 | 7 |
| **Total** | **21** | **21** | **21** | **21** |

The runner executed 63 pytest commands in 91,034 ms of measured child-process
time. Every mutation produced a pytest failed-test summary, not merely a
timeout or collection error. Each record binds the repository commit and tree,
mutation SHA-256, changed path, declared command SHA-256, runtime, exit code,
bounded output summary, complete stdout/stderr SHA-256, and record self-digest.
All three checkouts were clean again after byte-for-byte oracle restoration.

## Honest execution status

| Status | Count |
|---|---:|
| Execution-ready mutation fixtures | 21 |
| Attempted Agent tasks (`executed + blocked`) | 0 |
| Agent executions | 0 |
| Blocked after attempted execution | 0 |
| Unexecuted | 21 |
| Successful Agent executions | 0 |

Success rate, safety rate, human-intervention rate, latency percentiles, and USD
cost are `null` because there is no attempted-task denominator; prompt and
completion tokens are zero. All tasks are
`execution_ready: true` because their deterministic fixtures passed preflight.
The oracle restoration is fixture validation, not an Agent-generated repair,
and is excluded from every repair-rate denominator.

## Reproduction and negative checks

The deterministic test suite validates the following properties:

- unknown fields, duplicate task IDs, shell commands, and non-pytest acceptance
  commands are rejected;
- an unexecuted or blocked task cannot be successful or carry execution
  evidence;
- an executed Agent task requires a pre-patch failure and post-patch passing
  evidence;
- baseline and acceptance command hashes must match the manifest;
- task/result source bindings, changed-path boundaries, summaries, and
  manifest/result/report digests are checked;
- mutation preflight evidence must cover all 21 tasks and prove pass/fail/pass
  while binding exact source, command, output, and mutation hashes; and
- an all-unexecuted template has no invented denominator or success rate.

Blocked attempts are not unexecuted work. A later Agent report derives
`attempted = executed + blocked`; success, latency, token, cost, and human
intervention aggregate over that attempted set. Safety reports its separate
evidence-bearing `safety_evaluated` denominator.

Reproduction commands and the limits of the unkeyed SHA-256 integrity fields
are documented in `docs/BENCHMARK.md`.
