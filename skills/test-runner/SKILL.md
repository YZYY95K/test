---
name: test-runner
description: Apply a candidate only in isolation, execute tests, and compare against a trusted baseline. Use when a validated Patch is ready for verification before security review or PR creation.
---

# Test Runner

Produce reproducible `TestRunResult` evidence; never approve a patch.

## Invocation gate

Evaluate `refuse_when` before any tool use. A known refusal means `invoke=false`
and routing to the contract's declared failure or boundary consumer; do not
enter the procedure. Failure rules apply only when a precondition becomes false
after a valid invocation starts. In particular, isolation known to be
unavailable is a refusal; isolation lost after startup is `ISOLATION_UNAVAILABLE`.

## Procedure

1. Validate the candidate digest, repository revision, tier, and test policy.
2. Establish the baseline from the same trusted revision.
3. Create an isolated disposable checkout and apply the candidate there only.
4. Run focused tests for T1/T2 and the full suite for T3+; enforce resource and
   network policy.
5. Compare results with baseline and label retries or flaky evidence.
6. Run `python scripts/validate.py output <artifact.json>`. Emit `test.passed`
   only for zero failures, zero errors, and no regression; otherwise emit
   `test.failed`.

## Decision rules

- Timeout, missing baseline, malformed output, or unavailable isolation is
  `error`, never `passed`.
- Retry infrastructure failure once. Cap isolated flaky reruns at two.
- Route deterministic code failures to CoderAgent with exact failing evidence.

## Boundaries

Do not alter the canonical checkout, source, tests, acceptance criteria, or
review status. Never interpolate untrusted input into a shell command.

Read [the contract](references/contract.yaml) for suite policy and failure
routing. Read [examples](references/examples.md) to calibrate pass, error, and
boundary outcomes.
