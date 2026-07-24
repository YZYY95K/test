# Capability examples

## Success

The trusted baseline fails one calculator test. The isolated candidate fixes
that test, adds no failures, records suite identity and duration, and emits
`test.passed` with the candidate digest.

## Failure

The candidate introduces one new failure. Emit `TEST_REGRESSION` and
`test.failed` with the exact case, traceback reference, and baseline delta.

## Boundary

If disposable isolation cannot be created, emit `ISOLATION_UNAVAILABLE`.
Never run the candidate in the canonical checkout and never infer a pass from
the patch text.
