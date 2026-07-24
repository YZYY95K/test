# Capability examples

## Success

Located evidence for `calculator.py` produces one modify change replacing
`return a - b` with `return a + b`, a focused test, a revision binding, passed
static validation, and a SHA-256 candidate digest.

## Failure

A third schema-invalid generation emits `CANDIDATE_INVALID` and
`coder.exhausted` with validator diagnostics. It does not emit
`coder.patch_ready`.

## Boundary

A requested cleanup of unrelated `README.md` is excluded because it is outside
the located blast radius. A path such as `../../secrets.env` rejects the whole
candidate and records `boundary.violation`.
