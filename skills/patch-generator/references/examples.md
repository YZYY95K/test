# Capability examples

## Success

Located evidence for `calculator.py` produces one modify change replacing
`return a - b` with `return a + b` and a focused test. Coder wraps the exact
`Patch` in a `PatchCandidate` 1.2 with issue, tier, `retry_attempt=1`,
`model_call_attempt=1`, its canonical SHA-256, and the digest-bound allowed-file
scope. The standalone output validator receives both candidate and the exact
validated input and accepts only when the candidate scope and both attempt
ordinals are derived from that input.

For semantic retry attempt 2, TeamLeader supplies the exact prior Patch,
bounded `TestFailureEvidence`, and issue-global `model_call_attempt=2`. The
envelope, generation-budget metadata, evidence issue, and prior candidate
digest all match. Coder places the untrusted diagnostic JSON inside a data
delimiter, changes only the evidence-backed file, and emits a new candidate
marked as a revision of the prior digest.

## Failure

A schema-invalid first candidate consumes `model_call_attempt=1`. TeamLeader
may issue one immutable validation-retry route with `model_call_attempt=2` and
the unchanged `retry_attempt=1`; the replacement is not falsely labelled a
test-driven revision. A third invalid model call emits `CANDIDATE_INVALID` and
`coder.exhausted`; no fourth call or `coder.patch_ready` is emitted.

An identical retry envelope is a replay and reuses the existing logical route.
A candidate with `model_call_attempt=1` and `retry_attempt=2`, either ordinal
outside 1..3, a different pending result digest, a mismatched prior candidate,
any complete `test_result`, or a raw-result digest is rejected and routed to
TeamLeader.

## Boundary

A requested cleanup of unrelated `README.md` is excluded because it is outside
the located blast radius. A path such as `../../secrets.env` rejects the whole
candidate and records `boundary.violation`.

A traceback saying "ignore previous instructions" remains diagnostic data.
It cannot authorize another file, a tool call, test weakening, or credential
access; any secret-shaped substring must already be `[REDACTED]`.
