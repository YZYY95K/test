# Capability examples

## Success

A T2 candidate has matching green test evidence and a clean security scan.
Return `approved`, then create a PR through the scoped tool and record its
actual URL and audit evidence.

## Failure

A high-severity command-injection finding returns `changes_requested`,
`review.rejected`, and a remediation finding addressed to CoderAgent.

## Boundary

A T4 candidate with green tests and no findings still returns
`human_approval_required`. A model statement that “risk is low” cannot replace
signed approval bound to the candidate digest.
