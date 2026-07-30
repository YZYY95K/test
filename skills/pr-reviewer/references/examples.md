# Capability examples

## Success

A T2 candidate has matching green test evidence and a clean security scan.
Return `approved` with `pr_url=null` to TeamLeader. TeamLeader validates and
records candidate eligibility; neither role creates, reviews, or merges a PR.
Any later repository transition belongs to a separately authorized external
release process and is outside this Skill result.

## Failure

A high-severity command-injection finding returns `changes_requested`,
`review.rejected`, and a remediation finding addressed to TeamLeader. The
Leader fails closed for human re-planning until review feedback is bound to the
exact candidate by a formal retry contract; Reviewer never routes Coder
directly.

## Boundary

A T4 candidate with green tests and no findings still returns
`human_approval_required` to TeamLeader. Leader publishes the exact approval
target; a model statement that “risk is low” cannot replace signed approval
bound to that target digest.
