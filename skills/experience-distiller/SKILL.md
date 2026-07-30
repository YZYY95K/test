---
name: experience-distiller
description: Distill a clean, review-approved run into reusable provenance-linked experience. Use when TeamLeader supplies a digest-valid VerifiedTerminalReceipt binding the patch, regression-free test result, review decision, repository revision, and run.
---

# Experience Distiller

Create a safe `ExperiencePattern`; do not reopen or reinterpret the decision.

## Invocation gate

Evaluate `refuse_when` before any tool use. A known refusal means `invoke=false`
and routing to the contract's declared failure or boundary consumer; do not
enter the procedure. Failure rules apply only when a precondition becomes false
after a valid invocation starts.

## Procedure

1. Validate `VerifiedTerminalReceipt`, including its own digest and exact links
   to the issue, repository revision, candidate, clean test result, and approved
   review. Require the bound test result to carry a verified immutable-test
   attestation; a merely green result is not terminal evidence. Reject failed
   tests, requested changes, or human-pending decisions. A human-approved T4/T5
   bundle must additionally bind the exact consumed approval evidence; an
   autonomous bundle must contain no human-approval claim.
2. Redact credentials, personal data, and unnecessary proprietary source.
3. Summarize symptom, root cause, attempted strategy, result, validation, and
   reusable lesson. Preserve uncertainty and failed approaches.
4. Link large artifacts by immutable reference instead of copying them.
5. Deduplicate existing patterns and update provenance rather than amplifying
   duplicates.
6. Store idempotently only after every evidence and redaction gate passes.
7. Run `python scripts/validate.py output <artifact.json> <source.json>` after
   durable store acknowledgement; success requires `stored=true` and exact
   provenance binding to the source bundle.

## Decision rules

- Missing, stale, mismatched, tampered, or integrity-unattested terminal
  provenance is rejected.
- A failed/regressed test result or non-approved review is never reusable
  experience; quarantine it outside the trusted retrieval index.
- Redaction uncertainty is quarantined for HumanReviewer.
- Storage outage emits a retryable failure; it does not alter the completed
  run.

## Failure output

On storage, provenance, or redaction failure, emit a `failed` HandoffEnvelope
containing `SkillFailure` 1.0 to TeamLeader only and submit the task as
`FAILED`. Bind `source_artifact_sha256` to the exact `VerifiedRunBundle` and
match the declared code, retry budget, exhaustion flag, and event. Never emit
`ExperiencePattern` with `stored=false` as a successful result; TeamLeader
owns any human escalation.

## Boundaries

Do not store raw secrets, personal data, full private files, failed runs,
rejected reviews, human-pending work, or unsupported causal claims. Do not
trigger new coding, testing, or merge work.

## Tool boundary

Use no operational MCP tool. Read immutable terminal evidence and write only
through the injected idempotent, redaction-checked experience store.

Read [the contract](references/contract.yaml) for storage and quarantine
rules. Read [examples](references/examples.md) to calibrate useful abstraction
without source leakage.
