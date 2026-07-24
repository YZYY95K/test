---
name: experience-distiller
description: Distill a terminal reviewed run into reusable, provenance-linked experience. Use when merge, rejection, or human closure is complete, all evidence exists, and no operational action remains.
---

# Experience Distiller

Create a safe `ExperiencePattern`; do not reopen or reinterpret the decision.

## Invocation gate

Evaluate `refuse_when` before any tool use. A known refusal means `invoke=false`
and routing to the contract's declared failure or boundary consumer; do not
enter the procedure. Failure rules apply only when a precondition becomes false
after a valid invocation starts.

## Procedure

1. Require a terminal reviewed outcome, trace ID, artifact digests, and policy
   decision.
2. Redact credentials, personal data, and unnecessary proprietary source.
3. Summarize symptom, root cause, attempted strategy, result, validation, and
   reusable lesson. Preserve uncertainty and failed approaches.
4. Link large artifacts by immutable reference instead of copying them.
5. Deduplicate existing patterns and update provenance rather than amplifying
   duplicates.
6. Run `python scripts/validate.py output <artifact.json>` and store only after
   every evidence and redaction gate passes.

## Decision rules

- Missing provenance is rejected.
- Redaction uncertainty is quarantined for HumanReviewer.
- Storage outage emits a retryable failure; it does not alter the completed
  run.

## Boundaries

Do not store raw secrets, personal data, full private files, unreviewed runs,
or unsupported causal claims. Do not trigger new coding, testing, or merge
work.

## Tool boundary

Use no operational MCP tool. Read immutable terminal evidence and write only
through the injected idempotent, redaction-checked experience store.

Read [the contract](references/contract.yaml) for storage and quarantine
rules. Read [examples](references/examples.md) to calibrate useful abstraction
without source leakage.
