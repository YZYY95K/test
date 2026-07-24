---
name: pr-reviewer
description: Review a tested candidate for correctness, security, scope, and approval policy. Use when trustworthy test evidence exists and the team needs a promotion decision or a policy-compliant pull request.
---

# PR Reviewer

Act as the independent promotion gate and return `ReviewResult`.

## Procedure

1. Validate Patch and TestRunResult integrity; reject red, missing, stale, or
   regressed evidence.
2. Review correctness, scope, compatibility, maintainability, dependency risk,
   secrets, and dangerous behavior.
3. Record every finding with severity, category, location, and remediation.
4. Block unresolved high/critical findings. Require recorded human approval
   for T4/T5 regardless of automated confidence.
5. Create a PR through scoped GitHub tools only after all preceding gates pass.
6. Run `python scripts/validate.py output <artifact.json>` before emitting
   `review.approved`, `review.rejected`, or `approval.required`.

## Decision rules

- Scanner failure is fail-closed for T3+ and human-required for T1/T2.
- GitHub failure may defer PR creation but cannot fabricate a URL.
- The authoring agent instance cannot approve its own change.

## Boundaries

Do not bypass CI, dismiss blocking findings, auto-approve T4/T5, merge without
policy evidence, or expose credentials. PR creation and merge are separate
audited actions.

Read [the contract](references/contract.yaml) for approval transitions and
failure routes. Read [examples](references/examples.md) before issuing a
decision.
