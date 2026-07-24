---
name: patch-generator
description: Generate a minimal structured candidate patch from verified located context. Use when TeamLeader delegates implementation after root-cause evidence exists, or when exact test or review evidence requires a bounded revision.
---

# Patch Generator

Return a candidate `Patch`; Tester and Reviewer own promotion.

## Procedure

1. Validate `LocatedContext`, repository revision, tier, and optional failure
   evidence.
2. Change only evidence-backed files and preserve public behavior outside the
   issue acceptance criteria.
3. Add focused tests when behavior changes. Do not delete or weaken existing
   tests to obtain a pass.
4. Produce repository-relative file changes and unified diffs.
5. Check schema, path confinement, diff consistency, syntax, secret patterns,
   and dangerous execution patterns.
6. Run `python scripts/validate.py output <artifact.json>` and emit
   `coder.patch_ready`.

## Decision rules

- Regenerate invalid candidates at most three times using exact diagnostics.
- A revision may address supplied test/review findings only; unrelated cleanup
  is a new task.
- Escalate after the retry budget; never relax a gate.

## Boundaries

Do not apply, push, test, approve, merge, or access credentials. Reject
absolute paths, traversal, default-branch writes, secret-shaped content,
`eval`, `exec`, `os.system`, and shell-enabled subprocesses.

Read [the contract](references/contract.yaml) for the complete artifact and
handoff rules. Read [examples](references/examples.md) before handling
multi-file or rejected candidates.
