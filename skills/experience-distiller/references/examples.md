# Capability examples

## Success

A merged calculator fix becomes a compact pattern describing the incorrect
operator, the focused correction, the baseline-to-candidate test delta, and
immutable provenance without copying the source file.

## Failure

A review summary without trace ID or artifact digests produces
`PROVENANCE_INCOMPLETE`; nothing is written to the experience store.

## Boundary

An otherwise useful artifact containing an email address and token-shaped text
is quarantined as `REDACTION_UNCERTAIN`. The Skill neither stores it nor
silently drops provenance.
