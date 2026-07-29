# Capability examples

## Success

A verified calculator fix with clean regression evidence, an approved review,
and a digest-valid `VerifiedTerminalReceipt` becomes a compact pattern. It
describes the incorrect operator, focused correction, and validation delta
without copying the source file.

## Failure

A review summary without its terminal receipt, or a receipt bound to a failed
test or rejected review, produces `PROVENANCE_INCOMPLETE` or
`NON_TERMINAL_EVIDENCE`; nothing is written to the trusted experience store.

## Boundary

An otherwise useful artifact containing an email address and token-shaped text
is quarantined as `REDACTION_UNCERTAIN`. The Skill neither stores it nor
silently drops provenance.
