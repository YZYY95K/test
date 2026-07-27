# Examples

## Success

A valid Locator envelope has `artifact.type=SkillInvocation`, an integrity
checked inline payload, and one of these assignment shapes:

```json
{"repository":{"owner":"example","repo":"repo"},"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","capability":"<short-lived-broker-capability>","path":"README.md"}
```

```json
{"repository":{"owner":"example","repo":"repo"},"revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","capability":"<short-lived-broker-capability>","paths":["README.md","src/app.py"]}
```

Pass the unchanged envelope file plus the proposed MCP arguments to the
authorizer. It permits only an exact assigned path and includes the full
envelope digest, task ID, capability digest, trace ID, and idempotency key in
the scope digest. Pass the same task ID, capability, and revision to MCP. The
Broker still performs the authoritative parameter and expiry check.

## Failure

A missing envelope returns `HANDOFF_REQUIRED`. A stale envelope returns
`HANDOFF_EXPIRED`. A branch name returns `REVISION_REQUIRED`. A missing grant
returns `MCP_CAPABILITY_REQUIRED`. A changed inline payload returns
`HANDOFF_DIGEST_MISMATCH`. Do not call MCP.

## Boundary

A request to merge, push files, create a branch, dispatch a workflow, or
enumerate notifications returns `MCP_TOOL_DENIED`. A syntactically valid but
unassigned repository or path returns `MCP_SCOPE_MISMATCH`, even if the MCP
server advertises or accepts it.
