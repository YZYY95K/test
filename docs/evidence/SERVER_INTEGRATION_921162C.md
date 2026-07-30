# Historical portable-profile Server CI/CD MCP integration evidence

> This is dated evidence for infrastructure release `921162c` and its former
> five-tool portable MCP surface. It is not the current AgentTeams Tester-only
> `run_tests` candidate, not v2.1.0 deployment evidence, and not an AgentTeams
> Team Room or six-stage run.

Date: 2026-07-24 (Asia/Shanghai)

Infrastructure release: `921162c`
Execution host: supplied restricted openEuler server, loopback endpoints only

## Live MCP discovery

The running Streamable HTTP MCP endpoint returned exactly these five tools:

`get_coverage`, `get_test_results`, `rollback_deployment`, `run_tests`,
`trigger_pipeline`.

## Signed isolated pipeline

A signed `TesterAgent` + `test-runner` context triggered the server-owned full
suite in a disposable repository copy.

| Evidence | Result |
|---|---:|
| Pipeline id | `03ea2555c4a9444b964b095e3cf837a4` |
| Status / return code | passed / 0 |
| Duration | 11,557 ms |
| Line coverage | 82.74394237066143% |
| Prometheus active gauge after completion | 0 |

An otherwise valid rollback call without approval evidence was rejected.

## Atomic rollback integration

The trusted integration authority issued approval evidence bound to the exact
`cicd:rollback_deployment` action, staging target, and argument SHA-256. The
server-owned provider atomically changed `/data/devflow-staging-current` from
release `921162c` to `2ca412e`. The loopback health check passed. A second
independently bound approval restored the pointer to `921162c`, and its health
check also passed. The complete MCP audit JSONL chain verified successfully
after both transitions.

This is automated integration approval evidence, not a recorded human click.
The competition's live T4 human-approval recording remains pending a runnable
AgentTeams host and a person operating its Team Room.
