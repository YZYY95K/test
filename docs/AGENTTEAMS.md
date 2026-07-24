# AgentTeams mapping

DevFlow targets AgentTeams `agentteams.io/v1beta1` and uses a native `Team`
instead of pretending that an internal Python event bus is the production
multi-agent transport.

| AgentTeams concept | DevFlow role |
|---|---|
| Manager | Receives the human request and selects `devflow-swe` |
| Team Leader | TeamLeader: decomposes, tracks the DAG, handles conflicts |
| Worker | Triage, Locator, Coder, Tester, Reviewer |
| Team Room | Visible assignment/result/status collaboration |
| Worker Room | Focused task context and feedback |
| shared/projects | canonical issue plan and lifecycle |
| shared/tasks | located context, patch, tests, review evidence |
| shared/knowledge | distilled post-merge experience |
| Higress consumer credentials | scoped GitHub/LLM/CI access without raw keys |
| Human Team Admin | T4/T5 approval, intervention, rollback authorization |

## Deployment

1. Install AgentTeams following upstream instructions.
2. Build the shared custom Worker package:

   ```bash
   python scripts/build_agentteams_package.py
   ```

3. Copy `dist/devflow-worker.zip` to `/tmp/devflow-worker.zip` inside the
   Manager/controller environment.
4. Confirm the configured model ID and GitHub MCP server.
5. Apply `agentteams/team.yaml`.
6. Wait until `agt get teams devflow-swe -o json` reports `phase: Active`.
7. In Element, give the Manager a repository issue and request a DevFlow run.

The manifest references built-in `github-operations` only for repository-read
and PR-review roles. Coder receives no Git or MCP capability and emits only a
typed patch artifact. Custom DevFlow skills arrive through the shared package.
Worker-specific `agents` instructions state which Skill each Worker owns,
preventing responsibility drift.

AgentTeams supplies the collaboration rooms and delivery lifecycle; DevFlow
does not treat a room message as trusted authorization. Every delivered domain
artifact is wrapped in a digest-bound `HandoffEnvelope`, and the receiving
Worker verifies its consumer and Skill ownership before execution. MCP access
then requires the same Agent + Skill pair. See the
[responsibility matrix and MCP trust model](BOUNDARIES_AND_MCP.md).

The bundled MCP URL is the upstream local-install gateway endpoint. Replace it
when the AgentTeams gateway uses another hostname, port, or HTTPS origin.

## Evidence expected from a live run

- Matrix messages showing assignment and result boundaries.
- Project/task state from AgentTeams tools.
- shared task artifacts for localization, patch, tests, and review.
- DevFlow JSON report and OpenTelemetry trace ID.
- PR URL or an explicit dry-run result.
- For T4/T5, the pause and recorded human approval.
