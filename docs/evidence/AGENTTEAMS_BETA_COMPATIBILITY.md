# AgentTeams v1.2.0-beta.1 compatibility asset

DevFlow deploys against the official AgentTeams `v1.2.0-beta.1` release. During
the 2026-07-27 server integration, six beta compatibility gaps blocked a real
Team reconciliation. They are captured in
`scripts/patch_agentteams_beta.sh` and
`scripts/patch_openclaw_matrix_bots.sh` so the live repairs are reproducible
after a Helm upgrade or a fresh cluster installation.

## Covered repairs

| Gap | Fail-closed repair |
| --- | --- |
| The Team CRD rejects `spec.leader.runtime` | Copy the installed worker `runtime` schema into every served Team version. An incompatible existing schema is rejected, not overwritten. |
| Higress watches `TLSRoute` `v1alpha2`, but that CRD version is not served | Locate `v1alpha2` by name and set only its `served` field to `true`. |
| Higress cannot watch experimental Gateway API resources | Grant its detected ServiceAccount only `get`, `list`, and `watch` on `xlistenersets` and `xbackendtrafficpolicies`. |
| The controller image exposes `hiclaw-controller`, while the beta chart uses another entrypoint | Replace the controller command with `/usr/local/bin/hiclaw-controller` after verifying the binary is executable. |
| `AGENTTEAMS_STORAGE_PREFIX` uses an `mc` alias that was never initialized | Derive the alias from the existing prefix and configure it from existing Secret-backed environment variables before starting the controller. |
| OpenClaw ignores or incompletely dispatches messages authored by another Agent | For one explicitly selected Team, set `channels.matrix.allowBots` to `"mentions"` and `streaming` to `"off"` in ready OpenClaw members while preserving the sender allowlists and `requireMention: true`. |

The script never contains, prints, copies, or persists a credential. The
MinIO access key and secret remain references to environment variables already
injected into the controller by the Helm release. `mc alias set` output is
discarded.

## Runbook

Use a cluster administrator identity, inspect the current context, then run:

```bash
kubectl config current-context
bash scripts/patch_agentteams_beta.sh
```

Supported overrides:

```bash
bash scripts/patch_agentteams_beta.sh \
  --namespace agentteams-system \
  --controller-deployment agentteams-hiclaw-controller \
  --higress-service-account <service-account>
```

Higress ServiceAccount discovery is automatic when exactly one controller
candidate exists. Ambiguous discovery stops without modifying the cluster and
requires the explicit override.

After the Team is reconciled and its OpenClaw Pods are Ready, enable
mention-gated Agent-to-Agent delivery with an explicit scope:

```bash
bash scripts/patch_openclaw_matrix_bots.sh \
  --namespace agentteams-system \
  --team devflow-swe
```

This second script discovers only Ready Pods carrying both the selected Team
label and `agentteams.io/runtime=openclaw`. It patches the authoritative MinIO
object and the live `$HOME/openclaw.json` without copying either file to the
operator host. The script is safe to rerun. Reapply it after a Team spec update
or controller upgrade because the beta controller's generated configuration
does not yet declare the reliable Agent-to-Agent combination.

`streaming: "off"` is a delivery requirement, not a presentation preference.
With `partial`, one Leader response becomes a short base event followed by
multiple Matrix `m.replace` edits. A receiving Agent can route only the short
base event and never execute the completed assignment. With streaming disabled,
the same Leader identity emits one complete event and the mentioned specialist
can dispatch the task deterministically.

## Safety and idempotency

The script uses `set -Eeuo pipefail`, preflights all required objects, and
builds schema patches from the objects currently installed. Empty patches are
reported as already compatible. RBAC uses declarative apply, while the
Deployment strategic merge is stable across repeated runs. Every temporary
file is removed on exit.

Post-apply checks require the controller rollout to become available and
verify the two exact Higress permissions through Kubernetes authorization.
No Team is created or mutated by this asset.

The Matrix patch refuses to run unless group and DM sender policy remain
non-empty allowlists and the wildcard room has `requireMention: true`. Before
each write it canonicalizes the full configuration with only `allowBots` and
`streaming` removed and requires byte equality, proving no other field changed.
It also uses optimistic concurrency checks for both object storage and the live
file.

This is a beta-version compatibility layer, not a permanent fork. Re-test and
remove individual patches as upstream releases close the corresponding gaps.
