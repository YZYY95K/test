#!/usr/bin/env bash
# Enable mention-gated bot-to-bot Matrix delivery for the running OpenClaw
# members of one existing AgentTeams Team and force one complete event per
# message for reliable Agent-to-Agent dispatch.
#
# No configuration content is copied to the operator host or printed. Both the
# authoritative object-storage file and the live Worker file are changed only
# after their sender allowlists and mention gate pass fail-closed checks.

set -Eeuo pipefail

readonly DEFAULT_CONTROLLER_DEPLOYMENT="agentteams-hiclaw-controller"
readonly EXPECTED_AGENT_COUNT="6"
readonly TEAM_LABEL="agentteams.io/team"
readonly RUNTIME_LABEL="agentteams.io/runtime"

NAMESPACE=""
TEAM=""
CONTROLLER_DEPLOYMENT="${AGENTTEAMS_CONTROLLER_DEPLOYMENT:-$DEFAULT_CONTROLLER_DEPLOYMENT}"
KUBECTL="${KUBECTL:-kubectl}"

usage() {
  cat <<'EOF'
Usage: scripts/patch_openclaw_matrix_bots.sh --namespace NAME --team NAME [options]

Required:
  --namespace NAME              Namespace containing the Team and Agent Pods
  --team NAME                   Existing Team resource name

Options:
  --controller-deployment NAME Controller Deployment with the configured mc alias
  --help                        Show this help

The patch sets channels.matrix.allowBots to "mentions" and streaming to "off"
for ready OpenClaw members of exactly one Team. It refuses an open group
policy, an empty sender allowlist, or a missing requireMention=true wildcard
room policy.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[openclaw-matrix-bots] %s\n' "$*" >&2
}

validate_kube_name() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] \
    || die "$label is not a valid Kubernetes name: $value"
}

cleanup() {
  if [[ -n "${WORK_DIR:-}" && -d "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR"
  fi
}
trap cleanup EXIT

while (($#)); do
  case "$1" in
    --namespace)
      (($# >= 2)) || die "--namespace requires a value"
      NAMESPACE="$2"
      shift 2
      ;;
    --team)
      (($# >= 2)) || die "--team requires a value"
      TEAM="$2"
      shift 2
      ;;
    --controller-deployment)
      (($# >= 2)) || die "--controller-deployment requires a value"
      CONTROLLER_DEPLOYMENT="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

command -v "$KUBECTL" >/dev/null 2>&1 || die "kubectl executable not found: $KUBECTL"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
[[ -n "$NAMESPACE" ]] || die "--namespace is required"
[[ -n "$TEAM" ]] || die "--team is required"
validate_kube_name "namespace" "$NAMESPACE"
validate_kube_name "Team" "$TEAM"
validate_kube_name "controller Deployment" "$CONTROLLER_DEPLOYMENT"

WORK_DIR="$(mktemp -d)"
readonly WORK_DIR

log "checking the scoped Team and ready OpenClaw Agent Pods"
"$KUBECTL" version --request-timeout=10s >/dev/null
"$KUBECTL" -n "$NAMESPACE" get team "$TEAM" \
  -o 'jsonpath={range .status.members[*]}{.name}{"\t"}{.runtimeName}{"\n"}{end}' \
  >"$WORK_DIR/members.tsv"
"$KUBECTL" -n "$NAMESPACE" get deployment "$CONTROLLER_DEPLOYMENT" >/dev/null
"$KUBECTL" -n "$NAMESPACE" get pods \
  -l "$TEAM_LABEL=$TEAM,$RUNTIME_LABEL=openclaw" \
  -o 'jsonpath={range .items[*]}{.metadata.name}{"\t"}{.metadata.labels.agentteams\.io/worker}{"\t"}{.metadata.deletionTimestamp}{"\t"}{.status.phase}{"\t"}{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' \
  >"$WORK_DIR/pods.tsv"

# The Pod label is the canonical member name. The selected Team status maps it to the
# runtime identity used as the object-storage path key. Query only selected
# metadata/status columns so literal Secret-backed Pod environment values never
# leave the API server.
python3 - "$WORK_DIR/members.tsv" "$WORK_DIR/pods.tsv" "$WORK_DIR/targets.tsv" "$EXPECTED_AGENT_COUNT" <<'PY'
import re
import sys

members_source, pods_source, destination, expected_count_text = sys.argv[1:]
expected_count = int(expected_count_text)
runtime_names = {}
with open(members_source, encoding="utf-8") as stream:
    for line in stream:
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 2 or not fields[0]:
            raise SystemExit("unexpected kubectl Team member status output")
        member_name, runtime_name = fields
        if member_name in runtime_names:
            raise SystemExit(f"duplicate Team status member {member_name!r}")
        if not runtime_name:
            raise SystemExit(f"Team status member {member_name!r} has no runtimeName")
        runtime_names[member_name] = runtime_name

if len(runtime_names) != expected_count:
    raise SystemExit(
        f"Team must expose exactly {expected_count} status members; "
        f"found {len(runtime_names)}"
    )
if len(set(runtime_names.values())) != expected_count:
    raise SystemExit("Team status runtimeName values are not unique")

name_pattern = re.compile(r"^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$")
targets = []
seen_agents = set()
with open(pods_source, encoding="utf-8") as stream:
    rows = [line.rstrip("\n").split("\t") for line in stream if line.strip()]
for row in rows:
    if len(row) != 5:
        raise SystemExit("unexpected kubectl Pod status output")
    pod_name, member_name, deletion_timestamp, phase, ready = row
    if deletion_timestamp:
        continue
    if phase != "Running" or ready != "True":
        raise SystemExit(f"OpenClaw Agent Pod {pod_name!r} is not Ready")
    if member_name not in runtime_names:
        raise SystemExit(
            f"ready OpenClaw Pod {pod_name!r} is not an exact Team status member"
        )
    agent_name = runtime_names[member_name]
    container_name = "worker"
    for label, value in (
        ("Pod", pod_name),
        ("Team member", member_name),
        ("container", container_name),
        ("Agent runtime", agent_name),
    ):
        if not isinstance(value, str) or not name_pattern.fullmatch(value):
            raise SystemExit(f"{label} name is unsafe: {value!r}")
    if agent_name in seen_agents:
        raise SystemExit(f"duplicate ready Pod for Agent runtime {agent_name!r}")
    seen_agents.add(agent_name)
    targets.append((agent_name, pod_name, container_name))

if len(targets) != expected_count:
    raise SystemExit(
        f"Team must have exactly {expected_count} Ready OpenClaw Agent Pods; "
        f"found {len(targets)}"
    )
if seen_agents != set(runtime_names.values()):
    raise SystemExit("Ready OpenClaw Agent Pods do not exactly cover Team status members")
targets.sort()
with open(destination, "w", encoding="utf-8", newline="\n") as stream:
    for agent_name, pod_name, container_name in targets:
        stream.write(f"{agent_name}\t{pod_name}\t{container_name}\n")
PY

preflight_remote_config() {
  local agent_name="$1"
  "$KUBECTL" -n "$NAMESPACE" exec -i "deployment/$CONTROLLER_DEPLOYMENT" -- \
    sh -s -- "$agent_name" <<'SH'
set -eu
agent_name=$1
: "${AGENTTEAMS_STORAGE_PREFIX:?AGENTTEAMS_STORAGE_PREFIX is required}"
command -v mc >/dev/null 2>&1
command -v jq >/dev/null 2>&1
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
config="$work_dir/openclaw.json"
remote="${AGENTTEAMS_STORAGE_PREFIX%/}/agents/$agent_name/openclaw.json"
mc cp "$remote" "$config" >/dev/null
jq -e '
  .channels.matrix as $matrix
  | ($matrix.groupPolicy == "allowlist")
  and ($matrix.groupAllowFrom | type == "array" and length > 0
       and all(.[]; type == "string" and length > 0 and . != "*"))
  and ($matrix.dm.policy == "allowlist")
  and ($matrix.dm.allowFrom | type == "array" and length > 0
       and all(.[]; type == "string" and length > 0 and . != "*"))
  and ($matrix.groups | type == "object")
  and ($matrix.groups["*"].allow == true)
  and ($matrix.groups["*"].requireMention == true)
' "$config" >/dev/null
SH
}

preflight_live_config() {
  local pod_name="$1"
  local container_name="$2"
  "$KUBECTL" -n "$NAMESPACE" exec -i "$pod_name" -c "$container_name" -- sh -s <<'SH'
set -eu
command -v jq >/dev/null 2>&1
config="${HOME:?HOME is required}/openclaw.json"
test -f "$config"
jq -e '
  .channels.matrix as $matrix
  | ($matrix.groupPolicy == "allowlist")
  and ($matrix.groupAllowFrom | type == "array" and length > 0
       and all(.[]; type == "string" and length > 0 and . != "*"))
  and ($matrix.dm.policy == "allowlist")
  and ($matrix.dm.allowFrom | type == "array" and length > 0
       and all(.[]; type == "string" and length > 0 and . != "*"))
  and ($matrix.groups | type == "object")
  and ($matrix.groups["*"].allow == true)
  and ($matrix.groups["*"].requireMention == true)
' "$config" >/dev/null
SH
}

log "preflighting every authoritative and live configuration"
while IFS=$'\t' read -r agent_name pod_name container_name; do
  preflight_remote_config "$agent_name"
  preflight_live_config "$pod_name" "$container_name"
done <"$WORK_DIR/targets.tsv"

patch_remote_config() {
  local agent_name="$1"
  "$KUBECTL" -n "$NAMESPACE" exec -i "deployment/$CONTROLLER_DEPLOYMENT" -- \
    sh -s -- "$agent_name" <<'SH'
set -eu
agent_name=$1
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
original="$work_dir/original.json"
latest="$work_dir/latest.json"
candidate="$work_dir/candidate.json"
before_matrix="$work_dir/before-matrix.json"
after_matrix="$work_dir/after-matrix.json"
verified="$work_dir/verified.json"
remote="${AGENTTEAMS_STORAGE_PREFIX%/}/agents/$agent_name/openclaw.json"

mc cp "$remote" "$original" >/dev/null
jq '.channels.matrix.allowBots = "mentions"
  | .channels.matrix.streaming = "off"' "$original" >"$candidate"
jq -e '.channels.matrix.allowBots == "mentions"
  and .channels.matrix.streaming == "off"
  and .channels.matrix.groupPolicy == "allowlist"
  and .channels.matrix.groups["*"].requireMention == true' \
  "$candidate" >/dev/null
jq -S 'del(.channels.matrix.allowBots, .channels.matrix.streaming)' \
  "$original" >"$before_matrix"
jq -S 'del(.channels.matrix.allowBots, .channels.matrix.streaming)' \
  "$candidate" >"$after_matrix"
cmp -s "$before_matrix" "$after_matrix"

if cmp -s "$original" "$candidate"; then
  exit 0
fi

# Optimistic concurrency guard: do not overwrite a controller update observed
# after this patch read the original object.
mc cp "$remote" "$latest" >/dev/null
cmp -s "$original" "$latest" || {
  echo "authoritative config changed concurrently; retry the patch" >&2
  exit 1
}
mc cp "$candidate" "$remote" >/dev/null
mc cp "$remote" "$verified" >/dev/null
cmp -s "$candidate" "$verified"
SH
}

patch_live_config() {
  local pod_name="$1"
  local container_name="$2"
  "$KUBECTL" -n "$NAMESPACE" exec -i "$pod_name" -c "$container_name" -- sh -s <<'SH'
set -eu
config="${HOME:?HOME is required}/openclaw.json"
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
original="$work_dir/original.json"
candidate="$work_dir/candidate.json"
before_matrix="$work_dir/before-matrix.json"
after_matrix="$work_dir/after-matrix.json"
cp "$config" "$original"
jq '.channels.matrix.allowBots = "mentions"
  | .channels.matrix.streaming = "off"' "$original" >"$candidate"
jq -e '.channels.matrix.allowBots == "mentions"
  and .channels.matrix.streaming == "off"
  and .channels.matrix.groupPolicy == "allowlist"
  and .channels.matrix.groups["*"].requireMention == true' \
  "$candidate" >/dev/null
jq -S 'del(.channels.matrix.allowBots, .channels.matrix.streaming)' \
  "$original" >"$before_matrix"
jq -S 'del(.channels.matrix.allowBots, .channels.matrix.streaming)' \
  "$candidate" >"$after_matrix"
cmp -s "$before_matrix" "$after_matrix"

if cmp -s "$original" "$candidate"; then
  exit 0
fi
cmp -s "$original" "$config" || {
  echo "live config changed concurrently; retry the patch" >&2
  exit 1
}
mv "$candidate" "$config"
jq -e '.channels.matrix.allowBots == "mentions"
  and .channels.matrix.streaming == "off"
  and .channels.matrix.groupPolicy == "allowlist"
  and .channels.matrix.groups["*"].requireMention == true' \
  "$config" >/dev/null
SH
}

log "updating authoritative configurations without exposing their contents"
while IFS=$'\t' read -r agent_name pod_name container_name; do
  patch_remote_config "$agent_name"
done <"$WORK_DIR/targets.tsv"

log "hot-updating running OpenClaw configurations"
patched=0
while IFS=$'\t' read -r agent_name pod_name container_name; do
  patch_live_config "$pod_name" "$container_name"
  log "verified Agent $agent_name"
  patched=$((patched + 1))
done <"$WORK_DIR/targets.tsv"

log "allowBots=mentions and streaming=off are active for $patched OpenClaw Agent(s) in Team $TEAM"
