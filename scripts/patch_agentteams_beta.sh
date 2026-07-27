#!/usr/bin/env bash
# Reapply the compatibility fixes needed by AgentTeams v1.2.0-beta.1.
#
# The script intentionally contains no credentials. The controller startup
# wrapper references the Secret-backed environment variables already present
# on the Deployment.

set -Eeuo pipefail

readonly DEFAULT_NAMESPACE="agentteams-system"
readonly DEFAULT_CONTROLLER_DEPLOYMENT="agentteams-hiclaw-controller"
readonly TEAM_CRD="teams.agentteams.io"
readonly TLSROUTE_CRD="tlsroutes.gateway.networking.k8s.io"
readonly PATCH_LABEL="devflow.agentteams.io/beta-compatibility"

NAMESPACE="${AGENTTEAMS_NAMESPACE:-$DEFAULT_NAMESPACE}"
CONTROLLER_DEPLOYMENT="${AGENTTEAMS_CONTROLLER_DEPLOYMENT:-$DEFAULT_CONTROLLER_DEPLOYMENT}"
HIGRESS_SERVICE_ACCOUNT="${HIGRESS_SERVICE_ACCOUNT:-}"
KUBECTL="${KUBECTL:-kubectl}"

usage() {
  cat <<'EOF'
Usage: scripts/patch_agentteams_beta.sh [options]

Options:
  --namespace NAME              AgentTeams namespace (default: agentteams-system)
  --controller-deployment NAME Controller Deployment name
  --higress-service-account SA Override automatic Higress ServiceAccount discovery
  --help                        Show this help

The current kubectl context must point at the intended cluster. The operation
is idempotent and fails before applying a patch when an expected object or
schema path is missing or ambiguous.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[agentteams-beta-compat] %s\n' "$*" >&2
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
    --controller-deployment)
      (($# >= 2)) || die "--controller-deployment requires a value"
      CONTROLLER_DEPLOYMENT="$2"
      shift 2
      ;;
    --higress-service-account)
      (($# >= 2)) || die "--higress-service-account requires a value"
      HIGRESS_SERVICE_ACCOUNT="$2"
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
[[ -n "$NAMESPACE" ]] || die "namespace must not be empty"
[[ -n "$CONTROLLER_DEPLOYMENT" ]] || die "controller Deployment must not be empty"
validate_kube_name "namespace" "$NAMESPACE"
validate_kube_name "controller Deployment" "$CONTROLLER_DEPLOYMENT"

WORK_DIR="$(mktemp -d)"
readonly WORK_DIR

log "checking cluster access and required objects"
"$KUBECTL" version --request-timeout=10s >/dev/null
"$KUBECTL" get namespace "$NAMESPACE" >/dev/null
"$KUBECTL" get crd "$TEAM_CRD" -o json >"$WORK_DIR/team-crd.json"
"$KUBECTL" get crd "$TLSROUTE_CRD" -o json >"$WORK_DIR/tlsroute-crd.json"
"$KUBECTL" -n "$NAMESPACE" get deployment "$CONTROLLER_DEPLOYMENT" -o json \
  >"$WORK_DIR/controller-deployment.json"

# Generate JSON patches from the installed schemas instead of assuming a
# version-list index. The Team leader runtime schema is copied from workers so
# it remains exactly compatible with the runtime enum installed by the chart.
python3 - "$WORK_DIR/team-crd.json" "$WORK_DIR/team-crd.patch.json" <<'PY'
import copy
import json
import sys

source, destination = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    crd = json.load(stream)

patch = []
matched = 0
for version_index, version in enumerate(crd.get("spec", {}).get("versions", [])):
    if not version.get("served"):
        continue
    properties = (
        version.get("schema", {})
        .get("openAPIV3Schema", {})
        .get("properties", {})
        .get("spec", {})
        .get("properties", {})
    )
    leader = properties.get("leader", {}).get("properties")
    worker_runtime = (
        properties.get("workers", {})
        .get("items", {})
        .get("properties", {})
        .get("runtime")
    )
    if not isinstance(leader, dict) or not isinstance(worker_runtime, dict):
        raise SystemExit(
            f"served Team version {version.get('name')!r} lacks leader/worker schema paths"
        )
    matched += 1
    if "runtime" not in leader:
        patch.append(
            {
                "op": "add",
                "path": (
                    f"/spec/versions/{version_index}/schema/openAPIV3Schema/"
                    "properties/spec/properties/leader/properties/runtime"
                ),
                "value": copy.deepcopy(worker_runtime),
            }
        )
    elif leader["runtime"] != worker_runtime:
        raise SystemExit(
            f"served Team version {version.get('name')!r} has an incompatible leader.runtime schema"
        )

if matched == 0:
    raise SystemExit("Team CRD has no served version")
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(patch, stream, separators=(",", ":"))
PY

python3 - "$WORK_DIR/tlsroute-crd.json" "$WORK_DIR/tlsroute-crd.patch.json" <<'PY'
import json
import sys

source, destination = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    crd = json.load(stream)

matches = [
    (index, version)
    for index, version in enumerate(crd.get("spec", {}).get("versions", []))
    if version.get("name") == "v1alpha2"
]
if len(matches) != 1:
    raise SystemExit(f"expected one TLSRoute v1alpha2 version, found {len(matches)}")
index, version = matches[0]
patch = [] if version.get("served") is True else [
    {"op": "replace", "path": f"/spec/versions/{index}/served", "value": True}
]
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(patch, stream, separators=(",", ":"))
PY

# Detect the controller container without relying on a beta chart's container
# name. Refuse ambiguity rather than modifying an arbitrary sidecar.
python3 - "$WORK_DIR/controller-deployment.json" "$WORK_DIR/controller.patch.json" <<'PY'
import json
import sys

source, destination = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    deployment = json.load(stream)

containers = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
candidates = [
    item for item in containers
    if "controller" in item.get("name", "").lower()
    or "controller" in item.get("image", "").lower()
]
if len(candidates) != 1:
    raise SystemExit(f"expected one controller container, found {len(candidates)}")

startup = r'''set -eu
: "${AGENTTEAMS_STORAGE_PREFIX:?AGENTTEAMS_STORAGE_PREFIX is required}"
: "${AGENTTEAMS_FS_ENDPOINT:?AGENTTEAMS_FS_ENDPOINT is required}"
: "${AGENTTEAMS_FS_ACCESS_KEY:?AGENTTEAMS_FS_ACCESS_KEY is required}"
: "${AGENTTEAMS_FS_SECRET_KEY:?AGENTTEAMS_FS_SECRET_KEY is required}"
case "$AGENTTEAMS_STORAGE_PREFIX" in
  */*) storage_alias=${AGENTTEAMS_STORAGE_PREFIX%%/*} ;;
  *) echo "AGENTTEAMS_STORAGE_PREFIX must be alias/path" >&2; exit 1 ;;
esac
command -v mc >/dev/null 2>&1
test -x /usr/local/bin/hiclaw-controller
mc alias set "$storage_alias" "$AGENTTEAMS_FS_ENDPOINT" \
  "$AGENTTEAMS_FS_ACCESS_KEY" "$AGENTTEAMS_FS_SECRET_KEY" >/dev/null
exec /usr/local/bin/hiclaw-controller
'''
patch = {
    "metadata": {"labels": {"devflow.agentteams.io/beta-compatibility": "v1.2.0-beta.1"}},
    "spec": {
        "template": {
            "metadata": {"labels": {"devflow.agentteams.io/beta-compatibility": "v1.2.0-beta.1"}},
            "spec": {
                "containers": [
                    {
                        "name": candidates[0]["name"],
                        "command": ["/bin/sh", "-ec"],
                        "args": [startup],
                    }
                ]
            },
        }
    },
}
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(patch, stream, separators=(",", ":"))
PY

if [[ -z "$HIGRESS_SERVICE_ACCOUNT" ]]; then
  "$KUBECTL" -n "$NAMESPACE" get deployments -o json >"$WORK_DIR/deployments.json"
  HIGRESS_SERVICE_ACCOUNT="$({
    python3 - "$WORK_DIR/deployments.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    deployments = json.load(stream).get("items", [])

accounts = set()
for deployment in deployments:
    template = deployment.get("spec", {}).get("template", {}).get("spec", {})
    searchable = " ".join(
        [deployment.get("metadata", {}).get("name", "")]
        + [container.get("name", "") for container in template.get("containers", [])]
        + [container.get("image", "") for container in template.get("containers", [])]
    ).lower()
    if "higress" in searchable and "controller" in searchable:
        account = template.get("serviceAccountName") or "default"
        accounts.add(account)

if len(accounts) != 1:
    raise SystemExit(
        f"expected one Higress controller ServiceAccount, found {sorted(accounts)!r}; "
        "use --higress-service-account"
    )
print(accounts.pop())
PY
  })"
fi
[[ -n "$HIGRESS_SERVICE_ACCOUNT" ]] || die "Higress ServiceAccount must not be empty"
validate_kube_name "Higress ServiceAccount" "$HIGRESS_SERVICE_ACCOUNT"
"$KUBECTL" -n "$NAMESPACE" get serviceaccount "$HIGRESS_SERVICE_ACCOUNT" >/dev/null

cat >"$WORK_DIR/higress-rbac.yaml" <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: agentteams-higress-experimental-reader
  labels:
    $PATCH_LABEL: v1.2.0-beta.1
rules:
  - apiGroups: ["gateway.networking.x-k8s.io"]
    resources: ["xlistenersets", "xbackendtrafficpolicies"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: agentteams-higress-experimental-reader
  labels:
    $PATCH_LABEL: v1.2.0-beta.1
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: agentteams-higress-experimental-reader
subjects:
  - kind: ServiceAccount
    name: $HIGRESS_SERVICE_ACCOUNT
    namespace: $NAMESPACE
EOF

apply_json_patch_if_needed() {
  local resource="$1"
  local patch_file="$2"
  local count
  count="$(python3 - "$patch_file" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(len(json.load(stream)))
PY
)"
  if [[ "$count" == "0" ]]; then
    log "$resource already compatible"
  else
    "$KUBECTL" patch "$resource" --type=json --patch-file "$patch_file"
  fi
}

log "adding Team leader.runtime schema when absent"
apply_json_patch_if_needed "crd/$TEAM_CRD" "$WORK_DIR/team-crd.patch.json"
log "serving TLSRoute v1alpha2"
apply_json_patch_if_needed "crd/$TLSROUTE_CRD" "$WORK_DIR/tlsroute-crd.patch.json"
log "granting Higress read-only access to experimental Gateway API resources"
"$KUBECTL" apply -f "$WORK_DIR/higress-rbac.yaml"
log "fixing controller entrypoint and storage alias initialization"
"$KUBECTL" -n "$NAMESPACE" patch deployment "$CONTROLLER_DEPLOYMENT" \
  --type=strategic --patch-file "$WORK_DIR/controller.patch.json"
"$KUBECTL" -n "$NAMESPACE" rollout status deployment "$CONTROLLER_DEPLOYMENT" --timeout=180s

log "verifying effective permissions and rollout"
"$KUBECTL" auth can-i get xlistenersets.gateway.networking.x-k8s.io \
  --as="system:serviceaccount:$NAMESPACE:$HIGRESS_SERVICE_ACCOUNT" | grep -qx yes
"$KUBECTL" auth can-i watch xbackendtrafficpolicies.gateway.networking.x-k8s.io \
  --as="system:serviceaccount:$NAMESPACE:$HIGRESS_SERVICE_ACCOUNT" | grep -qx yes
"$KUBECTL" -n "$NAMESPACE" get deployment "$CONTROLLER_DEPLOYMENT" \
  -o jsonpath='{.status.availableReplicas}' | grep -Eq '^[1-9][0-9]*$'

log "AgentTeams v1.2.0-beta.1 compatibility patch is active"
