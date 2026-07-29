"""Attest and converge the AgentTeams controller's DevFlow cache.

The host validates the unique Deployment -> ReplicaSet -> Pod ownership chain
and the pinned controller image.  A self-contained BusyBox/POSIX-shell helper
then hashes the six pinned role archives and the six controller-owned Skill
caches. Apply uses those pinned archives and external same-filesystem
quarantines; arbitrary Skill names and file contents never cross the Pod
boundary.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Protocol

try:
    from scripts.build_agentteams_package import ROLE_SKILLS as PACKAGE_ROLE_SKILLS
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from build_agentteams_package import (  # type: ignore[no-redef]
        ROLE_SKILLS as PACKAGE_ROLE_SKILLS,
    )

NAMESPACE = "agentteams-system"
DEPLOYMENT_NAME = "agentteams-hiclaw-controller"
CONTAINER_NAME = "controller"
SELECTOR_LABELS = {
    "app.kubernetes.io/name": "hiclaw",
    "app.kubernetes.io/instance": "agentteams",
    "app.kubernetes.io/component": "controller",
}
SELECTOR = (
    "app.kubernetes.io/name=hiclaw,"
    "app.kubernetes.io/instance=agentteams,"
    "app.kubernetes.io/component=controller"
)
CONTROLLER_IMAGE = (
    "higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/agentteams-controller:v1.2.0-beta.1"
)
CONTROLLER_IMAGE_ID = (
    "higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/"
    "agentteams-controller@sha256:"
    "074cf1c379704bfbbd8f61eea77782819d6afbb540cee0c21af973d4ee07e7d6"
)
ROLE_SKILLS: dict[str, tuple[str, ...]] = {
    "devflow-lead": (),
    "devflow-triage": ("issue-classifier",),
    "devflow-locator": ("code-root-cause", "github-evidence"),
    "devflow-coder": ("patch-generator",),
    "devflow-tester": ("test-runner",),
    "devflow-reviewer": ("pr-reviewer", "experience-distiller"),
}
ARCHIVE_DIGESTS = {
    "devflow-lead": "82ffe34e3f02162febe4d1e88c5ed68b4676d4917007d6f8a2cf13e0cb9741a5",
    "devflow-triage": "d5297a1741b0279310dc1adbe36cc02c5c33c8cf5897f4ea1532b4761f21630f",
    "devflow-locator": "cab3503cd3100bf42238cf3b53ad65deca95e9e9e6b99551a81bb0f506daf54b",
    "devflow-coder": "a54c323f4599899b8bee7950a759ec0e9cd0c56ae27fd091e559853ed9d41b16",
    "devflow-tester": "684de72825bb0fdc9a0435c7e568934ce85dc8a37d30e17aa67d1eb7d3833563",
    "devflow-reviewer": "e3d5513508f49b288384fbf47b746dbb52760de997388450f5636c640895842a",
}
ARCHIVE_SIZES = {
    "devflow-lead": 2862,
    "devflow-triage": 15721,
    "devflow-locator": 57200,
    "devflow-coder": 56024,
    "devflow-tester": 55161,
    "devflow-reviewer": 37151,
}
ALL_FIXED_SKILLS = tuple(sorted({skill for skills in ROLE_SKILLS.values() for skill in skills}))
DIGEST = re.compile(r"^[0-9a-f]{64}$")
UID = re.compile(r"^[a-f0-9-]{8,128}$")
MAX_KUBECTL_OUTPUT = 4 * 1024 * 1024

if ROLE_SKILLS != PACKAGE_ROLE_SKILLS or len(ALL_FIXED_SKILLS) != 7:
    raise RuntimeError("controller cache policy disagrees with the package policy")


class ControllerCacheError(RuntimeError):
    """Controller identity or cache state is outside the fixed policy."""


class Runner(Protocol):
    def run(self, args: list[str], input_data: bytes | None = None) -> str: ...


class SubprocessRunner:
    """Run commands without a host shell and suppress remote diagnostic text."""

    def run(self, args: list[str], input_data: bytes | None = None) -> str:
        try:
            completed = subprocess.run(
                args,
                input=input_data,
                capture_output=True,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ControllerCacheError("controller authority command failed") from exc
        if completed.returncode != 0 or len(completed.stdout) > MAX_KUBECTL_OUTPUT:
            raise ControllerCacheError("controller authority command failed safely")
        try:
            return completed.stdout.decode("utf-8")
        except UnicodeError as exc:
            raise ControllerCacheError(
                "controller authority command returned invalid text"
            ) from exc


@dataclass(frozen=True)
class ControllerTarget:
    deployment_uid: str
    replica_set_name: str
    replica_set_uid: str
    pod_name: str
    pod_uid: str
    image: str
    image_id: str
    restart_count: int


@dataclass(frozen=True)
class ControllerCacheReport:
    role: str
    archive_size: int
    archive_digest: str
    archive_valid: bool
    known_skills: tuple[str, ...]
    stable_skill_digests: tuple[tuple[str, str], ...]
    unknown_count: int
    unknown_digest: str
    snapshot: str


@dataclass(frozen=True)
class ControllerReconcileResult:
    target: ControllerTarget
    reports: tuple[ControllerCacheReport, ...]
    changed_roles: tuple[str, ...]
    transaction_id: str | None


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ControllerCacheError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ControllerCacheError("non-standard JSON scalar")


def _json_object(text: str, label: str) -> dict[str, Any]:
    if len(text.encode("utf-8")) > MAX_KUBECTL_OUTPUT:
        raise ControllerCacheError(f"{label} exceeded the output limit")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ControllerCacheError(f"{label} was not strict JSON") from exc
    if not isinstance(value, dict):
        raise ControllerCacheError(f"{label} must be an object")
    return value


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ControllerCacheError(f"{label} must be an object")
    return value


def _items(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ControllerCacheError(f"{label} must be a list")
    return value


def _owner(value: Any, *, kind: str, name: str, uid: str) -> bool:
    owners = _items(value, "owner references")
    if len(owners) != 1 or not isinstance(owners[0], dict):
        return False
    owner = owners[0]
    return (
        owner.get("apiVersion") == "apps/v1"
        and owner.get("kind") == kind
        and owner.get("name") == name
        and owner.get("uid") == uid
        and owner.get("controller") is True
        and owner.get("blockOwnerDeletion") is True
    )


def _metadata(document: dict[str, Any], *, name: str) -> tuple[dict[str, Any], str]:
    metadata = _mapping(document.get("metadata"), f"{name} metadata")
    uid = metadata.get("uid")
    if (
        metadata.get("name") != name
        or metadata.get("namespace") != NAMESPACE
        or not isinstance(uid, str)
        or UID.fullmatch(uid) is None
        or metadata.get("deletionTimestamp") is not None
    ):
        raise ControllerCacheError(f"{name} metadata is outside policy")
    return metadata, uid


def _container(spec: dict[str, Any], label: str) -> dict[str, Any]:
    containers = _items(spec.get("containers"), f"{label} containers")
    if len(containers) != 1 or not isinstance(containers[0], dict):
        raise ControllerCacheError(f"{label} must contain only the controller")
    container = containers[0]
    if container.get("name") != CONTAINER_NAME or container.get("image") != CONTROLLER_IMAGE:
        raise ControllerCacheError(f"{label} controller image is outside policy")
    return container


def _labels_cover(value: Any) -> bool:
    return isinstance(value, dict) and all(
        value.get(key) == item for key, item in SELECTOR_LABELS.items()
    )


def _kubectl(kubectl: str, *args: str) -> list[str]:
    return [kubectl, "--namespace", NAMESPACE, *args]


def discover_controller(runner: Runner, kubectl: str = "kubectl") -> ControllerTarget:
    """Discover and attest exactly one pinned controller ownership chain."""

    runner.run([kubectl, "version", "--request-timeout=10s"])
    deployment = _json_object(
        runner.run(_kubectl(kubectl, "get", "deployment", DEPLOYMENT_NAME, "-o", "json")),
        "controller Deployment",
    )
    replica_sets = _json_object(
        runner.run(_kubectl(kubectl, "get", "replicasets", "-l", SELECTOR, "-o", "json")),
        "controller ReplicaSets",
    )
    pods = _json_object(
        runner.run(_kubectl(kubectl, "get", "pods", "-l", SELECTOR, "-o", "json")),
        "controller Pods",
    )

    metadata, deployment_uid = _metadata(deployment, name=DEPLOYMENT_NAME)
    spec = _mapping(deployment.get("spec"), "Deployment spec")
    status = _mapping(deployment.get("status"), "Deployment status")
    selector = _mapping(spec.get("selector"), "Deployment selector")
    template = _mapping(spec.get("template"), "Deployment template")
    template_metadata = _mapping(template.get("metadata"), "Deployment template metadata")
    template_spec = _mapping(template.get("spec"), "Deployment template spec")
    _container(template_spec, "Deployment template")
    if (
        deployment.get("apiVersion") != "apps/v1"
        or deployment.get("kind") != "Deployment"
        or spec.get("replicas") != 1
        or selector.get("matchLabels") != SELECTOR_LABELS
        or not _labels_cover(template_metadata.get("labels"))
        or status.get("observedGeneration") != metadata.get("generation")
        or any(
            status.get(field) != 1
            for field in ("replicas", "readyReplicas", "availableReplicas", "updatedReplicas")
        )
        or status.get("unavailableReplicas") not in (None, 0)
    ):
        raise ControllerCacheError("controller Deployment is not uniquely ready")

    pod_values = _items(pods.get("items"), "Pod items")
    if pods.get("kind") not in ("PodList", "List") or len(pod_values) != 1:
        raise ControllerCacheError("controller does not have exactly one Pod")
    pod = _mapping(pod_values[0], "Pod")
    pod_meta = _mapping(pod.get("metadata"), "Pod metadata")
    pod_name = pod_meta.get("name")
    if not isinstance(pod_name, str):
        raise ControllerCacheError("controller Pod name is outside policy")
    _, pod_uid = _metadata(pod, name=pod_name)
    pod_owners = _items(pod_meta.get("ownerReferences"), "Pod owner references")
    if len(pod_owners) != 1 or not isinstance(pod_owners[0], dict):
        raise ControllerCacheError("controller Pod owner is ambiguous")
    pod_owner = pod_owners[0]
    rs_name = pod_owner.get("name")
    rs_uid = pod_owner.get("uid")
    if (
        pod_owner.get("apiVersion") != "apps/v1"
        or pod_owner.get("kind") != "ReplicaSet"
        or pod_owner.get("controller") is not True
        or pod_owner.get("blockOwnerDeletion") is not True
        or not isinstance(rs_name, str)
        or re.fullmatch(r"agentteams-hiclaw-controller-[a-z0-9]+", rs_name) is None
        or not isinstance(rs_uid, str)
        or UID.fullmatch(rs_uid) is None
        or not pod_name.startswith(f"{rs_name}-")
    ):
        raise ControllerCacheError("controller Pod owner is outside policy")

    rs_values = _items(replica_sets.get("items"), "ReplicaSet items")
    if replica_sets.get("kind") not in ("ReplicaSetList", "List"):
        raise ControllerCacheError("controller ReplicaSet collection is outside policy")
    matching: list[dict[str, Any]] = []
    historical: list[dict[str, Any]] = []
    for raw_replica_set in rs_values:
        candidate = _mapping(raw_replica_set, "ReplicaSet")
        candidate_meta = _mapping(candidate.get("metadata"), "ReplicaSet metadata")
        if candidate_meta.get("name") == rs_name and candidate_meta.get("uid") == rs_uid:
            matching.append(candidate)
        else:
            historical.append(candidate)
    if len(matching) != 1:
        raise ControllerCacheError("controller Pod does not resolve to exactly one ReplicaSet")
    replica_set = matching[0]
    rs_meta = _mapping(replica_set.get("metadata"), "ReplicaSet metadata")
    _metadata(replica_set, name=rs_name)
    rs_spec = _mapping(replica_set.get("spec"), "ReplicaSet spec")
    rs_status = _mapping(replica_set.get("status"), "ReplicaSet status")
    rs_template = _mapping(rs_spec.get("template"), "ReplicaSet template")
    rs_template_meta = _mapping(rs_template.get("metadata"), "ReplicaSet template metadata")
    rs_template_spec = _mapping(rs_template.get("spec"), "ReplicaSet template spec")
    _container(rs_template_spec, "ReplicaSet template")
    if (
        replica_set.get("apiVersion") != "apps/v1"
        or replica_set.get("kind") != "ReplicaSet"
        or not _owner(
            rs_meta.get("ownerReferences"),
            kind="Deployment",
            name=DEPLOYMENT_NAME,
            uid=deployment_uid,
        )
        or rs_spec.get("replicas") != 1
        or not _labels_cover(
            _mapping(rs_spec.get("selector"), "ReplicaSet selector").get("matchLabels")
        )
        or not _labels_cover(rs_template_meta.get("labels"))
        or any(
            rs_status.get(field) != 1
            for field in ("replicas", "readyReplicas", "availableReplicas", "fullyLabeledReplicas")
        )
    ):
        raise ControllerCacheError("controller ReplicaSet is outside policy")

    for old_replica_set in historical:
        old_meta = _mapping(old_replica_set.get("metadata"), "historical ReplicaSet metadata")
        old_name = old_meta.get("name")
        if (
            not isinstance(old_name, str)
            or re.fullmatch(r"agentteams-hiclaw-controller-[a-z0-9]+", old_name) is None
        ):
            raise ControllerCacheError("historical ReplicaSet name is outside policy")
        _metadata(old_replica_set, name=old_name)
        old_spec = _mapping(old_replica_set.get("spec"), "historical ReplicaSet spec")
        old_status = _mapping(old_replica_set.get("status"), "historical ReplicaSet status")
        if (
            old_replica_set.get("apiVersion") != "apps/v1"
            or old_replica_set.get("kind") != "ReplicaSet"
            or not _owner(
                old_meta.get("ownerReferences"),
                kind="Deployment",
                name=DEPLOYMENT_NAME,
                uid=deployment_uid,
            )
            or old_spec.get("replicas") != 0
            or not _labels_cover(
                _mapping(old_spec.get("selector"), "historical ReplicaSet selector").get(
                    "matchLabels"
                )
            )
            or any(
                old_status.get(field) not in (None, 0)
                for field in (
                    "replicas",
                    "readyReplicas",
                    "availableReplicas",
                    "fullyLabeledReplicas",
                )
            )
        ):
            raise ControllerCacheError("historical ReplicaSet is not safely scaled down")

    pod_spec = _mapping(pod.get("spec"), "Pod spec")
    pod_status = _mapping(pod.get("status"), "Pod status")
    _container(pod_spec, "Pod")
    statuses = _items(pod_status.get("containerStatuses"), "container statuses")
    conditions = _items(pod_status.get("conditions"), "Pod conditions")
    if len(statuses) != 1 or not isinstance(statuses[0], dict):
        raise ControllerCacheError("controller status is ambiguous")
    container_status = statuses[0]
    image_id = container_status.get("imageID")
    restart_count = container_status.get("restartCount")
    if isinstance(image_id, str) and image_id.startswith("docker-pullable://"):
        image_id = image_id.removeprefix("docker-pullable://")
    ready = any(
        isinstance(item, dict) and item.get("type") == "Ready" and item.get("status") == "True"
        for item in conditions
    )
    if (
        pod.get("apiVersion") != "v1"
        or pod.get("kind") != "Pod"
        or not _owner(pod_meta.get("ownerReferences"), kind="ReplicaSet", name=rs_name, uid=rs_uid)
        or not _labels_cover(pod_meta.get("labels"))
        or pod_status.get("phase") != "Running"
        or not ready
        or container_status.get("name") != CONTAINER_NAME
        or container_status.get("ready") is not True
        or container_status.get("image") != CONTROLLER_IMAGE
        or image_id != CONTROLLER_IMAGE_ID
        or isinstance(restart_count, bool)
        or not isinstance(restart_count, int)
        or restart_count < 0
    ):
        raise ControllerCacheError("controller Pod runtime identity is outside policy")
    return ControllerTarget(
        deployment_uid=deployment_uid,
        replica_set_name=rs_name,
        replica_set_uid=rs_uid,
        pod_name=pod_name,
        pod_uid=pod_uid,
        image=CONTROLLER_IMAGE,
        image_id=CONTROLLER_IMAGE_ID,
        restart_count=restart_count,
    )


CONTROLLER_AUDIT_HELPER = r"""#!/bin/sh
set -eu
export LC_ALL=C
umask 077
fail() { exit 70; }
tmp=$(mktemp -d /tmp/devflow-controller-audit.XXXXXX) || fail
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

safe_rel() {
  case "$1" in ''|.|*[!A-Za-z0-9._/-]*|/*|*//*|*/../*|../*|*/..|..|*/./*|./*|*/.) return 1;; esac
  [ "${#1}" -le 4096 ]
}
reject_mounts() {
  if awk -v root="$1" '$5 == root || index($5, root "/") == 1 { found=1 } END { exit(found ? 0 : 1) }' /proc/self/mountinfo; then
    fail
  fi
}
meta_dir() {
  [ -d "$1" ] && [ ! -L "$1" ] || fail
  [ "$(stat -c %u "$1")" = 0 ] && [ "$(stat -c %g "$1")" = 0 ] || fail
  [ "$(stat -c %a "$1")" = 755 ] || fail
}
tree_digest() {
  root=$1; base_dev=$2; records=$tmp/records.$$
  : > "$records"
  reject_mounts "$root"
  find "$root" -xdev -print > "$tmp/paths.$$" 2>/dev/null || fail
  count=0; total=0
  while IFS= read -r path; do
    count=$((count + 1)); [ "$count" -le 20000 ] || fail
    [ -L "$path" ] && fail
    rel=${path#"$root"}; rel=${rel#/}; [ -n "$rel" ] || rel=.
    [ "$rel" = . ] || safe_rel "$rel" || fail
    uid=$(stat -c %u "$path") || fail; gid=$(stat -c %g "$path") || fail
    mode=$(stat -c %a "$path") || fail; dev=$(stat -c %d "$path") || fail
    [ "$uid" = 0 ] && [ "$gid" = 0 ] && [ "$dev" = "$base_dev" ] || fail
    if [ -d "$path" ]; then
      [ "$mode" = 755 ] || fail
      printf 'D\t%s\t755\t0\t0\n' "$rel" >> "$records"
    elif [ -f "$path" ]; then
      [ "$mode" = 644 ] && [ "$(stat -c %h "$path")" = 1 ] || fail
      size=$(stat -c %s "$path") || fail; total=$((total + size))
      [ "$total" -le 268435456 ] || fail
      sum=$(sha256sum "$path") || fail; sum=${sum%% *}
      case "$sum" in *[!0-9a-f]*|'') fail;; esac; [ "${#sum}" -eq 64 ] || fail
      printf 'F\t%s\t644\t0\t0\t%s\t%s\n' "$rel" "$size" "$sum" >> "$records"
    else
      fail
    fi
  done < "$tmp/paths.$$"
  sort "$records" | sha256sum | awk '{print $1}'
}
is_fixed() {
  case "$1" in code-root-cause|experience-distiller|github-evidence|issue-classifier|patch-generator|pr-reviewer|test-runner) return 0;; *) return 1;; esac
}
audit_role() {
  role=$1; root=/root/hiclaw-fs/agents/$role/skills
  meta_dir "$root"; base_dev=$(stat -c %d "$root") || fail; reject_mounts "$root"
  known=$tmp/known.$role; unknown=$tmp/unknown.$role; : > "$known"; : > "$unknown"
  for entry in "$root"/* "$root"/.[!.]* "$root"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    [ -d "$entry" ] && [ ! -L "$entry" ] || fail
    name=${entry##*/}; safe_rel "$name" || fail
    digest=$(tree_digest "$entry" "$base_dev") || fail
    if is_fixed "$name"; then
      printf '%s\t%s\n' "$name" "$digest" >> "$known"
    else
      printf '%s\t%s\n' "$name" "$digest" >> "$unknown"
    fi
  done
  sort -o "$known" "$known"; sort -o "$unknown" "$unknown"
  unknown_count=$(wc -l < "$unknown" | tr -d ' ')
  unknown_digest=$(sha256sum "$unknown"); unknown_digest=${unknown_digest%% *}
  archive_line=$(grep "^$role|" "$tmp/archives") || fail
  { printf 'R\t%s\nA\t%s\nU\t%s\t%s\n' "$role" "$archive_line" "$unknown_count" "$unknown_digest"; cat "$known"; } > "$tmp/snapshot.$role"
  snapshot=$(sha256sum "$tmp/snapshot.$role"); snapshot=${snapshot%% *}
  printf '%s|%s|%s|%s\n' "$role" "$unknown_count" "$unknown_digest" "$snapshot" >> "$tmp/rolemeta"
}
audit_archive() {
  role=$1; expected_size=$2; expected_sum=$3
  path=/tmp/import/$role-v2.0.0.zip
  [ -f "$path" ] && [ ! -L "$path" ] || fail; reject_mounts "$path"
  [ "$(stat -c %u "$path")" = 0 ] && [ "$(stat -c %g "$path")" = 0 ] || fail
  [ "$(stat -c %a "$path")" = 644 ] && [ "$(stat -c %h "$path")" = 1 ] || fail
  [ "$(stat -c %d "$path")" = "$import_dev" ] || fail
  size=$(stat -c %s "$path") || fail; sum=$(sha256sum "$path") || fail; sum=${sum%% *}
  valid=false; [ "$size" = "$expected_size" ] && [ "$sum" = "$expected_sum" ] && valid=true
  printf '%s|%s|%s|%s\n' "$role" "$size" "$sum" "$valid" >> "$tmp/archives"
}
meta_dir /tmp/import; reject_mounts /tmp/import; import_dev=$(stat -c %d /tmp/import) || fail
: > "$tmp/archives"; : > "$tmp/rolemeta"
audit_archive devflow-lead 2862 82ffe34e3f02162febe4d1e88c5ed68b4676d4917007d6f8a2cf13e0cb9741a5
audit_archive devflow-triage 15721 d5297a1741b0279310dc1adbe36cc02c5c33c8cf5897f4ea1532b4761f21630f
audit_archive devflow-locator 57200 cab3503cd3100bf42238cf3b53ad65deca95e9e9e6b99551a81bb0f506daf54b
audit_archive devflow-coder 56024 a54c323f4599899b8bee7950a759ec0e9cd0c56ae27fd091e559853ed9d41b16
audit_archive devflow-tester 55161 684de72825bb0fdc9a0435c7e568934ce85dc8a37d30e17aa67d1eb7d3833563
audit_archive devflow-reviewer 37151 e3d5513508f49b288384fbf47b746dbb52760de997388450f5636c640895842a
audit_role devflow-lead
audit_role devflow-triage
audit_role devflow-locator
audit_role devflow-coder
audit_role devflow-tester
audit_role devflow-reviewer

emit_role() {
  role=$1
  archive=$(grep "^$role|" "$tmp/archives") || fail
  oldifs=$IFS; IFS='|'; set -- $archive; IFS=$oldifs
  size=$2; sum=$3; valid=$4
  meta=$(grep "^$role|" "$tmp/rolemeta") || fail
  oldifs=$IFS; IFS='|'; set -- $meta; IFS=$oldifs
  unknown_count=$2; unknown_digest=$3; snapshot=$4
  printf '"%s":{"archiveSize":%s,"archiveSha256":"%s","archiveValid":%s,"knownSkills":[' "$role" "$size" "$sum" "$valid"
  first=true
  tab=$(printf '\t')
  while IFS="$tab" read -r skill digest; do
    [ -n "$skill" ] || continue; $first || printf ','; first=false; printf '"%s"' "$skill"
  done < "$tmp/known.$role"
  printf '],"stableSkillDigests":{'; first=true
  while IFS="$tab" read -r skill digest; do
    [ -n "$skill" ] || continue; $first || printf ','; first=false; printf '"%s":"%s"' "$skill" "$digest"
  done < "$tmp/known.$role"
  printf '},"unknownCount":%s,"unknownDigest":"%s","snapshot":"%s"}' "$unknown_count" "$unknown_digest" "$snapshot"
}
printf '{"ok":true,"roles":{'
first_role=true
for role in devflow-lead devflow-triage devflow-locator devflow-coder devflow-tester devflow-reviewer; do
  $first_role || printf ','; first_role=false; emit_role "$role"
done
printf '}}\n'
"""


def _release_digest(value: Any) -> str | None:
    if isinstance(value, dict):
        candidate = value.get("archive_digest", value.get("digest"))
    else:
        candidate = getattr(value, "archive_digest", getattr(value, "digest", None))
    return candidate if isinstance(candidate, str) else None


def _validate_releases(releases: Mapping[str, Any]) -> None:
    if set(releases) != set(ROLE_SKILLS):
        raise ControllerCacheError("controller release set is incomplete")
    for role, expected in ARCHIVE_DIGESTS.items():
        release = releases[role]
        if _release_digest(release) != expected:
            raise ControllerCacheError("controller release identity is outside policy")
        archive = (
            release.get("archive")
            if isinstance(release, dict)
            else getattr(release, "archive", None)
        )
        if isinstance(archive, bytes) and hashlib.sha256(archive).hexdigest() != expected:
            raise ControllerCacheError("controller release bytes are outside policy")


def _exec_helper(kubectl: str, target: ControllerTarget) -> list[str]:
    return _kubectl(
        kubectl,
        "exec",
        "--stdin",
        target.pod_name,
        "--container",
        CONTAINER_NAME,
        "--",
        "/bin/sh",
        "-s",
    )


def _fixed_name_list(value: Any) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or item not in ALL_FIXED_SKILLS for item in value)
        or value != sorted(set(value))
    ):
        raise ControllerCacheError("controller helper returned invalid fixed Skill names")
    return tuple(value)


def _parse_reports(text: str) -> tuple[ControllerCacheReport, ...]:
    value = _json_object(text, "controller cache audit")
    if set(value) != {"ok", "roles"} or value.get("ok") is not True:
        raise ControllerCacheError("controller helper returned an unexpected summary")
    roles = _mapping(value.get("roles"), "controller role summaries")
    if set(roles) != set(ROLE_SKILLS):
        raise ControllerCacheError("controller helper omitted a fixed role")
    reports: list[ControllerCacheReport] = []
    fields = {
        "archiveSize",
        "archiveSha256",
        "archiveValid",
        "knownSkills",
        "stableSkillDigests",
        "unknownCount",
        "unknownDigest",
        "snapshot",
    }
    for role in ROLE_SKILLS:
        item = _mapping(roles[role], f"{role} cache summary")
        if set(item) != fields:
            raise ControllerCacheError("controller helper role summary schema is invalid")
        size = item.get("archiveSize")
        digest = item.get("archiveSha256")
        valid = item.get("archiveValid")
        unknown_count = item.get("unknownCount")
        unknown_digest = item.get("unknownDigest")
        snapshot = item.get("snapshot")
        known = _fixed_name_list(item.get("knownSkills"))
        stable = _mapping(item.get("stableSkillDigests"), "stable Skill digests")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > 64 * 1024 * 1024
            or not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
            or not isinstance(valid, bool)
            or valid is not (size == ARCHIVE_SIZES[role] and digest == ARCHIVE_DIGESTS[role])
            or isinstance(unknown_count, bool)
            or not isinstance(unknown_count, int)
            or unknown_count < 0
            or unknown_count > 20_000
            or not isinstance(unknown_digest, str)
            or DIGEST.fullmatch(unknown_digest) is None
            or not isinstance(snapshot, str)
            or DIGEST.fullmatch(snapshot) is None
            or set(stable) != set(known)
            or any(
                not isinstance(item_digest, str) or DIGEST.fullmatch(item_digest) is None
                for item_digest in stable.values()
            )
        ):
            raise ControllerCacheError("controller helper returned invalid cache evidence")
        reports.append(
            ControllerCacheReport(
                role=role,
                archive_size=size,
                archive_digest=digest,
                archive_valid=valid,
                known_skills=known,
                stable_skill_digests=tuple((name, stable[name]) for name in sorted(stable)),
                unknown_count=unknown_count,
                unknown_digest=unknown_digest,
                snapshot=snapshot,
            )
        )
    return tuple(reports)


def check_controller_authority(
    runner: Runner,
    target: ControllerTarget,
    releases: Mapping[str, Any],
    kubectl: str = "kubectl",
) -> tuple[ControllerCacheReport, ...]:
    """Read and validate all pinned archives and controller Skill caches once."""

    _validate_releases(releases)
    if target.image != CONTROLLER_IMAGE or target.image_id != CONTROLLER_IMAGE_ID:
        raise ControllerCacheError("controller target image identity changed")
    output = runner.run(
        _exec_helper(kubectl, target),
        CONTROLLER_AUDIT_HELPER.encode("utf-8"),
    )
    return _parse_reports(output)


CONTROLLER_PREPARE_HELPER = r"""#!/bin/sh
set -eu
export LC_ALL=C
umask 077
fail() { exit 70; }
txid=$1
case "$txid" in *[!0-9a-f]*|'') fail;; esac
[ "${#txid}" -eq 64 ] || fail
base=/root/hiclaw-fs
[ -d "$base" ] && [ ! -L "$base" ] || fail
[ "$(readlink -f "$base")" = "$base" ] || fail
[ "$(stat -c %u "$base")" = 0 ] && [ "$(stat -c %g "$base")" = 0 ] || fail
tx="$base/.devflow-role-skills-$txid"
if [ -e "$tx" ] || [ -L "$tx" ]; then
  [ -d "$tx" ] && [ ! -L "$tx" ] || fail
  [ "$(readlink -f "$tx")" = "$tx" ] || fail
  [ "$(stat -c %a "$tx")" = 700 ] || fail
else
  mkdir -m 700 "$tx" || fail
fi
[ "$(stat -c %u "$tx")" = 0 ] && [ "$(stat -c %g "$tx")" = 0 ] || fail
[ "$(stat -c %d "$tx")" = "$(stat -c %d "$base")" ] || fail
mkdir -p "$tx/stage" "$tx/quarantine" || fail
chmod 700 "$tx/stage" "$tx/quarantine" || fail
probe="$tx/.probe"
moved="$tx/.probe-moved"
[ ! -e "$probe" ] && [ ! -L "$probe" ] && [ ! -e "$moved" ] && [ ! -L "$moved" ] || fail
mkdir -m 700 "$probe" || fail
mv -nT "$probe" "$moved" || fail
[ ! -e "$probe" ] && [ -d "$moved" ] && [ ! -L "$moved" ] || fail
rmdir "$moved" || fail
sync
printf 'ok\n'
"""


CONTROLLER_ARCHIVE_REPLACE_HELPER = r"""set -eu
export LC_ALL=C
umask 077
fail() { exit 70; }
role=$1; expected_size=$2; expected_sha=$3; txid=$4
case "$role" in devflow-lead|devflow-triage|devflow-locator|devflow-coder|devflow-tester|devflow-reviewer) ;; *) fail;; esac
case "$expected_size" in *[!0-9]*|'') fail;; esac
case "$expected_sha" in *[!0-9a-f]*|'') fail;; esac
[ "${#expected_sha}" -eq 64 ] || fail
case "$txid" in *[!0-9a-f]*|'') fail;; esac
[ "${#txid}" -eq 64 ] || fail
base=/tmp/import
[ -d "$base" ] && [ ! -L "$base" ] && [ "$(readlink -f "$base")" = "$base" ] || fail
tx="$base/.devflow-role-skills-$txid"
if [ -e "$tx" ] || [ -L "$tx" ]; then
  [ -d "$tx" ] && [ ! -L "$tx" ] && [ "$(stat -c %a "$tx")" = 700 ] || fail
else
  mkdir -m 700 "$tx" || fail
fi
[ "$(stat -c %u "$tx")" = 0 ] && [ "$(stat -c %g "$tx")" = 0 ] || fail
[ "$(stat -c %d "$tx")" = "$(stat -c %d "$base")" ] || fail
stage="$tx/$role.new"; saved="$tx/$role.previous"; target="$base/$role-v2.0.0.zip"
[ ! -e "$stage" ] && [ ! -L "$stage" ] && [ ! -e "$saved" ] && [ ! -L "$saved" ] || fail
cat > "$stage" || fail
chmod 644 "$stage" || fail
[ "$(stat -c %s "$stage")" = "$expected_size" ] || fail
actual=$(sha256sum "$stage") || fail; actual=${actual%% *}; [ "$actual" = "$expected_sha" ] || fail
if [ -e "$target" ] || [ -L "$target" ]; then
  [ -f "$target" ] && [ ! -L "$target" ] && [ "$(stat -c %h "$target")" = 1 ] || fail
  cp -p "$target" "$saved" || fail
  [ -f "$saved" ] && [ ! -L "$saved" ] && [ "$(stat -c %h "$saved")" = 1 ] || fail
  mv -fT "$stage" "$target" || fail
else
  mv -nT "$stage" "$target" || fail
fi
[ -f "$target" ] && [ ! -L "$target" ] && [ "$(stat -c %h "$target")" = 1 ] || fail
[ "$(stat -c %u "$target")" = 0 ] && [ "$(stat -c %g "$target")" = 0 ] || fail
[ "$(stat -c %a "$target")" = 644 ] && [ "$(stat -c %s "$target")" = "$expected_size" ] || fail
actual=$(sha256sum "$target") || fail; actual=${actual%% *}; [ "$actual" = "$expected_sha" ] || fail
sync
printf 'ok\n'
"""


CONTROLLER_CONVERGE_HELPER = r"""#!/bin/sh
set -eu
export LC_ALL=C
umask 077
fail() { exit 70; }
role=$1; expected_size=$2; expected_sha=$3; txid=$4
case "$role" in
  devflow-lead) allowed='' ;;
  devflow-triage) allowed='issue-classifier' ;;
  devflow-locator) allowed='code-root-cause github-evidence' ;;
  devflow-coder) allowed='patch-generator' ;;
  devflow-tester) allowed='test-runner' ;;
  devflow-reviewer) allowed='experience-distiller pr-reviewer' ;;
  *) fail ;;
esac
case "$expected_size" in *[!0-9]*|'') fail;; esac
case "$expected_sha" in *[!0-9a-f]*|'') fail;; esac
[ "${#expected_sha}" -eq 64 ] || fail
case "$txid" in *[!0-9a-f]*|'') fail;; esac
[ "${#txid}" -eq 64 ] || fail
archive="/tmp/import/$role-v2.0.0.zip"
[ -f "$archive" ] && [ ! -L "$archive" ] && [ "$(stat -c %h "$archive")" = 1 ] || fail
[ "$(stat -c %u "$archive")" = 0 ] && [ "$(stat -c %g "$archive")" = 0 ] || fail
[ "$(stat -c %a "$archive")" = 644 ] && [ "$(stat -c %s "$archive")" = "$expected_size" ] || fail
actual=$(sha256sum "$archive") || fail; actual=${actual%% *}; [ "$actual" = "$expected_sha" ] || fail
root="/root/hiclaw-fs/agents/$role/skills"
[ -d "$root" ] && [ ! -L "$root" ] && [ "$(readlink -f "$root")" = "$root" ] || fail
[ "$(stat -c %u "$root")" = 0 ] && [ "$(stat -c %g "$root")" = 0 ] || fail
[ "$(stat -c %a "$root")" = 755 ] || fail
base=/root/hiclaw-fs; tx="$base/.devflow-role-skills-$txid"
[ -d "$tx" ] && [ ! -L "$tx" ] && [ "$(stat -c %a "$tx")" = 700 ] || fail
[ "$(stat -c %d "$tx")" = "$(stat -c %d "$root")" ] || fail
stage="$tx/stage/$role"; quarantine="$tx/quarantine/$role"
[ ! -e "$stage" ] && [ ! -L "$stage" ] && [ ! -e "$quarantine" ] && [ ! -L "$quarantine" ] || fail
mkdir -m 700 "$stage" "$quarantine" || fail
/bin/busybox unzip -q "$archive" -d "$stage" || fail
if [ -d "$stage/skills" ]; then
  find "$stage/skills" -type l -print | grep . >/dev/null && fail || true
  find "$stage/skills" -type d -exec chmod 755 {} + || fail
  find "$stage/skills" -type f -exec chmod 644 {} + || fail
  find "$stage/skills" ! -type d ! -type f -print | grep . >/dev/null && fail || true
fi
for skill in code-root-cause experience-distiller github-evidence issue-classifier patch-generator pr-reviewer test-runner; do
  source="$root/$skill"; destination="$quarantine/$skill"
  if [ -e "$source" ] || [ -L "$source" ]; then
    [ -d "$source" ] && [ ! -L "$source" ] && [ "$(stat -c %d "$source")" = "$(stat -c %d "$root")" ] || fail
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || fail
    mv -nT "$source" "$destination" || fail
    [ ! -e "$source" ] && [ -d "$destination" ] && [ ! -L "$destination" ] || fail
  fi
done
if [ -n "$allowed" ]; then
  [ -d "$stage/skills" ] && [ ! -L "$stage/skills" ] || fail
fi
for skill in $allowed; do
  source="$stage/skills/$skill"; destination="$root/$skill"
  [ -d "$source" ] && [ ! -L "$source" ] || fail
  [ ! -e "$destination" ] && [ ! -L "$destination" ] || fail
  mv -nT "$source" "$destination" || fail
  [ ! -e "$source" ] && [ -d "$destination" ] && [ ! -L "$destination" ] || fail
done
sync
printf 'ok\n'
"""


def _release_archive(value: Any) -> bytes | None:
    candidate = value.get("archive") if isinstance(value, dict) else getattr(value, "archive", None)
    return candidate if isinstance(candidate, bytes) else None


def expected_controller_skill_digests(
    releases: Mapping[str, Any],
) -> dict[str, dict[str, str]]:
    """Derive the BusyBox stable-tree digests from pinned release bytes."""

    _validate_releases(releases)
    result: dict[str, dict[str, str]] = {}
    for role, allowed in ROLE_SKILLS.items():
        archive = _release_archive(releases[role])
        if archive is None:
            raise ControllerCacheError("controller release bytes are required for convergence")
        role_digests: dict[str, str] = {}
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as package:
                names = package.namelist()
                for skill in allowed:
                    prefix = f"skills/{skill}/"
                    selected = sorted(name for name in names if name.startswith(prefix))
                    if not selected or any(name.endswith("/") for name in selected):
                        raise ControllerCacheError("controller release Skill entries are invalid")
                    directories = {"."}
                    records: list[str] = []
                    for name in selected:
                        relative = name.removeprefix(prefix)
                        path = PurePosixPath(relative)
                        if (
                            not relative
                            or path.is_absolute()
                            or path.as_posix() != relative
                            or any(
                                not component
                                or re.fullmatch(r"[A-Za-z0-9._-]{1,255}", component) is None
                                for component in path.parts
                            )
                        ):
                            raise ControllerCacheError("controller release Skill path is unsafe")
                        parent = path.parent
                        while parent.as_posix() != ".":
                            directories.add(parent.as_posix())
                            parent = parent.parent
                        data = package.read(name)
                        records.append(
                            "F\t"
                            f"{relative}\t644\t0\t0\t{len(data)}\t"
                            f"{hashlib.sha256(data).hexdigest()}\n"
                        )
                    records.extend(f"D\t{directory}\t755\t0\t0\n" for directory in directories)
                    role_digests[skill] = hashlib.sha256(
                        "".join(sorted(records)).encode("utf-8")
                    ).hexdigest()
        except (OSError, zipfile.BadZipFile, KeyError) as exc:
            raise ControllerCacheError("controller release archive cannot be inspected") from exc
        if set(role_digests) != set(allowed):
            raise ControllerCacheError("controller release allowlist is incomplete")
        result[role] = role_digests
    return result


def _controller_drift_roles(
    reports: tuple[ControllerCacheReport, ...],
    expected: Mapping[str, Mapping[str, str]],
) -> tuple[str, ...]:
    drift: list[str] = []
    for report in reports:
        stable = dict(report.stable_skill_digests)
        if (
            not report.archive_valid
            or report.known_skills != tuple(sorted(ROLE_SKILLS[report.role]))
            or stable != dict(expected[report.role])
        ):
            drift.append(report.role)
    return tuple(sorted(drift))


def _script_exec(
    kubectl: str,
    target: ControllerTarget,
    *args: str,
) -> list[str]:
    return _kubectl(
        kubectl,
        "exec",
        "--stdin",
        target.pod_name,
        "--container",
        CONTAINER_NAME,
        "--",
        "/bin/sh",
        "-s",
        "--",
        *args,
    )


def _archive_exec(
    kubectl: str,
    target: ControllerTarget,
    role: str,
    transaction_id: str,
) -> list[str]:
    return _kubectl(
        kubectl,
        "exec",
        "--stdin",
        target.pod_name,
        "--container",
        CONTAINER_NAME,
        "--",
        "/bin/sh",
        "-c",
        CONTROLLER_ARCHIVE_REPLACE_HELPER,
        "--",
        role,
        str(ARCHIVE_SIZES[role]),
        ARCHIVE_DIGESTS[role],
        transaction_id,
    )


def _transaction_id(
    target: ControllerTarget,
    reports: tuple[ControllerCacheReport, ...],
) -> str:
    material = "|".join(
        [
            target.pod_uid,
            str(target.restart_count),
            *(f"{report.role}:{report.snapshot}" for report in reports),
        ]
    )
    return hashlib.sha256(material.encode("ascii")).hexdigest()


def reconcile_controller_authority(
    runner: Runner,
    target: ControllerTarget,
    releases: Mapping[str, Any],
    *,
    kubectl: str = "kubectl",
    apply: bool = False,
) -> ControllerReconcileResult:
    """Attest and optionally converge both pinned controller cache layers."""

    expected = expected_controller_skill_digests(releases)
    first = check_controller_authority(runner, target, releases, kubectl)
    drift = _controller_drift_roles(first, expected)
    if not apply or not drift:
        return ControllerReconcileResult(target, first, drift, None)

    barrier_target = discover_controller(runner, kubectl)
    barrier = check_controller_authority(runner, barrier_target, releases, kubectl)
    if barrier_target != target or barrier != first:
        raise ControllerCacheError("controller authority changed during the apply barrier")
    transaction_id = _transaction_id(target, first)
    prepared = runner.run(
        _script_exec(kubectl, target, transaction_id),
        CONTROLLER_PREPARE_HELPER.encode("utf-8"),
    )
    if prepared != "ok\n":
        raise ControllerCacheError("controller transaction preparation failed")

    for report in first:
        if report.archive_valid:
            continue
        archive = _release_archive(releases[report.role])
        if archive is None:
            raise ControllerCacheError("controller release bytes are required for convergence")
        response = runner.run(
            _archive_exec(kubectl, target, report.role, transaction_id),
            archive,
        )
        if response != "ok\n":
            raise ControllerCacheError("controller archive replacement failed")

    after_archives = check_controller_authority(runner, target, releases, kubectl)
    first_by_role = {report.role: report for report in first}
    for report in after_archives:
        before = first_by_role[report.role]
        if (
            not report.archive_valid
            or report.known_skills != before.known_skills
            or report.stable_skill_digests != before.stable_skill_digests
            or report.unknown_count != before.unknown_count
            or report.unknown_digest != before.unknown_digest
        ):
            raise ControllerCacheError("controller archive convergence changed the Skill cache")

    for report in after_archives:
        stable = dict(report.stable_skill_digests)
        if (
            report.known_skills == tuple(sorted(ROLE_SKILLS[report.role]))
            and stable == expected[report.role]
        ):
            continue
        response = runner.run(
            _script_exec(
                kubectl,
                target,
                report.role,
                str(ARCHIVE_SIZES[report.role]),
                ARCHIVE_DIGESTS[report.role],
                transaction_id,
            ),
            CONTROLLER_CONVERGE_HELPER.encode("utf-8"),
        )
        if response != "ok\n":
            raise ControllerCacheError("controller Skill cache convergence failed")

    final_target = discover_controller(runner, kubectl)
    final = check_controller_authority(runner, final_target, releases, kubectl)
    if final_target != target:
        raise ControllerCacheError("controller runtime identity changed during convergence")
    final_by_role = {report.role: report for report in final}
    for before in first:
        current = final_by_role[before.role]
        if (
            not current.archive_valid
            or current.known_skills != tuple(sorted(ROLE_SKILLS[current.role]))
            or dict(current.stable_skill_digests) != expected[current.role]
            or current.unknown_count != before.unknown_count
            or current.unknown_digest != before.unknown_digest
        ):
            raise ControllerCacheError("controller authority did not converge safely")
    return ControllerReconcileResult(target, final, drift, transaction_id)
