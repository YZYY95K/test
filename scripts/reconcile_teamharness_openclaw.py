#!/usr/bin/env python3
"""Reconcile the guarded TeamHarness overlay after a DevFlow Team rebuild.

This host-side utility uses only existing ``get`` and ``pods/exec`` access. It
does not read Secrets, print remote configuration, create Kubernetes objects,
or modify RBAC. All six role Pods and all local sources are validated before
the first remote write.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = "agentteams-system"
TEAM_NAME = "devflow-swe"
CONTAINER_NAME = "worker"
TEAM_LABEL = "agentteams.io/team"
WORKER_LABEL = "agentteams.io/worker"
RUNTIME_LABEL = "agentteams.io/runtime"
EXPECTED_ROLES = frozenset(
    {
        "devflow-lead",
        "devflow-triage",
        "devflow-locator",
        "devflow-coder",
        "devflow-tester",
        "devflow-reviewer",
    }
)
LEADER_ROLE = "devflow-lead"
LEADER_SERVICE_ACCOUNT = "agentteams-worker-devflow-lead"
GITHUB_ISSUER_AUDIENCE = "agentteams-controller"
SERVICE_ACCOUNT_TOKEN_VOLUME = "agentteams-token"
SERVICE_ACCOUNT_TOKEN_MOUNT = "/var/run/secrets/agentteams"
SERVICE_ACCOUNT_TOKEN_PATH = "/var/run/secrets/agentteams/token"
REMOTE_STAGE = "/tmp/devflow-teamharness-reconcile-v1"
REQUIRED_MCP_FILES = ("server.py", "message_tool.py", "roomflow_tool.py")
UPSTREAM_AGENTTEAMS_COMMIT = "78d0ceda336befa6e62bf89fc1a6b08b965e128d"
UPSTREAM_FILE_SHA256 = {
    "plugin.yaml": "40121114d1f2a5897e90e21f819f34491bd8062eae25634825f9e7b50b61d518",
    "mcp/server.py": "cb9971baae3545f440821ecf1fd18c76078962a1fe1591141cc88026bf5b684f",
    "mcp/message_tool.py": "03e8fcfcaf002c5d9dd0c023b85bd4d2f4641b83cb59c6d89be08a9c1689c47c",
    "mcp/roomflow_tool.py": "db127d550cf9155c133657ab7c89fee48292c07587a061954bd60b4c14991680",
}
PLUGIN_RELATIVE = PurePosixPath("plugins/teamharness")
OVERLAY_FILES = (
    PurePosixPath("scripts/teamharness_openclaw.py"),
    PurePosixPath("agentteams/teamharness/guarded_server.py"),
)
APPROVAL_PUBLIC_KEY_NAME = "approval-ed25519.pub"
RUNTIME_BINDING_NAME = "runtime-binding.json"
RUNTIME_CONFIG_NAME = "runtime-config.yaml"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?$")
REMOTE_HASH_CHECK = """
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
expected = json.loads(sys.argv[2])
if not isinstance(expected, dict):
    raise SystemExit("invalid integrity policy")
for relative, digest in expected.items():
    path = root.joinpath(*relative.split("/"))
    if not path.is_file() or path.is_symlink():
        raise SystemExit("missing staged source")
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise SystemExit("staged source integrity mismatch")
""".strip()


class ReconcileError(RuntimeError):
    """A discovery, source-integrity, or remote verification gate failed."""


def _safe_command_label(args: list[str]) -> str:
    """Describe a failed command without echoing payloads or policy values."""

    executable = Path(args[0]).name if args else "command"
    if executable != "kubectl":
        return executable
    if "exec" not in args:
        operation = next((item for item in ("version", "get") if item in args), "command")
        return f"kubectl {operation}"
    index = args.index("exec") + 1
    if index < len(args) and args[index] == "--stdin":
        index += 1
    pod = args[index] if index < len(args) and DNS_LABEL.fullmatch(args[index]) else "pod"
    operation = "exec"
    if "--" in args:
        command_index = args.index("--") + 1
        if command_index < len(args):
            operation = Path(args[command_index]).name
        for action in ("install", "verify"):
            if action in args[command_index + 1 :]:
                operation = action
                break
    return f"kubectl exec {pod} {operation}"


class Runner(Protocol):
    def run(self, args: list[str], *, input_data: bytes | None = None) -> str: ...


class SubprocessRunner:
    """Run commands without a shell and suppress their potentially sensitive output."""

    def run(self, args: list[str], *, input_data: bytes | None = None) -> str:
        try:
            process = subprocess.run(
                args,
                input=input_data,
                check=False,
                capture_output=True,
                text=input_data is None,
            )
        except OSError as exc:
            raise ReconcileError(
                f"unable to invoke required command: {_safe_command_label(args)}"
            ) from exc
        if process.returncode != 0:
            raise ReconcileError(
                "command failed without applying a success claim: "
                + _safe_command_label(args)
            )
        stdout = process.stdout
        if isinstance(stdout, bytes):
            try:
                return stdout.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ReconcileError("command returned non-UTF-8 output") from exc
        if isinstance(stdout, str):
            return stdout
        raise ReconcileError("command returned an unsupported output type")


@dataclass(frozen=True, order=True)
class Target:
    role_name: str
    member_name: str
    matrix_user_id: str
    pod_name: str

    @property
    def teamharness_role(self) -> str:
        return "leader" if self.role_name == LEADER_ROLE else "worker"

    @property
    def workspace(self) -> str:
        return f"/root/hiclaw-fs/agents/{self.role_name}"

    @property
    def runtime_binding(self) -> dict[str, str]:
        return {
            "schemaVersion": "1.0",
            "teamName": TEAM_NAME,
            "memberName": self.member_name,
            "runtimeName": self.role_name,
            "podName": self.pod_name,
            "teamHarnessRole": self.teamharness_role,
        }

    @property
    def sanitized_runtime_config(self) -> dict[str, str]:
        """Return public identity fields attested by Team status only."""

        return {
            "role": self.teamharness_role,
            "runtimeName": self.role_name,
            "matrixUserId": self.matrix_user_id,
        }


@dataclass(frozen=True)
class SourceBundle:
    plugin_dir: Path
    plugin_files: tuple[Path, ...]
    plugin_hashes: dict[str, str]
    overlay_hashes: dict[str, str]
    approval_public_key: bytes
    approval_public_key_sha256: str


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReconcileError(f"{label} is malformed")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReconcileError(f"{label} is malformed")
    return value


def _safe_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not DNS_LABEL.fullmatch(value):
        raise ReconcileError(f"{label} is missing or unsafe")
    return value


def _safe_matrix_user_id(value: Any, runtime_name: str) -> str:
    if not isinstance(value, str):
        raise ReconcileError("Team status Matrix identity is missing or unsafe")
    match = re.fullmatch(r"@([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?):([^:\s]+)", value)
    if match is None or match.group(1) != runtime_name:
        raise ReconcileError("Team status Matrix identity is missing or unsafe")
    return value


def _ready_condition(document: dict[str, Any]) -> bool:
    status = _object(document.get("status"), "Pod status")
    conditions = _list(status.get("conditions"), "Pod conditions")
    ready = [
        condition
        for condition in conditions
        if isinstance(condition, dict) and condition.get("type") == "Ready"
    ]
    return len(ready) == 1 and ready[0].get("status") == "True"


def _worker_container_ready(document: dict[str, Any]) -> bool:
    spec = _object(document.get("spec"), "Pod spec")
    containers = _list(spec.get("containers"), "Pod containers")
    if (
        sum(
            1
            for container in containers
            if isinstance(container, dict) and container.get("name") == CONTAINER_NAME
        )
        != 1
    ):
        return False
    status = _object(document.get("status"), "Pod status")
    container_statuses = _list(status.get("containerStatuses"), "Pod container statuses")
    worker_statuses = [
        item
        for item in container_statuses
        if isinstance(item, dict) and item.get("name") == CONTAINER_NAME
    ]
    return len(worker_statuses) == 1 and worker_statuses[0].get("ready") is True


def _leader_has_github_issuer_token(document: dict[str, Any]) -> bool:
    """Verify the controller-owned, rotating audience-bound token projection."""

    spec = _object(document.get("spec"), "Pod spec")
    if (
        spec.get("serviceAccountName") != LEADER_SERVICE_ACCOUNT
        or spec.get("automountServiceAccountToken") is not False
    ):
        return False
    volumes = _list(spec.get("volumes"), "Pod volumes")
    token_volumes = [
        volume
        for volume in volumes
        if isinstance(volume, dict) and volume.get("name") == SERVICE_ACCOUNT_TOKEN_VOLUME
    ]
    if len(token_volumes) != 1:
        return False
    projected = token_volumes[0].get("projected")
    if not isinstance(projected, dict):
        return False
    sources = projected.get("sources")
    if not isinstance(sources, list) or len(sources) != 1:
        return False
    projection = sources[0].get("serviceAccountToken") if isinstance(sources[0], dict) else None
    if not isinstance(projection, dict):
        return False
    expiration = projection.get("expirationSeconds")
    if (
        set(projection) != {"audience", "expirationSeconds", "path"}
        or projection.get("audience") != GITHUB_ISSUER_AUDIENCE
        or projection.get("path") != "token"
        or isinstance(expiration, bool)
        or not isinstance(expiration, int)
        or not 600 <= expiration <= 3600
    ):
        return False
    containers = _list(spec.get("containers"), "Pod containers")
    worker = [
        container
        for container in containers
        if isinstance(container, dict) and container.get("name") == CONTAINER_NAME
    ]
    if len(worker) != 1:
        return False
    mounts = worker[0].get("volumeMounts")
    if not isinstance(mounts, list):
        return False
    token_mounts = [
        mount
        for mount in mounts
        if isinstance(mount, dict) and mount.get("name") == SERVICE_ACCOUNT_TOKEN_VOLUME
    ]
    return len(token_mounts) == 1 and token_mounts[0] == {
        "name": SERVICE_ACCOUNT_TOKEN_VOLUME,
        "mountPath": SERVICE_ACCOUNT_TOKEN_MOUNT,
        "readOnly": True,
    }


def discover_targets(team: dict[str, Any], pods: dict[str, Any]) -> list[Target]:
    """Return exactly six unique, active, Ready role Pods or fail closed."""

    metadata = _object(team.get("metadata"), "Team metadata")
    spec = _object(team.get("spec"), "Team spec")
    if (
        team.get("apiVersion") != "agentteams.io/v1beta1"
        or team.get("kind") != "Team"
        or metadata.get("name") != TEAM_NAME
        or metadata.get("namespace") != NAMESPACE
    ):
        raise ReconcileError("Team identity does not match the fixed DevFlow target")
    leader = _object(spec.get("leader"), "Team leader")
    workers = _list(spec.get("workers"), "Team workers")
    declared_roles = {_safe_name(leader.get("name"), "Team leader name")}
    for worker in workers:
        declared_roles.add(
            _safe_name(_object(worker, "Team worker").get("name"), "Team worker name")
        )
    if declared_roles != EXPECTED_ROLES or len(workers) != 5:
        raise ReconcileError("Team must declare exactly the six DevFlow roles")

    status = _object(team.get("status"), "Team status")
    members = _list(status.get("members"), "Team status members")
    member_to_role: dict[str, tuple[str, str]] = {}
    seen_roles: set[str] = set()
    for value in members:
        member = _object(value, "Team status member")
        member_name = _safe_name(member.get("name"), "Team status member name")
        role_name = _safe_name(member.get("runtimeName"), "Team status runtime name")
        matrix_user_id = _safe_matrix_user_id(member.get("matrixUserID"), role_name)
        if member_name in member_to_role or role_name in seen_roles:
            raise ReconcileError("Team status contains a duplicate member or runtime role")
        member_to_role[member_name] = (role_name, matrix_user_id)
        seen_roles.add(role_name)
    if seen_roles != EXPECTED_ROLES or len(member_to_role) != 6:
        raise ReconcileError("Team status must resolve exactly the six DevFlow roles")

    # kubectl can serialize the core-v1 collection as the generic ``List``
    # kind. Accept only the two observed collection spellings, then validate
    # every item's apiVersion and kind below.
    if pods.get("apiVersion") != "v1" or pods.get("kind") not in {"List", "PodList"}:
        raise ReconcileError("Pod discovery response is malformed")
    active = []
    for value in _list(pods.get("items"), "Pod items"):
        pod = _object(value, "Pod")
        if pod.get("apiVersion") != "v1" or pod.get("kind") != "Pod":
            raise ReconcileError("Pod discovery item has an unexpected type")
        pod_metadata = _object(pod.get("metadata"), "Pod metadata")
        if pod_metadata.get("deletionTimestamp"):
            continue
        active.append(pod)
    if len(active) != 6:
        raise ReconcileError("expected exactly six active OpenClaw role Pods")

    targets: list[Target] = []
    seen_target_roles: set[str] = set()
    for pod in active:
        pod_metadata = _object(pod.get("metadata"), "Pod metadata")
        labels = _object(pod_metadata.get("labels"), "Pod labels")
        pod_name = _safe_name(pod_metadata.get("name"), "Pod name")
        member_name = _safe_name(labels.get(WORKER_LABEL), "Pod member label")
        if (
            pod_metadata.get("namespace") != NAMESPACE
            or labels.get(TEAM_LABEL) != TEAM_NAME
            or labels.get(RUNTIME_LABEL) != "openclaw"
            or member_name not in member_to_role
        ):
            raise ReconcileError("Pod identity is outside the fixed DevFlow OpenClaw Team")
        role_name, matrix_user_id = member_to_role[member_name]
        status = _object(pod.get("status"), "Pod status")
        if (
            status.get("phase") != "Running"
            or not _ready_condition(pod)
            or not _worker_container_ready(pod)
        ):
            raise ReconcileError(f"role Pod is not Ready: {role_name}")
        if role_name == LEADER_ROLE and not _leader_has_github_issuer_token(pod):
            raise ReconcileError(
                "Leader Pod lacks the fixed audience-bound issuer token projection"
            )
        if role_name in seen_target_roles:
            raise ReconcileError(f"duplicate active Pod for role: {role_name}")
        seen_target_roles.add(role_name)
        targets.append(Target(role_name, member_name, matrix_user_id, pod_name))
    if seen_target_roles != EXPECTED_ROLES:
        raise ReconcileError("ready Pod roles do not match the six DevFlow roles")
    return sorted(targets)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _hash_policy(test_hash_policy: dict[str, str] | None) -> dict[str, str]:
    policy = dict(UPSTREAM_FILE_SHA256 if test_hash_policy is None else test_hash_policy)
    if set(policy) != set(UPSTREAM_FILE_SHA256) or any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
        for value in policy.values()
    ):
        raise ReconcileError("TeamHarness source policy is incomplete or malformed")
    return policy


def _approval_public_key(path: Path) -> tuple[bytes, str]:
    """Load one canonical Ed25519 SubjectPublicKeyInfo PEM, never a private key."""

    path = path.resolve()
    if not path.is_file() or path.is_symlink():
        raise ReconcileError("approval public key is missing or unsafe")
    try:
        payload = path.read_bytes()
        lines = payload.decode("ascii").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ReconcileError("approval public key is not canonical ASCII PEM") from exc
    if (
        len(lines) != 3
        or lines[0] != "-----BEGIN PUBLIC KEY-----"
        or lines[2] != "-----END PUBLIC KEY-----"
        or not lines[1]
    ):
        raise ReconcileError("approval public key is not canonical public-key PEM")
    try:
        der = base64.b64decode(lines[1], validate=True)
    except ValueError as exc:
        raise ReconcileError("approval public key contains invalid base64") from exc
    canonical = (
        f"-----BEGIN PUBLIC KEY-----\n{base64.b64encode(der).decode('ascii')}\n"
        "-----END PUBLIC KEY-----\n"
    ).encode("ascii")
    if payload != canonical or len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
        raise ReconcileError("approval public key is not canonical Ed25519 SPKI")
    return payload, hashlib.sha256(payload).hexdigest()


def validate_sources(
    runner: Runner,
    agentteams_repo: Path,
    devflow_repo: Path,
    approval_public_key: Path,
    *,
    _test_hash_policy: dict[str, str] | None = None,
) -> SourceBundle:
    """Validate the fixed upstream checkout and exact local overlay sources."""

    agentteams_repo = agentteams_repo.resolve()
    devflow_repo = devflow_repo.resolve()
    if not agentteams_repo.is_dir() or not devflow_repo.is_dir():
        raise ReconcileError("source repository directory is missing")
    commit = runner.run(["git", "-C", str(agentteams_repo), "rev-parse", "HEAD"]).strip()
    if commit != UPSTREAM_AGENTTEAMS_COMMIT:
        raise ReconcileError("AgentTeams checkout is not the pinned upstream commit")
    drift = runner.run(
        [
            "git",
            "-C",
            str(agentteams_repo),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            PLUGIN_RELATIVE.as_posix(),
        ]
    )
    if drift.strip():
        raise ReconcileError("TeamHarness source tree differs from the pinned commit")
    tracked_output = runner.run(
        [
            "git",
            "-C",
            str(agentteams_repo),
            "ls-files",
            "-z",
            "--",
            PLUGIN_RELATIVE.as_posix(),
        ]
    )
    tracked = [item for item in tracked_output.split("\x00") if item]
    prefix = f"{PLUGIN_RELATIVE.as_posix()}/"
    if not tracked or any(not item.startswith(prefix) for item in tracked):
        raise ReconcileError("tracked TeamHarness file list is empty or malformed")
    plugin_dir = agentteams_repo.joinpath(*PLUGIN_RELATIVE.parts)
    plugin_files: list[Path] = []
    for item in sorted(set(tracked)):
        relative = PurePosixPath(item.removeprefix(prefix))
        path = plugin_dir.joinpath(*relative.parts)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not path.is_file()
            or path.is_symlink()
        ):
            raise ReconcileError("tracked TeamHarness source contains an unsafe file")
        plugin_files.append(path)

    policy = _hash_policy(_test_hash_policy)
    plugin_hashes = {
        path.relative_to(plugin_dir).as_posix(): _sha256(path) for path in plugin_files
    }
    for relative_key, expected in policy.items():
        path = plugin_dir.joinpath(*PurePosixPath(relative_key).parts)
        if not path.is_file() or path.is_symlink() or plugin_hashes.get(relative_key) != expected:
            raise ReconcileError(f"TeamHarness source integrity mismatch: {relative_key}")
    required = {"plugin.yaml", *(f"mcp/{name}" for name in REQUIRED_MCP_FILES)}
    relative_files = {path.relative_to(plugin_dir).as_posix() for path in plugin_files}
    if not required <= relative_files:
        raise ReconcileError("tracked TeamHarness source omits a critical file")
    if runner.run(
        [
            "git",
            "-C",
            str(agentteams_repo),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            PLUGIN_RELATIVE.as_posix(),
        ]
    ).strip():
        raise ReconcileError("TeamHarness source changed during validation")

    overlay_hashes: dict[str, str] = {}
    for relative in OVERLAY_FILES:
        path = devflow_repo.joinpath(*relative.parts)
        if not path.is_file() or path.is_symlink():
            raise ReconcileError(f"DevFlow overlay source is missing: {relative}")
        overlay_hashes[relative.as_posix()] = _sha256(path)
    public_key, public_key_sha256 = _approval_public_key(approval_public_key)
    return SourceBundle(
        plugin_dir=plugin_dir,
        plugin_files=tuple(plugin_files),
        plugin_hashes=plugin_hashes,
        overlay_hashes=overlay_hashes,
        approval_public_key=public_key,
        approval_public_key_sha256=public_key_sha256,
    )


def _tar_files(root: Path, files: tuple[Path, ...]) -> bytes:
    """Create a deterministic archive containing only validated regular files."""

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(files):
            relative = path.relative_to(root)
            if path.is_symlink() or not path.is_file():
                raise ReconcileError("source changed while preparing the archive")
            try:
                payload = path.read_bytes()
                executable = bool(path.stat().st_mode & 0o111)
            except OSError as exc:
                raise ReconcileError("source changed while preparing the archive") from exc
            info = tarfile.TarInfo(relative.as_posix())
            info.size = len(payload)
            info.mode = 0o755 if executable else 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _tar_public_key(payload: bytes) -> bytes:
    """Create the deterministic, public-only approval-policy archive."""

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo(APPROVAL_PUBLIC_KEY_NAME)
        info.size = len(payload)
        info.mode = 0o444
        info.mtime = 0
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _tar_runtime_binding(target: Target) -> tuple[bytes, str]:
    payload = (json.dumps(target.runtime_binding, indent=2, sort_keys=True) + "\n").encode("utf-8")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo(RUNTIME_BINDING_NAME)
        info.size = len(payload)
        info.mode = 0o444
        info.mtime = 0
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue(), hashlib.sha256(payload).hexdigest()


def _tar_runtime_config(target: Target) -> tuple[bytes, str]:
    """Stage a credential-free runtime identity derived from Team status."""

    identity = target.sanitized_runtime_config
    payload = (
        f"role: {identity['role']}\n"
        f"runtimeName: {identity['runtimeName']}\n"
        f"matrixUserId: {identity['matrixUserId']}\n"
    ).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo(RUNTIME_CONFIG_NAME)
        info.size = len(payload)
        info.mode = 0o444
        info.mtime = 0
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue(), hashlib.sha256(payload).hexdigest()


def _kubectl(kubectl: str, *args: str) -> list[str]:
    return [kubectl, "--namespace", NAMESPACE, *args]


def _exec(
    kubectl: str,
    target: Target,
    *args: str,
    stdin: bool = False,
) -> list[str]:
    command = _kubectl(kubectl, "exec")
    if stdin:
        command.append("--stdin")
    command.extend(
        [
            target.pod_name,
            "--container",
            CONTAINER_NAME,
            "--",
            *args,
        ]
    )
    return command


def _remote_preflight(runner: Runner, kubectl: str, target: Target) -> None:
    script = """
set -eu
expected=$1
test "${HOME:?HOME is required}" = "$expected"
test "$PWD" = "$expected"
test -f "$expected/runtime/runtime.json"
test "$(cat /etc/hostname)" = "$2"
command -v python3 >/dev/null
command -v tar >/dev/null
command -v openssl >/dev/null
if [ "$3" = "leader" ]; then
  test -s "/var/run/secrets/agentteams/token"
fi
""".strip()
    runner.run(
        _exec(
            kubectl,
            target,
            "/bin/sh",
            "-eu",
            "-c",
            script,
            "devflow-teamharness-preflight",
            target.workspace,
            target.pod_name,
            target.teamharness_role,
        )
    )


def _stage_sources(
    runner: Runner,
    kubectl: str,
    target: Target,
    plugin_archive: bytes,
    overlay_archive: bytes,
    approval_archive: bytes,
    runtime_binding_archive: bytes,
    runtime_config_archive: bytes,
    plugin_hashes: dict[str, str],
    overlay_hashes: dict[str, str],
    approval_public_key_sha256: str,
    runtime_binding_sha256: str,
    runtime_config_sha256: str,
) -> None:
    reset = f"""
set -eu
stage={REMOTE_STAGE}
test "$stage" = "{REMOTE_STAGE}"
rm -rf -- "$stage"
mkdir -p -- "$stage/plugin" "$stage/overlay" "$stage/policy" "$stage/identity"
""".strip()
    runner.run(_exec(kubectl, target, "/bin/sh", "-eu", "-c", reset))
    runner.run(
        _exec(
            kubectl,
            target,
            "tar",
            "-xf",
            "-",
            "-C",
            f"{REMOTE_STAGE}/plugin",
            stdin=True,
        ),
        input_data=plugin_archive,
    )
    runner.run(
        _exec(
            kubectl,
            target,
            "tar",
            "-xf",
            "-",
            "-C",
            f"{REMOTE_STAGE}/overlay",
            stdin=True,
        ),
        input_data=overlay_archive,
    )
    runner.run(
        _exec(
            kubectl,
            target,
            "tar",
            "-xf",
            "-",
            "-C",
            f"{REMOTE_STAGE}/policy",
            stdin=True,
        ),
        input_data=approval_archive,
    )
    runner.run(
        _exec(
            kubectl,
            target,
            "tar",
            "-xf",
            "-",
            "-C",
            f"{REMOTE_STAGE}/identity",
            stdin=True,
        ),
        input_data=runtime_binding_archive,
    )
    runner.run(
        _exec(
            kubectl,
            target,
            "tar",
            "-xf",
            "-",
            "-C",
            f"{REMOTE_STAGE}/identity",
            stdin=True,
        ),
        input_data=runtime_config_archive,
    )
    runner.run(
        _exec(
            kubectl,
            target,
            "python3",
            "-c",
            REMOTE_HASH_CHECK,
            f"{REMOTE_STAGE}/plugin",
            json.dumps(plugin_hashes, sort_keys=True, separators=(",", ":")),
        )
    )
    runner.run(
        _exec(
            kubectl,
            target,
            "python3",
            "-c",
            REMOTE_HASH_CHECK,
            f"{REMOTE_STAGE}/identity",
            json.dumps(
                {
                    RUNTIME_BINDING_NAME: runtime_binding_sha256,
                    RUNTIME_CONFIG_NAME: runtime_config_sha256,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    )
    runner.run(
        _exec(
            kubectl,
            target,
            "python3",
            "-c",
            REMOTE_HASH_CHECK,
            f"{REMOTE_STAGE}/overlay",
            json.dumps(overlay_hashes, sort_keys=True, separators=(",", ":")),
        )
    )
    runner.run(
        _exec(
            kubectl,
            target,
            "python3",
            "-c",
            REMOTE_HASH_CHECK,
            f"{REMOTE_STAGE}/policy",
            json.dumps(
                {APPROVAL_PUBLIC_KEY_NAME: approval_public_key_sha256},
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    )
    runner.run(
        _exec(
            kubectl,
            target,
            "/usr/bin/openssl",
            "pkey",
            "-pubin",
            "-in",
            f"{REMOTE_STAGE}/policy/{APPROVAL_PUBLIC_KEY_NAME}",
            "-text",
            "-noout",
        )
    )


def _install_and_verify(runner: Runner, kubectl: str, target: Target) -> None:
    adapter = f"{REMOTE_STAGE}/overlay/scripts/teamharness_openclaw.py"
    common = [
        "--workspace",
        target.workspace,
        "--role",
        target.teamharness_role,
    ]
    approval_args = (
        [
            "--approval-public-key",
            f"{REMOTE_STAGE}/policy/{APPROVAL_PUBLIC_KEY_NAME}",
        ]
        if target.role_name == LEADER_ROLE
        else []
    )
    runner.run(
        _exec(
            kubectl,
            target,
            "python3",
            adapter,
            "install",
            "--plugin-dir",
            f"{REMOTE_STAGE}/plugin",
            *common,
            "--runtime-config",
            f"{REMOTE_STAGE}/identity/{RUNTIME_CONFIG_NAME}",
            "--runtime-binding",
            f"{REMOTE_STAGE}/identity/{RUNTIME_BINDING_NAME}",
            *approval_args,
            "--replace",
        )
    )
    runner.run(
        _exec(
            kubectl,
            target,
            "python3",
            adapter,
            "verify",
            *common,
        )
    )


def reconcile(
    runner: Runner,
    *,
    kubectl: str,
    agentteams_repo: Path,
    approval_public_key: Path,
    devflow_repo: Path = ROOT,
    _test_hash_policy: dict[str, str] | None = None,
) -> list[Target]:
    """Run discovery, source preflight, staging, installation, and verification."""

    runner.run([kubectl, "version", "--request-timeout=10s"])
    team_text = runner.run(_kubectl(kubectl, "get", "team", TEAM_NAME, "--output", "json"))
    pods_text = runner.run(
        _kubectl(
            kubectl,
            "get",
            "pods",
            "--selector",
            f"{TEAM_LABEL}={TEAM_NAME},{RUNTIME_LABEL}=openclaw",
            "--output",
            "json",
        )
    )
    try:
        team = json.loads(team_text)
        pods = json.loads(pods_text)
    except json.JSONDecodeError as exc:
        raise ReconcileError("Kubernetes discovery returned malformed JSON") from exc
    if not isinstance(team, dict) or not isinstance(pods, dict):
        raise ReconcileError("Kubernetes discovery documents must be objects")
    targets = discover_targets(team, pods)
    sources = validate_sources(
        runner,
        agentteams_repo,
        devflow_repo,
        approval_public_key,
        _test_hash_policy=_test_hash_policy,
    )
    plugin_archive = _tar_files(sources.plugin_dir, sources.plugin_files)
    overlay_paths = tuple(
        devflow_repo.resolve().joinpath(*relative.parts) for relative in OVERLAY_FILES
    )
    overlay_archive = _tar_files(devflow_repo.resolve(), overlay_paths)
    approval_archive = _tar_public_key(sources.approval_public_key)

    # Preflight every role before staging or installing into any Pod.
    for target in targets:
        _remote_preflight(runner, kubectl, target)
    for target in targets:
        runtime_binding_archive, runtime_binding_sha256 = _tar_runtime_binding(target)
        runtime_config_archive, runtime_config_sha256 = _tar_runtime_config(target)
        _stage_sources(
            runner,
            kubectl,
            target,
            plugin_archive,
            overlay_archive,
            approval_archive,
            runtime_binding_archive,
            runtime_config_archive,
            sources.plugin_hashes,
            sources.overlay_hashes,
            sources.approval_public_key_sha256,
            runtime_binding_sha256,
            runtime_config_sha256,
        )
    for target in targets:
        _install_and_verify(runner, kubectl, target)
    return targets


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reconcile the guarded TeamHarness overlay onto six DevFlow role Pods."
    )
    parser.add_argument(
        "--agentteams-repo",
        type=Path,
        required=True,
        help="local AgentTeams checkout at the pinned upstream commit",
    )
    parser.add_argument(
        "--devflow-repo",
        type=Path,
        default=ROOT,
        help="local DevFlow repository containing the guarded overlay",
    )
    parser.add_argument(
        "--approval-public-key",
        type=Path,
        required=True,
        help="external Ed25519 public key PEM; never pass a private key",
    )
    parser.add_argument("--kubectl", default="kubectl", help="kubectl executable")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        targets = reconcile(
            SubprocessRunner(),
            kubectl=args.kubectl,
            agentteams_repo=args.agentteams_repo,
            approval_public_key=args.approval_public_key,
            devflow_repo=args.devflow_repo,
        )
    except ReconcileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError, ValueError, tarfile.TarError):
        print("error: local source processing failed safely", file=sys.stderr)
        return 1
    summary = {
        "namespace": NAMESPACE,
        "team": TEAM_NAME,
        "upstreamCommit": UPSTREAM_AGENTTEAMS_COMMIT,
        "roles": [
            {
                "name": target.role_name,
                "pod": target.pod_name,
                "teamHarnessRole": target.teamharness_role,
            }
            for target in targets
        ],
        "verified": True,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
