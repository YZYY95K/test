#!/usr/bin/env python3
"""Reconcile the fixed DevFlow mcporter allowlist after Team rebuilds.

The host receives only digests and server names. Configuration parsing,
Bearer-header validation, fixed-path TeamHarness attestation, atomic live writes,
and MinIO synchronization happen inside each role Pod. Check mode is the default
and never writes.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

try:
    from scripts.reconcile_teamharness_openclaw import (
        CONTAINER_NAME,
        EXPECTED_ROLES,
        NAMESPACE,
        RUNTIME_LABEL,
        TEAM_LABEL,
        TEAM_NAME,
        Target,
        discover_targets,
    )
except ModuleNotFoundError:  # pragma: no cover - direct ``python -S`` execution
    from reconcile_teamharness_openclaw import (  # type: ignore[no-redef]
        CONTAINER_NAME,
        EXPECTED_ROLES,
        NAMESPACE,
        RUNTIME_LABEL,
        TEAM_LABEL,
        TEAM_NAME,
        Target,
        discover_targets,
    )

LOCATOR_ROLE = "devflow-locator"
LEADER_ROLE = "devflow-lead"
TEAMHARNESS_SERVER = "teamharness"
DEVFLOW_SERVER = "devflow-github-readonly"
STALE_SERVER = "github"
DEVFLOW_URL = (
    "http://higress-gateway.agentteams-system.svc.cluster.local:80/"
    "mcp-servers/devflow-github-readonly/mcp"
)
STALE_URL = "http://aigw-local.agentteams.io:8080/mcp-servers/mcp-github/mcp"
TEAMHARNESS_COMMAND = "/usr/bin/python3"
TEAMHARNESS_GUARD_PATH = "/opt/devflow/teamharness/guarded_server.py"
TEAMHARNESS_ADAPTER_PATH = "/opt/devflow/teamharness/teamharness_openclaw.py"
TEAMHARNESS_UPSTREAM_SERVER_PATH = "/opt/devflow/teamharness/plugin/mcp/server.py"
TEAMHARNESS_MANIFEST_PATH = "/etc/devflow/teamharness/install-manifest.json"
TEAMHARNESS_RUNTIME_BINDING_PATH = "/etc/devflow/teamharness/runtime-binding.json"
TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH = "/etc/devflow/teamharness/approval-ed25519.pub"
TEAMHARNESS_APPROVAL_POLICY_PATH = "/etc/devflow/teamharness/approval-policy.json"
TEAMHARNESS_APPROVAL_LEDGER_PATH = "/var/lib/devflow/teamharness/approval-ledger.json"
TEAMHARNESS_OPENSSL_PATH = "/usr/bin/openssl"
TEAMHARNESS_SHARED_DIR = "/root/hiclaw-fs/shared"
TEAMHARNESS_CORE_ARTIFACTS = (
    ("guard", TEAMHARNESS_GUARD_PATH, "guardPath", "guardSha256"),
    ("adapter", TEAMHARNESS_ADAPTER_PATH, "adapterPath", "adapterSha256"),
    ("server", TEAMHARNESS_UPSTREAM_SERVER_PATH, "serverPath", "serverSha256"),
    (
        "runtimeBinding",
        TEAMHARNESS_RUNTIME_BINDING_PATH,
        "runtimeBindingPath",
        "runtimeBindingSha256",
    ),
)
TEAMHARNESS_LEADER_ARTIFACTS = (
    (
        "approvalPolicy",
        TEAMHARNESS_APPROVAL_POLICY_PATH,
        "approvalPolicyPath",
        "approvalPolicySha256",
    ),
    (
        "approvalPublicKey",
        TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH,
        "approvalPublicKeyPath",
        "approvalPublicKeySha256",
    ),
)
TEAMHARNESS_POLICY_FIELDS = frozenset(
    {
        "schemaVersion",
        "algorithm",
        "guardSha256",
        "adapterSha256",
        "policyAttestationPath",
        "publicKeyPath",
        "publicKeySha256",
        "serverSha256",
        "ledgerPath",
        "opensslPath",
        "maxApprovalLifetimeSeconds",
        "remainingThreat",
    }
)
RUNTIME_BINDING_FIELDS = frozenset(
    {
        "schemaVersion",
        "teamName",
        "memberName",
        "runtimeName",
        "podName",
        "teamHarnessRole",
    }
)
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SUMMARY_FIELDS = frozenset(
    {
        "ok",
        "role",
        "liveDigest",
        "desiredDigest",
        "remoteDigest",
        "liveServerNames",
        "desiredServerNames",
        "remoteServerNames",
        "needsApply",
        "applied",
    }
)


class PolicyError(RuntimeError):
    """Discovery, policy, concurrency, or remote verification failed."""


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Any:
    raise PolicyError("non-standard JSON scalar")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def _config_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _valid_bearer_entry(value: Any, expected_url: str) -> bool:
    if not isinstance(value, dict) or set(value) != {"url", "transport", "headers"}:
        return False
    headers = value.get("headers")
    if not isinstance(headers, dict) or set(headers) != {"Authorization"}:
        return False
    authorization = headers.get("Authorization")
    return (
        value.get("url") == expected_url
        and value.get("transport") == "http"
        and isinstance(authorization, str)
        and re.fullmatch(r"Bearer [^\s]+", authorization) is not None
    )


def _expected_teamharness_entry() -> dict[str, Any]:
    return {
        "command": TEAMHARNESS_COMMAND,
        "args": [TEAMHARNESS_GUARD_PATH],
        "transport": "stdio",
        "env": {"TEAMHARNESS_SHARED_DIR": TEAMHARNESS_SHARED_DIR},
    }


def _validate_teamharness_entry(value: Any) -> None:
    expected = _expected_teamharness_entry()
    if not isinstance(value, dict) or set(value) != set(expected):
        raise PolicyError("TeamHarness entry schema is outside policy")
    if value.get("transport") != expected["transport"]:
        raise PolicyError("TeamHarness transport is outside policy")
    if value.get("command") != expected["command"]:
        raise PolicyError("TeamHarness executable is outside policy")
    if value.get("args") != expected["args"]:
        raise PolicyError("TeamHarness guard path is outside policy")
    if value.get("env") != expected["env"]:
        raise PolicyError("TeamHarness environment is outside policy")


def _valid_legacy_teamharness_entry(value: Any, role: str) -> bool:
    """Recognize only the exact pre-externalized entry removable on reconcile."""

    workspace = f"/root/hiclaw-fs/agents/{role}"
    return bool(value == {
        "command": "python3",
        "args": [f"{workspace}/.teamharness/mcp/guarded_server.py"],
        "transport": "stdio",
        "env": {
            "AGENTTEAMS_AGENT_ROLE": "leader" if role == LEADER_ROLE else "worker",
            "TEAMHARNESS_RUNTIME_CONFIG": f"{workspace}/runtime/runtime.json",
            "TEAMHARNESS_SHARED_DIR": TEAMHARNESS_SHARED_DIR,
        },
    })


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise PolicyError("trusted runtime artifact cannot be read") from exc
    return digest.hexdigest()


def _trusted_fixed_file(expected: str, workspace: str) -> Path:
    path = Path(expected)
    workspace_path = Path(workspace)
    try:
        resolved = path.resolve(strict=True)
        workspace_resolved = workspace_path.resolve(strict=True)
    except OSError as exc:
        raise PolicyError("trusted runtime artifact is missing") from exc
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or resolved != path
    ):
        raise PolicyError("trusted runtime artifact path is unsafe")
    try:
        resolved.relative_to(workspace_resolved)
    except ValueError:
        return path
    raise PolicyError("trusted runtime artifact is inside the agent workspace")


def _trusted_fixed_directory(expected: str, workspace: str) -> Path:
    path = Path(expected)
    workspace_path = Path(workspace)
    try:
        resolved = path.resolve(strict=True)
        workspace_resolved = workspace_path.resolve(strict=True)
    except OSError as exc:
        raise PolicyError("trusted runtime directory is missing") from exc
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_dir()
        or resolved != path
    ):
        raise PolicyError("trusted runtime directory path is unsafe")
    try:
        resolved.relative_to(workspace_resolved)
    except ValueError:
        return path
    raise PolicyError("trusted runtime directory is inside the agent workspace")


def _read_strict_json(path: Path, label: str) -> dict[str, Any]:
    try:
        if path.stat().st_size > 1024 * 1024:
            raise PolicyError(f"{label} is unexpectedly large")
        text = path.read_text(encoding="utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, OSError, UnicodeError) as exc:
        raise PolicyError(f"{label} is invalid") from exc
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must contain an object")
    return value


def _validate_runtime_attestation(
    manifest: dict[str, Any],
    policy: dict[str, Any] | None,
    runtime_binding: dict[str, Any],
    role: str,
    digests: dict[str, str],
) -> None:
    artifacts = list(TEAMHARNESS_CORE_ARTIFACTS)
    if role == LEADER_ROLE:
        artifacts.extend(TEAMHARNESS_LEADER_ARTIFACTS)
    expected_digest_names = {name for name, _path, _path_field, _sha_field in artifacts}
    if set(digests) != expected_digest_names or any(
        not isinstance(value, str) or DIGEST.fullmatch(value) is None
        for value in digests.values()
    ):
        raise PolicyError("runtime artifact digest set is outside policy")
    for name, expected_path, path_field, sha_field in artifacts:
        if (
            manifest.get(path_field) != expected_path
            or manifest.get(sha_field) != digests[name]
        ):
            raise PolicyError("runtime artifact path or digest mismatch")

    teamharness_role = "leader" if role == LEADER_ROLE else "worker"
    runtime_identity = manifest.get("runtimeIdentity")
    if (
        manifest.get("schemaVersion") != "1.0"
        or manifest.get("sourcePolicy") != "production-pinned"
        or manifest.get("role") != teamharness_role
        or not isinstance(runtime_identity, dict)
        or runtime_identity.get("runtimeName") != role
        or runtime_identity.get("hostname") != runtime_binding.get("podName")
        or manifest.get("runtimeBinding") != runtime_binding
        or set(runtime_binding) != RUNTIME_BINDING_FIELDS
        or runtime_binding.get("schemaVersion") != "1.0"
        or runtime_binding.get("teamName") != TEAM_NAME
        or runtime_binding.get("runtimeName") != role
        or runtime_binding.get("teamHarnessRole") != teamharness_role
        or not isinstance(runtime_binding.get("memberName"), str)
        or not runtime_binding.get("memberName")
        or not isinstance(runtime_binding.get("podName"), str)
        or not runtime_binding.get("podName")
    ):
        raise PolicyError("runtime identity attestation mismatch")

    leader_fields = {
        path_field
        for _name, _path, path_field, _sha_field in TEAMHARNESS_LEADER_ARTIFACTS
    } | {
        sha_field
        for _name, _path, _path_field, sha_field in TEAMHARNESS_LEADER_ARTIFACTS
    }
    if role != LEADER_ROLE:
        if policy is not None or "approvalPolicy" in manifest or leader_fields & set(manifest):
            raise PolicyError("non-Leader manifest contains approval policy material")
        return

    if (
        not isinstance(policy, dict)
        or set(policy) != TEAMHARNESS_POLICY_FIELDS
        or manifest.get("approvalPolicy") != policy
        or policy.get("schemaVersion") != "1.0"
        or policy.get("algorithm") != "Ed25519"
        or policy.get("guardSha256") != digests["guard"]
        or policy.get("adapterSha256") != digests["adapter"]
        or policy.get("serverSha256") != digests["server"]
        or policy.get("publicKeySha256") != digests["approvalPublicKey"]
        or policy.get("policyAttestationPath") != TEAMHARNESS_APPROVAL_POLICY_PATH
        or policy.get("publicKeyPath") != TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH
        or policy.get("ledgerPath") != TEAMHARNESS_APPROVAL_LEDGER_PATH
        or policy.get("opensslPath") != TEAMHARNESS_OPENSSL_PATH
        or policy.get("maxApprovalLifetimeSeconds") != 900
        or not isinstance(policy.get("remainingThreat"), str)
        or not policy.get("remainingThreat")
    ):
        raise PolicyError("Leader approval policy attestation mismatch")


def _validate_runtime_trust(workspace: str, role: str) -> None:
    manifest_path = _trusted_fixed_file(TEAMHARNESS_MANIFEST_PATH, workspace)
    manifest = _read_strict_json(manifest_path, "TeamHarness install manifest")
    artifacts = list(TEAMHARNESS_CORE_ARTIFACTS)
    if role == LEADER_ROLE:
        artifacts.extend(TEAMHARNESS_LEADER_ARTIFACTS)

    artifact_paths = {
        name: _trusted_fixed_file(expected_path, workspace)
        for name, expected_path, _path_field, _sha_field in artifacts
    }
    digests = {name: _sha256_file(path) for name, path in artifact_paths.items()}
    runtime_binding = _read_strict_json(
        artifact_paths["runtimeBinding"],
        "TeamHarness runtime binding",
    )
    policy = (
        _read_strict_json(
            artifact_paths["approvalPolicy"],
            "TeamHarness approval policy",
        )
        if role == LEADER_ROLE
        else None
    )
    _trusted_fixed_directory(TEAMHARNESS_SHARED_DIR, workspace)
    _validate_runtime_attestation(manifest, policy, runtime_binding, role, digests)


def _evaluate_config(
    text: str,
    role: str,
    *,
    require_complete: bool,
) -> tuple[str, str, list[str], list[str], bytes]:
    try:
        document = json.loads(
            text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise PolicyError("mcporter config is invalid JSON") from exc
    if not isinstance(document, dict) or set(document) != {"mcpServers"}:
        raise PolicyError("mcporter config root is outside policy")
    servers = document.get("mcpServers")
    if not isinstance(servers, dict):
        raise PolicyError("mcpServers must be an object")

    required = {TEAMHARNESS_SERVER}
    if role == LOCATOR_ROLE:
        required.add(DEVFLOW_SERVER)
    elif role not in EXPECTED_ROLES:
        raise PolicyError("role is outside the fixed Team")
    names = set(servers)
    unknown = names - required - {STALE_SERVER}
    if unknown:
        raise PolicyError("mcporter config contains an unknown server")
    if require_complete and not required <= names:
        raise PolicyError("mcporter config is missing a required server")
    if TEAMHARNESS_SERVER in servers:
        try:
            _validate_teamharness_entry(servers[TEAMHARNESS_SERVER])
        except PolicyError:
            if require_complete or not _valid_legacy_teamharness_entry(
                servers[TEAMHARNESS_SERVER], role
            ):
                raise
    if STALE_SERVER in servers and not _valid_bearer_entry(servers[STALE_SERVER], STALE_URL):
        raise PolicyError("legacy github entry is not the exact removable shape")
    if DEVFLOW_SERVER in servers and (
        role != LOCATOR_ROLE or not _valid_bearer_entry(servers[DEVFLOW_SERVER], DEVFLOW_URL)
    ):
        raise PolicyError("DevFlow GitHub entry is outside policy")

    desired_servers = {name: value for name, value in servers.items() if name != STALE_SERVER}
    desired_servers[TEAMHARNESS_SERVER] = _expected_teamharness_entry()
    desired = {"mcpServers": desired_servers}
    return (
        _config_digest(document),
        _config_digest(desired),
        sorted(names),
        sorted(desired_servers),
        _canonical_json(desired),
    )


def _remote_main() -> None:
    import os
    import tempfile
    from pathlib import Path

    if len(sys.argv) != 6 or sys.argv[1] not in {"check", "apply"}:
        raise SystemExit(2)
    action, role, workspace, expected_live, expected_remote = sys.argv[1:]
    workspace_path = Path(workspace)
    live_path = workspace_path / "config" / "mcporter.json"
    expected_workspace = f"/root/hiclaw-fs/agents/{role}"
    try:
        exact_workspace = workspace_path.resolve(strict=True) == workspace_path
        exact_live_path = live_path.resolve(strict=True) == live_path
    except OSError:
        exact_workspace = False
        exact_live_path = False
    if (
        role not in EXPECTED_ROLES
        or workspace != expected_workspace
        or os.environ.get("AGENTTEAMS_WORKER_NAME") != role
        or os.environ.get("HOME") != workspace
        or not exact_workspace
        or workspace_path.is_symlink()
        or Path.cwd().resolve() != workspace_path
        or not exact_live_path
        or not live_path.is_file()
        or live_path.is_symlink()
    ):
        raise SystemExit(3)
    _validate_runtime_trust(workspace, role)
    prefix = os.environ.get("AGENTTEAMS_STORAGE_PREFIX", "").rstrip("/")
    if not prefix:
        raise SystemExit(3)
    remote_key = f"{prefix}/agents/{role}/config/mcporter.json"

    def mc_copy(source: str, destination: str) -> None:
        try:
            completed = subprocess.run(
                ["mc", "cp", source, destination],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise PolicyError("object storage command failed") from exc
        if completed.returncode != 0:
            raise PolicyError("object storage command failed")

    def read_remote(destination: Path) -> str:
        mc_copy(remote_key, str(destination))
        try:
            return destination.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise PolicyError("authoritative config cannot be read") from exc

    with tempfile.TemporaryDirectory(prefix="devflow-mcporter-policy-") as temp:
        remote_path = Path(temp) / "remote.json"
        live_text = live_path.read_text(encoding="utf-8")
        remote_text = read_remote(remote_path)
        live = _evaluate_config(live_text, role, require_complete=True)
        remote = _evaluate_config(remote_text, role, require_complete=False)
        needs_apply = live[0] != live[1] or remote[0] != live[1]

        if action == "apply":
            if live[0] != expected_live or remote[0] != expected_remote:
                raise PolicyError("mcporter config changed after preflight")
            if needs_apply:
                mode = live_path.stat().st_mode & 0o777
                staged_fd, staged_name = tempfile.mkstemp(
                    prefix=".mcporter-policy-",
                    dir=live_path.parent,
                )
                staged = Path(staged_name)
                try:
                    with os.fdopen(staged_fd, "wb") as stream:
                        stream.write(live[4])
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.chmod(staged, mode)
                    os.replace(staged, live_path)
                finally:
                    staged.unlink(missing_ok=True)
                mc_copy(str(live_path), remote_key)
                verified_path = Path(temp) / "verified.json"
                verified_text = read_remote(verified_path)
                verified = _evaluate_config(
                    verified_text,
                    role,
                    require_complete=True,
                )
                if verified[0] != live[1] or verified[2] != live[3]:
                    raise PolicyError("authoritative config verification failed")
                live = _evaluate_config(
                    live_path.read_text(encoding="utf-8"),
                    role,
                    require_complete=True,
                )
                remote = verified
                needs_apply = False

        _validate_runtime_trust(workspace, role)
        summary = {
            "ok": True,
            "role": role,
            "liveDigest": live[0],
            "desiredDigest": live[1],
            "remoteDigest": remote[0],
            "liveServerNames": live[2],
            "desiredServerNames": live[3],
            "remoteServerNames": remote[2],
            "needsApply": needs_apply,
            "applied": action == "apply",
        }
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))


REMOTE_HELPER = "\n\n".join(
    [
        "from __future__ import annotations",
        (
            "import hashlib\nimport json\nimport re\nimport subprocess\nimport sys\n"
            "from pathlib import Path\nfrom typing import Any"
        ),
        f"EXPECTED_ROLES = frozenset({sorted(EXPECTED_ROLES)!r})",
        f"TEAM_NAME = {TEAM_NAME!r}",
        f"LOCATOR_ROLE = {LOCATOR_ROLE!r}",
        f"LEADER_ROLE = {LEADER_ROLE!r}",
        f"TEAMHARNESS_SERVER = {TEAMHARNESS_SERVER!r}",
        f"DEVFLOW_SERVER = {DEVFLOW_SERVER!r}",
        f"STALE_SERVER = {STALE_SERVER!r}",
        f"DEVFLOW_URL = {DEVFLOW_URL!r}",
        f"STALE_URL = {STALE_URL!r}",
        f"TEAMHARNESS_COMMAND = {TEAMHARNESS_COMMAND!r}",
        f"TEAMHARNESS_GUARD_PATH = {TEAMHARNESS_GUARD_PATH!r}",
        f"TEAMHARNESS_ADAPTER_PATH = {TEAMHARNESS_ADAPTER_PATH!r}",
        f"TEAMHARNESS_UPSTREAM_SERVER_PATH = {TEAMHARNESS_UPSTREAM_SERVER_PATH!r}",
        f"TEAMHARNESS_MANIFEST_PATH = {TEAMHARNESS_MANIFEST_PATH!r}",
        f"TEAMHARNESS_RUNTIME_BINDING_PATH = {TEAMHARNESS_RUNTIME_BINDING_PATH!r}",
        (
            "TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH = "
            f"{TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH!r}"
        ),
        f"TEAMHARNESS_APPROVAL_POLICY_PATH = {TEAMHARNESS_APPROVAL_POLICY_PATH!r}",
        f"TEAMHARNESS_APPROVAL_LEDGER_PATH = {TEAMHARNESS_APPROVAL_LEDGER_PATH!r}",
        f"TEAMHARNESS_OPENSSL_PATH = {TEAMHARNESS_OPENSSL_PATH!r}",
        f"TEAMHARNESS_SHARED_DIR = {TEAMHARNESS_SHARED_DIR!r}",
        f"TEAMHARNESS_CORE_ARTIFACTS = {TEAMHARNESS_CORE_ARTIFACTS!r}",
        f"TEAMHARNESS_LEADER_ARTIFACTS = {TEAMHARNESS_LEADER_ARTIFACTS!r}",
        f"TEAMHARNESS_POLICY_FIELDS = frozenset({sorted(TEAMHARNESS_POLICY_FIELDS)!r})",
        f"RUNTIME_BINDING_FIELDS = frozenset({sorted(RUNTIME_BINDING_FIELDS)!r})",
        "DIGEST = re.compile(r'^[0-9a-f]{64}$')",
        inspect.getsource(PolicyError),
        inspect.getsource(_strict_json_object),
        inspect.getsource(_reject_json_constant),
        inspect.getsource(_canonical_json),
        inspect.getsource(_config_digest),
        inspect.getsource(_valid_bearer_entry),
        inspect.getsource(_expected_teamharness_entry),
        inspect.getsource(_validate_teamharness_entry),
        inspect.getsource(_valid_legacy_teamharness_entry),
        inspect.getsource(_sha256_file),
        inspect.getsource(_trusted_fixed_file),
        inspect.getsource(_trusted_fixed_directory),
        inspect.getsource(_read_strict_json),
        inspect.getsource(_validate_runtime_attestation),
        inspect.getsource(_validate_runtime_trust),
        inspect.getsource(_evaluate_config),
        inspect.getsource(_remote_main),
        "_remote_main()",
    ]
)


class Runner(Protocol):
    def run(self, args: list[str]) -> str: ...


class SubprocessRunner:
    """Run commands without a shell and suppress remote failure output."""

    def run(self, args: list[str]) -> str:
        try:
            completed = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            raise PolicyError("unable to invoke required command") from exc
        if completed.returncode != 0:
            label = "command"
            if args and Path(args[0]).name == "kubectl":
                if "exec" in args:
                    index = args.index("exec") + 1
                    pod = args[index] if index < len(args) else "pod"
                    action = args[-5] if len(args) >= 5 and args[-5] in {"check", "apply"} else "exec"
                    label = f"kubectl exec {pod} {action}"
                else:
                    operation = next(
                        (item for item in ("version", "get") if item in args),
                        "command",
                    )
                    label = f"kubectl {operation}"
            raise PolicyError(f"remote policy command failed: {label}")
        return completed.stdout


@dataclass(frozen=True)
class Report:
    target: Target
    live_digest: str
    desired_digest: str
    remote_digest: str
    live_names: tuple[str, ...]
    desired_names: tuple[str, ...]
    remote_names: tuple[str, ...]
    needs_apply: bool
    applied: bool


def _kubectl(kubectl: str, *args: str) -> list[str]:
    return [kubectl, "--namespace", NAMESPACE, *args]


def _exec_helper(
    kubectl: str,
    target: Target,
    action: str,
    expected_live: str = "-",
    expected_remote: str = "-",
) -> list[str]:
    return _kubectl(
        kubectl,
        "exec",
        target.pod_name,
        "--container",
        CONTAINER_NAME,
        "--",
        "python3",
        "-c",
        REMOTE_HELPER,
        action,
        target.role_name,
        target.workspace,
        expected_live,
        expected_remote,
    )


def _expected_names(role: str) -> tuple[str, ...]:
    names = [TEAMHARNESS_SERVER]
    if role == LOCATOR_ROLE:
        names.append(DEVFLOW_SERVER)
    return tuple(sorted(names))


def _parse_report(text: str, target: Target, *, applied: bool) -> Report:
    try:
        value = json.loads(text, object_pairs_hook=_strict_json_object)
    except (json.JSONDecodeError, PolicyError) as exc:
        raise PolicyError("remote helper returned malformed JSON") from exc
    if not isinstance(value, dict) or set(value) != SUMMARY_FIELDS:
        raise PolicyError("remote helper returned an unexpected summary")
    if value.get("ok") is not True or value.get("role") != target.role_name:
        raise PolicyError("remote helper summary identity mismatch")
    if value.get("applied") is not applied or not isinstance(value.get("needsApply"), bool):
        raise PolicyError("remote helper summary state mismatch")
    digests = [
        value.get("liveDigest"),
        value.get("desiredDigest"),
        value.get("remoteDigest"),
    ]
    if any(not isinstance(item, str) or not DIGEST.fullmatch(item) for item in digests):
        raise PolicyError("remote helper returned an invalid digest")
    name_fields = [
        value.get("liveServerNames"),
        value.get("desiredServerNames"),
        value.get("remoteServerNames"),
    ]
    if any(
        not isinstance(names, list)
        or names != sorted(set(names))
        or any(not isinstance(name, str) for name in names)
        for names in name_fields
    ):
        raise PolicyError("remote helper returned invalid server names")
    desired_names = tuple(value["desiredServerNames"])
    expected_names = _expected_names(target.role_name)
    allowed_names = set(expected_names) | {STALE_SERVER}
    live_names = tuple(value["liveServerNames"])
    remote_names = tuple(value["remoteServerNames"])
    if (
        desired_names != expected_names
        or not set(expected_names) <= set(live_names) <= allowed_names
        or not set(remote_names) <= allowed_names
    ):
        raise PolicyError("remote desired server names violate role policy")
    return Report(
        target=target,
        live_digest=value["liveDigest"],
        desired_digest=value["desiredDigest"],
        remote_digest=value["remoteDigest"],
        live_names=live_names,
        desired_names=desired_names,
        remote_names=remote_names,
        needs_apply=value["needsApply"],
        applied=value["applied"],
    )


def reconcile(
    runner: Runner,
    *,
    kubectl: str = "kubectl",
    apply: bool = False,
) -> list[Report]:
    """Preflight all six role Pods, then optionally apply the fixed policy."""
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
        raise PolicyError("Kubernetes discovery returned malformed JSON") from exc
    if not isinstance(team, dict) or not isinstance(pods, dict):
        raise PolicyError("Kubernetes discovery documents must be objects")
    targets = discover_targets(team, pods)

    preflight = [
        _parse_report(
            runner.run(_exec_helper(kubectl, target, "check")),
            target,
            applied=False,
        )
        for target in targets
    ]
    if not apply:
        return preflight

    final: list[Report] = []
    for report in preflight:
        if not report.needs_apply:
            final.append(report)
            continue
        applied_report = _parse_report(
            runner.run(
                _exec_helper(
                    kubectl,
                    report.target,
                    "apply",
                    report.live_digest,
                    report.remote_digest,
                )
            ),
            report.target,
            applied=True,
        )
        if (
            applied_report.needs_apply
            or applied_report.live_digest != applied_report.desired_digest
            or applied_report.remote_digest != applied_report.desired_digest
            or applied_report.live_names != applied_report.desired_names
            or applied_report.remote_names != applied_report.desired_names
        ):
            raise PolicyError("post-apply mcporter policy verification failed")
        final.append(applied_report)
    return final


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check or reconcile the fixed six-role DevFlow mcporter policy."
    )
    parser.add_argument("--apply", action="store_true", help="apply after all preflights")
    parser.add_argument("--kubectl", default="kubectl", help="kubectl executable")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        reports = reconcile(SubprocessRunner(), kubectl=args.kubectl, apply=args.apply)
    except PolicyError as exc:
        print(f"error: mcporter policy reconciliation failed safely: {exc}", file=sys.stderr)
        return 1
    except (RuntimeError, OSError, UnicodeError, ValueError):
        print("error: mcporter policy reconciliation failed safely", file=sys.stderr)
        return 1
    summary = {
        "applied": args.apply,
        "namespace": NAMESPACE,
        "roles": [
            {
                "name": report.target.role_name,
                "serverNames": list(report.desired_names),
                "compliant": not report.needs_apply,
            }
            for report in reports
        ],
        "team": TEAM_NAME,
        "verified": all(not report.needs_apply for report in reports),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
