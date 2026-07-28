#!/usr/bin/env python3
"""Audit the native OpenClaw tool boundary for the fixed DevFlow Team.

OpenClaw 2026.4.14 can narrow its tool catalogue, constrain filesystem tools
to a workspace, and approval-gate ``exec``.  Those controls are useful
defence-in-depth, but they cannot form a strong boundary in the current
AgentTeams Worker layout: the OpenClaw process runs as root while its config,
exec-approval state, MinIO client material, and mcporter configuration live in
the same workspace that role tools must read or write.

This utility therefore performs a read-only, six-Pod audit.  It deliberately
refuses ``--apply`` after every Pod has been preflighted.  It never reads a
Kubernetes Secret, returns configuration content, or claims enforcement that
the runtime cannot provide.
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

EXPECTED_OPENCLAW_VERSION = "2026.4.14"
EXPECTED_OPENCLAW_COMMIT = "2f35b6f"
OPENCLAW_VERSION_PATTERN = re.compile(
    rf"^OpenClaw {re.escape(EXPECTED_OPENCLAW_VERSION)} "
    rf"\({re.escape(EXPECTED_OPENCLAW_COMMIT)}\)$"
)

CODER_ROLE = "devflow-coder"
ALL_CORE_TOOLS = frozenset(
    {
        "read",
        "write",
        "edit",
        "apply_patch",
        "exec",
        "process",
        "code_execution",
        "web_search",
        "web_fetch",
        "x_search",
        "memory_search",
        "memory_get",
        "sessions_list",
        "sessions_history",
        "sessions_send",
        "sessions_spawn",
        "sessions_yield",
        "subagents",
        "session_status",
        "browser",
        "canvas",
        "message",
        "cron",
        "gateway",
        "nodes",
        "agents_list",
        "update_plan",
        "image",
        "image_generate",
        "music_generate",
        "video_generate",
        "tts",
    }
)
BASE_ROLE_TOOLS = frozenset({"read", "exec"})
CODER_EXTRA_TOOLS = frozenset({"write", "edit", "apply_patch"})

# These are source-level claims audited against the exact source shipped in the
# running image.  Runtime schema checks below independently verify accepted
# value types/enums.  An aggregate digest must agree across all six Pods.
SOURCE_ASSERTIONS: dict[str, tuple[str, ...]] = {
    "/opt/openclaw/src/agents/tool-policy-match.ts": (
        "matchesAnyGlobPattern(normalized, deny)",
        "if (allow.length === 0)",
        "return true;",
    ),
    "/opt/openclaw/src/agents/tool-fs-policy.ts": (
        "workspaceOnly: params.workspaceOnly === true",
        "fsConfig.workspaceOnly === true",
    ),
    "/opt/openclaw/src/agents/exec-defaults.ts": (
        'resolved.effectiveHost === "sandbox" ? "deny" : "full"',
        "approvalDefaults?.ask ??",
        '"off",',
    ),
    "/opt/openclaw/src/agents/pi-tools.ts": (
        "const workspaceOnly = fsPolicy.workspaceOnly",
        "workspaceOnly || applyPatchConfig?.workspaceOnly !== false",
        "const allowBackground = isToolAllowedByPolicies(\"process\"",
    ),
    "/opt/openclaw/src/infra/exec-approvals.ts": (
        'const DEFAULT_SECURITY: ExecSecurity = "full"',
        'const DEFAULT_ASK: ExecAsk = "off"',
        'const DEFAULT_FILE = "~/.openclaw/exec-approvals.json"',
    ),
}

BLOCKER_CODES = (
    "ROOT_RUNTIME_SHARED_WITH_AGENT_TOOLS",
    "FS_WORKSPACE_ONLY_HAS_NO_SENSITIVE_PATH_EXCLUSIONS",
    "OPENCLAW_POLICY_IS_STORED_IN_AGENT_WORKSPACE",
    "EXEC_APPROVAL_STATE_IS_STORED_IN_AGENT_WORKSPACE",
    "MCP_CREDENTIAL_CONFIG_IS_STORED_IN_AGENT_WORKSPACE",
    "MCP_REQUIRES_GENERAL_PURPOSE_EXEC",
)

REPORT_FIELDS = frozenset(
    {
        "ok",
        "role",
        "openclawVersion",
        "sourceDigest",
        "liveDigest",
        "remoteDigest",
        "recommendedPolicyDigest",
        "livePolicyState",
        "remotePolicyState",
        "liveConfigValid",
        "remoteConfigValid",
        "schemaAudited",
        "runtimeUid",
        "workspaceWritable",
        "activeConfigTargetInWorkspace",
        "execApprovalStateInWorkspace",
        "mcCredentialMaterialInWorkspace",
        "mcporterConfigInWorkspace",
        "canEnforceStrongBoundary",
        "blockers",
    }
)
DIGEST = re.compile(r"^[0-9a-f]{64}$")


class BoundaryAuditError(RuntimeError):
    """A discovery, runtime-integrity, or redaction gate failed."""


class BoundaryBlockedError(BoundaryAuditError):
    """The requested mutation cannot honestly provide a strong boundary."""


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BoundaryAuditError("duplicate JSON field")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> Any:
    raise BoundaryAuditError("non-standard JSON scalar")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _digest_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def recommended_tool_policy(role: str) -> dict[str, Any]:
    """Return the narrowest useful native policy for audit comparison only."""

    allowed = set(BASE_ROLE_TOOLS)
    if role == CODER_ROLE:
        allowed.update(CODER_EXTRA_TOOLS)
    if role not in EXPECTED_ROLES:
        raise BoundaryAuditError("role is outside the fixed DevFlow Team")
    return {
        "allow": sorted(allowed),
        "deny": sorted(ALL_CORE_TOOLS - allowed),
        "elevated": {"enabled": False},
        "exec": {
            "applyPatch": {
                "enabled": role == CODER_ROLE,
                "workspaceOnly": True,
            },
            "ask": "always",
            "host": "gateway",
            "safeBins": [],
            "security": "allowlist",
            "strictInlineEval": True,
        },
        "fs": {"workspaceOnly": True},
    }


def _policy_state(document: dict[str, Any], role: str) -> tuple[str, str]:
    expected = recommended_tool_policy(role)
    actual = document.get("tools")
    if actual is None:
        return "unmanaged", _digest_json(expected)
    if actual == expected:
        return "recommended-defense-in-depth", _digest_json(expected)
    return "unknown-or-relaxed-drift", _digest_json(expected)


def _schema_node(schema: dict[str, Any], *path: str) -> dict[str, Any]:
    node: Any = schema
    for item in path:
        if not isinstance(node, dict) or item not in node:
            raise BoundaryAuditError("OpenClaw schema is missing an audited field")
        node = node[item]
    if not isinstance(node, dict):
        raise BoundaryAuditError("OpenClaw schema field has an unexpected shape")
    return node


def _audit_schema(schema: dict[str, Any]) -> None:
    properties = ("properties", "tools", "properties")
    if _schema_node(schema, *properties, "allow").get("type") != "array":
        raise BoundaryAuditError("tools.allow schema drift")
    if _schema_node(schema, *properties, "deny").get("type") != "array":
        raise BoundaryAuditError("tools.deny schema drift")
    if (
        _schema_node(schema, *properties, "fs", "properties", "workspaceOnly").get(
            "type"
        )
        != "boolean"
    ):
        raise BoundaryAuditError("tools.fs.workspaceOnly schema drift")
    exec_path = (*properties, "exec", "properties")
    expected_enums = {
        "host": {"auto", "sandbox", "gateway", "node"},
        "security": {"deny", "allowlist", "full"},
        "ask": {"off", "on-miss", "always"},
    }
    for field, expected in expected_enums.items():
        if set(_schema_node(schema, *exec_path, field).get("enum", [])) != expected:
            raise BoundaryAuditError(f"tools.exec.{field} schema drift")
    if _schema_node(schema, *exec_path, "safeBins").get("type") != "array":
        raise BoundaryAuditError("tools.exec.safeBins schema drift")
    if _schema_node(schema, *exec_path, "strictInlineEval").get("type") != "boolean":
        raise BoundaryAuditError("tools.exec.strictInlineEval schema drift")
    if (
        _schema_node(
            schema,
            *exec_path,
            "applyPatch",
            "properties",
            "workspaceOnly",
        ).get("type")
        != "boolean"
    ):
        raise BoundaryAuditError("tools.exec.applyPatch.workspaceOnly schema drift")
    if (
        _schema_node(
            schema,
            *properties,
            "elevated",
            "properties",
            "enabled",
        ).get("type")
        != "boolean"
    ):
        raise BoundaryAuditError("tools.elevated.enabled schema drift")


def _inside(path: Any, root: Any) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _remote_main() -> None:
    import os
    import tempfile
    from pathlib import Path

    if len(sys.argv) != 4:
        raise SystemExit(2)
    role, workspace, pod_name = sys.argv[1:]
    workspace_path = Path(workspace)
    if (
        os.environ.get("AGENTTEAMS_WORKER_NAME") != role
        or os.environ.get("HOME") != workspace
        or Path.cwd().resolve() != workspace_path.resolve()
        or Path("/etc/hostname").read_text(encoding="utf-8").strip() != pod_name
    ):
        raise SystemExit(3)

    def run_suppressed(
        command: list[str],
        *,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                command,
                cwd=workspace,
                env=env,
                check=False,
                capture_output=True,
            )
        except OSError as exc:
            raise BoundaryAuditError("required runtime command failed") from exc

    version_run = run_suppressed(["openclaw", "--version"])
    try:
        version = version_run.stdout.decode("utf-8").strip()
    except UnicodeError as exc:
        raise BoundaryAuditError("OpenClaw version output is not UTF-8") from exc
    if version_run.returncode != 0 or OPENCLAW_VERSION_PATTERN.fullmatch(version) is None:
        raise BoundaryAuditError("OpenClaw version is outside the audited release")

    source_hash = hashlib.sha256()
    for source_path, assertions in sorted(SOURCE_ASSERTIONS.items()):
        path = Path(source_path)
        if not path.is_file() or path.is_symlink():
            raise BoundaryAuditError("audited OpenClaw source file is missing")
        payload = path.read_bytes()
        try:
            text = payload.decode("utf-8")
        except UnicodeError as exc:
            raise BoundaryAuditError("audited OpenClaw source is not UTF-8") from exc
        if any(assertion not in text for assertion in assertions):
            raise BoundaryAuditError("audited OpenClaw source semantics drifted")
        source_hash.update(source_path.encode("utf-8"))
        source_hash.update(b"\0")
        source_hash.update(payload)
        source_hash.update(b"\0")

    schema_run = run_suppressed(["openclaw", "config", "schema"])
    if schema_run.returncode != 0:
        raise BoundaryAuditError("OpenClaw schema command failed")
    try:
        schema = json.loads(
            schema_run.stdout.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BoundaryAuditError("OpenClaw schema output is malformed") from exc
    if not isinstance(schema, dict):
        raise BoundaryAuditError("OpenClaw schema root is malformed")
    _audit_schema(schema)

    active_path = workspace_path / ".openclaw" / "openclaw.json"
    local_path = workspace_path / "openclaw.json"
    if not active_path.is_symlink() or not local_path.is_file() or local_path.is_symlink():
        raise BoundaryAuditError("OpenClaw config layout differs from audited AgentTeams")
    try:
        live_bytes = local_path.read_bytes()
        live = json.loads(
            live_bytes.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BoundaryAuditError("live OpenClaw config is malformed") from exc
    if not isinstance(live, dict):
        raise BoundaryAuditError("live OpenClaw config root is malformed")
    live_validation = run_suppressed(["openclaw", "config", "validate", "--json"])
    if live_validation.returncode != 0:
        raise BoundaryAuditError("live OpenClaw config failed strict validation")

    prefix = os.environ.get("AGENTTEAMS_STORAGE_PREFIX", "").rstrip("/")
    if not prefix:
        raise BoundaryAuditError("AgentTeams storage prefix is unavailable")
    remote_key = f"{prefix}/agents/{role}/openclaw.json"
    with tempfile.TemporaryDirectory(prefix="devflow-openclaw-audit-") as temp:
        remote_path = Path(temp) / "openclaw.json"
        remote_copy = run_suppressed(["mc", "cp", remote_key, str(remote_path)])
        if remote_copy.returncode != 0:
            raise BoundaryAuditError("authoritative OpenClaw config cannot be read")
        try:
            remote_bytes = remote_path.read_bytes()
            remote = json.loads(
                remote_bytes.decode("utf-8"),
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BoundaryAuditError("authoritative OpenClaw config is malformed") from exc
        if not isinstance(remote, dict):
            raise BoundaryAuditError("authoritative OpenClaw config root is malformed")
        validation_env = dict(os.environ)
        validation_env["OPENCLAW_CONFIG_PATH"] = str(remote_path)
        remote_validation = run_suppressed(
            ["openclaw", "config", "validate", "--json"],
            env=validation_env,
        )
        if remote_validation.returncode != 0:
            raise BoundaryAuditError("authoritative config failed strict validation")

    live_state, expected_digest = _policy_state(live, role)
    remote_state, remote_expected_digest = _policy_state(remote, role)
    if expected_digest != remote_expected_digest:
        raise BoundaryAuditError("role policy digest is not deterministic")

    mc_paths = (
        workspace_path / ".mc" / "config.json",
        workspace_path / ".mc.bin" / "config.json",
    )
    mcporter_path = workspace_path / "config" / "mcporter.json"
    exec_approval_path = workspace_path / ".openclaw" / "exec-approvals.json"
    active_target_in_workspace = _inside(active_path.resolve(), workspace_path)
    workspace_mode = workspace_path.stat().st_mode & 0o777
    runtime_uid = int(getattr(os, "getuid", lambda: -1)())
    report = {
        "ok": True,
        "role": role,
        "openclawVersion": version,
        "sourceDigest": source_hash.hexdigest(),
        "liveDigest": hashlib.sha256(live_bytes).hexdigest(),
        "remoteDigest": hashlib.sha256(remote_bytes).hexdigest(),
        "recommendedPolicyDigest": expected_digest,
        "livePolicyState": live_state,
        "remotePolicyState": remote_state,
        "liveConfigValid": True,
        "remoteConfigValid": True,
        "schemaAudited": True,
        "runtimeUid": runtime_uid,
        "workspaceWritable": runtime_uid == 0 or bool(workspace_mode & 0o222),
        "activeConfigTargetInWorkspace": active_target_in_workspace,
        # The default path is workspace-contained even before the file exists.
        "execApprovalStateInWorkspace": _inside(exec_approval_path, workspace_path),
        "mcCredentialMaterialInWorkspace": any(
            path.exists() and _inside(path, workspace_path) for path in mc_paths
        ),
        "mcporterConfigInWorkspace": mcporter_path.exists()
        and _inside(mcporter_path, workspace_path),
        "canEnforceStrongBoundary": False,
        "blockers": list(BLOCKER_CODES),
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


REMOTE_HELPER = "\n\n".join(
    [
        "from __future__ import annotations",
        "import hashlib\nimport json\nimport re\nimport subprocess\nimport sys\nfrom typing import Any",
        f"EXPECTED_OPENCLAW_VERSION = {EXPECTED_OPENCLAW_VERSION!r}",
        f"EXPECTED_OPENCLAW_COMMIT = {EXPECTED_OPENCLAW_COMMIT!r}",
        (
            "OPENCLAW_VERSION_PATTERN = re.compile("
            "rf\"^OpenClaw {re.escape(EXPECTED_OPENCLAW_VERSION)} \""
            "rf\"\\({re.escape(EXPECTED_OPENCLAW_COMMIT)}\\)$\")"
        ),
        f"CODER_ROLE = {CODER_ROLE!r}",
        f"EXPECTED_ROLES = frozenset({sorted(EXPECTED_ROLES)!r})",
        f"ALL_CORE_TOOLS = frozenset({sorted(ALL_CORE_TOOLS)!r})",
        f"BASE_ROLE_TOOLS = frozenset({sorted(BASE_ROLE_TOOLS)!r})",
        f"CODER_EXTRA_TOOLS = frozenset({sorted(CODER_EXTRA_TOOLS)!r})",
        f"SOURCE_ASSERTIONS = {SOURCE_ASSERTIONS!r}",
        f"BLOCKER_CODES = {BLOCKER_CODES!r}",
        inspect.getsource(BoundaryAuditError),
        inspect.getsource(_strict_json_object),
        inspect.getsource(_reject_json_constant),
        inspect.getsource(_canonical_json),
        inspect.getsource(_digest_json),
        inspect.getsource(recommended_tool_policy),
        inspect.getsource(_policy_state),
        inspect.getsource(_schema_node),
        inspect.getsource(_audit_schema),
        inspect.getsource(_inside),
        inspect.getsource(_remote_main),
        "_remote_main()",
    ]
)


class Runner(Protocol):
    def run(self, args: list[str]) -> str: ...


class SubprocessRunner:
    """Run without a shell and suppress potentially sensitive remote failures."""

    def run(self, args: list[str]) -> str:
        try:
            completed = subprocess.run(
                args,
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            raise BoundaryAuditError("unable to invoke required command") from exc
        if completed.returncode != 0:
            raise BoundaryAuditError("remote OpenClaw boundary audit failed")
        return completed.stdout


@dataclass(frozen=True)
class AuditReport:
    target: Target
    openclaw_version: str
    source_digest: str
    live_digest: str
    remote_digest: str
    recommended_policy_digest: str
    live_policy_state: str
    remote_policy_state: str
    runtime_uid: int
    workspace_writable: bool
    active_config_target_in_workspace: bool
    exec_approval_state_in_workspace: bool
    mc_credential_material_in_workspace: bool
    mcporter_config_in_workspace: bool
    blockers: tuple[str, ...]

    @property
    def strong_boundary(self) -> bool:
        return False


def _kubectl(kubectl: str, *args: str) -> list[str]:
    return [kubectl, "--namespace", NAMESPACE, *args]


def _audit_command(kubectl: str, target: Target) -> list[str]:
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
        target.role_name,
        target.workspace,
        target.pod_name,
    )


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise BoundaryAuditError(f"remote summary has invalid {label}")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise BoundaryAuditError(f"remote summary has invalid {label}")
    return value


def _parse_report(text: str, target: Target) -> AuditReport:
    try:
        value = json.loads(text, object_pairs_hook=_strict_json_object)
    except (json.JSONDecodeError, BoundaryAuditError) as exc:
        raise BoundaryAuditError("remote helper returned malformed JSON") from exc
    if not isinstance(value, dict) or set(value) != REPORT_FIELDS:
        raise BoundaryAuditError("remote helper returned an unexpected summary")
    if value.get("ok") is not True or value.get("role") != target.role_name:
        raise BoundaryAuditError("remote helper identity mismatch")
    if value.get("openclawVersion") != (
        f"OpenClaw {EXPECTED_OPENCLAW_VERSION} ({EXPECTED_OPENCLAW_COMMIT})"
    ):
        raise BoundaryAuditError("remote OpenClaw version mismatch")
    for field in (
        "sourceDigest",
        "liveDigest",
        "remoteDigest",
        "recommendedPolicyDigest",
    ):
        if not DIGEST.fullmatch(_string(value.get(field), field)):
            raise BoundaryAuditError(f"remote summary has invalid {field}")
    allowed_states = {
        "unmanaged",
        "recommended-defense-in-depth",
        "unknown-or-relaxed-drift",
    }
    live_state = _string(value.get("livePolicyState"), "livePolicyState")
    remote_state = _string(value.get("remotePolicyState"), "remotePolicyState")
    if live_state not in allowed_states or remote_state not in allowed_states:
        raise BoundaryAuditError("remote policy state is invalid")
    if (
        value.get("liveConfigValid") is not True
        or value.get("remoteConfigValid") is not True
        or value.get("schemaAudited") is not True
        or value.get("canEnforceStrongBoundary") is not False
    ):
        raise BoundaryAuditError("remote validation claim is inconsistent")
    runtime_uid = value.get("runtimeUid")
    if not isinstance(runtime_uid, int) or isinstance(runtime_uid, bool) or runtime_uid < 0:
        raise BoundaryAuditError("remote runtime uid is invalid")
    blockers = value.get("blockers")
    if blockers != list(BLOCKER_CODES):
        raise BoundaryAuditError("remote blocker set is incomplete or reordered")
    return AuditReport(
        target=target,
        openclaw_version=value["openclawVersion"],
        source_digest=value["sourceDigest"],
        live_digest=value["liveDigest"],
        remote_digest=value["remoteDigest"],
        recommended_policy_digest=value["recommendedPolicyDigest"],
        live_policy_state=live_state,
        remote_policy_state=remote_state,
        runtime_uid=runtime_uid,
        workspace_writable=_boolean(value.get("workspaceWritable"), "workspaceWritable"),
        active_config_target_in_workspace=_boolean(
            value.get("activeConfigTargetInWorkspace"),
            "activeConfigTargetInWorkspace",
        ),
        exec_approval_state_in_workspace=_boolean(
            value.get("execApprovalStateInWorkspace"),
            "execApprovalStateInWorkspace",
        ),
        mc_credential_material_in_workspace=_boolean(
            value.get("mcCredentialMaterialInWorkspace"),
            "mcCredentialMaterialInWorkspace",
        ),
        mcporter_config_in_workspace=_boolean(
            value.get("mcporterConfigInWorkspace"),
            "mcporterConfigInWorkspace",
        ),
        blockers=tuple(blockers),
    )


def audit(runner: Runner, *, kubectl: str = "kubectl") -> list[AuditReport]:
    """Preflight and audit exactly the six Ready DevFlow OpenClaw Pods."""

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
        raise BoundaryAuditError("Kubernetes discovery returned malformed JSON") from exc
    if not isinstance(team, dict) or not isinstance(pods, dict):
        raise BoundaryAuditError("Kubernetes discovery documents must be objects")
    targets = discover_targets(team, pods)
    reports = [
        _parse_report(runner.run(_audit_command(kubectl, target)), target)
        for target in targets
    ]
    if len({report.source_digest for report in reports}) != 1:
        raise BoundaryAuditError("OpenClaw source differs across role Pods")
    return reports


def reconcile(
    runner: Runner,
    *,
    kubectl: str = "kubectl",
    apply: bool = False,
) -> list[AuditReport]:
    """Audit all roles and refuse mutation when ``apply`` is requested."""

    reports = audit(runner, kubectl=kubectl)
    if apply:
        raise BoundaryBlockedError(
            "native OpenClaw config cannot enforce a strong boundary in this Worker layout"
        )
    return reports


def _summary(reports: list[AuditReport], *, apply: bool) -> dict[str, Any]:
    return {
        "applied": False,
        "applyRequested": apply,
        "namespace": NAMESPACE,
        "team": TEAM_NAME,
        "openclaw": {
            "version": EXPECTED_OPENCLAW_VERSION,
            "commit": EXPECTED_OPENCLAW_COMMIT,
        },
        "strongBoundaryEnforceable": False,
        "blockers": list(BLOCKER_CODES),
        "roles": [
            {
                "name": report.target.role_name,
                "livePolicyState": report.live_policy_state,
                "remotePolicyState": report.remote_policy_state,
                "recommendedPolicyDigest": report.recommended_policy_digest,
                "runtimeUid": report.runtime_uid,
                "workspaceWritable": report.workspace_writable,
                "policyInsideWorkspace": report.active_config_target_in_workspace,
                "execApprovalStateInsideWorkspace": (
                    report.exec_approval_state_in_workspace
                ),
                "mcCredentialMaterialInsideWorkspace": (
                    report.mc_credential_material_in_workspace
                ),
                "mcporterConfigInsideWorkspace": report.mcporter_config_in_workspace,
            }
            for report in reports
        ],
        "verified": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit the fixed DevFlow OpenClaw native tool boundary; mutation is "
            "refused while strong-boundary prerequisites are absent."
        )
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="request apply (currently fails closed after all six preflights)",
    )
    parser.add_argument("--kubectl", default="kubectl", help="kubectl executable")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        reports = audit(SubprocessRunner(), kubectl=args.kubectl)
        print(json.dumps(_summary(reports, apply=args.apply), indent=2, sort_keys=True))
        if args.apply:
            print(
                "error: apply refused; isolate policy, approval state, and credentials "
                "from the agent workspace and run the Worker as non-root first",
                file=sys.stderr,
            )
            return 2
        return 1
    except (BoundaryAuditError, RuntimeError, OSError, UnicodeError, ValueError):
        print("error: OpenClaw tool-boundary audit failed safely", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
