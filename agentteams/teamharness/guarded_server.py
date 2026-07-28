#!/usr/bin/env python3
"""Fail-closed identity and capability guard for TeamHarness stdio MCP."""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import errno
import hashlib
import http.client
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, cast

SELF_PATH = Path(__file__).resolve()
PRODUCTION_EXECUTION_ROOT = Path("/opt/devflow/teamharness")
PRODUCTION_GUARD = PRODUCTION_EXECUTION_ROOT / "guarded_server.py"
PRODUCTION_ADAPTER = PRODUCTION_EXECUTION_ROOT / "teamharness_openclaw.py"
PRODUCTION_SERVER = PRODUCTION_EXECUTION_ROOT / "plugin" / "mcp" / "server.py"
PRODUCTION_INSTALL_MANIFEST = Path("/etc/devflow/teamharness/install-manifest.json")
PRODUCTION_MODE = SELF_PATH == PRODUCTION_GUARD
HERE = SELF_PATH.parent
TEST_WORKSPACE = HERE.parents[1]
RUNTIME_IDENTITY = TEST_WORKSPACE / "runtime" / "runtime.json"
INSTALL_MANIFEST = (
    PRODUCTION_INSTALL_MANIFEST
    if PRODUCTION_MODE
    else TEST_WORKSPACE / ".teamharness" / "install-manifest.json"
)
SERVER_DIRECTORY = PRODUCTION_SERVER.parent if PRODUCTION_MODE else HERE
sys.path.insert(0, str(SERVER_DIRECTORY))

import server as upstream  # noqa: E402

HOSTNAME_PATH = Path("/etc/hostname")
PRODUCTION_APPROVAL_PUBLIC_KEY = Path("/etc/devflow/teamharness/approval-ed25519.pub")
PRODUCTION_APPROVAL_POLICY = Path("/etc/devflow/teamharness/approval-policy.json")
PRODUCTION_APPROVAL_LEDGER = Path("/var/lib/devflow/teamharness/approval-ledger.json")
PRODUCTION_OPENSSL = Path("/usr/bin/openssl")
PRODUCTION_RUNTIME_BINDING = Path("/etc/devflow/teamharness/runtime-binding.json")
PRODUCTION_SERVICE_ACCOUNT_TOKEN = Path("/var/run/secrets/agentteams/token")
PRODUCTION_WORKSPACE_ROOT = Path("/root/hiclaw-fs/agents")
GITHUB_ISSUER_HOST = "devflow-github-capability-issuer.agentteams-system.svc.cluster.local"
GITHUB_ISSUER_PORT = 8081
GITHUB_ISSUER_PATH = "/v1/capabilities"
GITHUB_ISSUER_TIMEOUT_SECONDS = 5
GITHUB_REQUEST_SCHEMA = "devflow.github-assignment-request/v1"
GITHUB_REQUEST_SCHEMA_PREFIX = "devflow.github-assignment-request/"
GITHUB_CAPABILITY_SCHEMA = "devflow.github-content-capability/v1"
GITHUB_ARTIFACT_TYPE = "SkillInvocation"
GITHUB_SKILL = "github-evidence"
GITHUB_PRODUCER = "devflow-lead"
GITHUB_CONSUMER = "devflow-locator"
GITHUB_MAX_RESPONSE_BYTES = 16_384
GITHUB_MAX_TOKEN_BYTES = 16_384
GITHUB_MAX_CAPABILITY_LIFETIME_SECONDS = 300
MAX_REQUEST_BYTES = 1_048_576
MAX_PAYLOAD_BYTES = 1_000_000
MATRIX_STATE_TIMEOUT_SECONDS = 10
MATRIX_MAX_RESPONSE_BYTES = 16_384
GITHUB_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "issue_id",
        "task_id",
        "trace_id",
        "idempotency_key",
        "repository",
        "revision",
        "paths",
    }
)
GITHUB_RESPONSE_FIELDS = frozenset({"schema", "capability", "expires_at", "jti"})
GITHUB_CAPABILITY_FIELDS = frozenset(
    {
        "schema",
        "task_id",
        "owner",
        "repo",
        "revision",
        "paths",
        "iat",
        "exp",
        "jti",
    }
)
RUNTIME_BINDING_FIELDS = {
    "schemaVersion",
    "teamName",
    "memberName",
    "runtimeName",
    "podName",
    "teamHarnessRole",
}
PINNED_UPSTREAM_SERVER_SHA256 = "cb9971baae3545f440821ecf1fd18c76078962a1fe1591141cc88026bf5b684f"
APPROVAL_ACTIONS = frozenset({"resume_project", "accept_task_result", "complete_project"})
APPROVAL_AUDIENCE = "devflow.agentteams.projectflow.approval/v1"
APPROVAL_REQUEST_SCHEMA = "devflow.agentteams.projectflow.approval-request/v1"
RISK_TIERS = frozenset({"T1", "T2", "T3", "T4", "T5"})
HIGH_RISK_TIERS = frozenset({"T4", "T5"})
SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
SOURCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
MATRIX_USER_RE = re.compile(r"@[A-Za-z0-9._=+/\-]+:[A-Za-z0-9.\-]+(?::\d+)?")
MATRIX_ROOM_RE = re.compile(r"![^:\s]+:[^\s]+")
FILESYNC_SEGMENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}")
FILESYNC_SCOPE_META_RE = re.compile(r"[*?\[\]{}]")
GITHUB_TASK_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
GITHUB_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
GITHUB_OWNER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
GITHUB_REPO_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9_-])?")
GITHUB_REVISION_RE = re.compile(r"[0-9a-f]{40}")
GITHUB_PATH_RE = re.compile(r"[A-Za-z0-9._/-]{1,512}")
GITHUB_JTI_RE = re.compile(r"[0-9a-f]{32}")
GITHUB_CAPABILITY_RE = re.compile(r"[A-Za-z0-9_-]{16,4096}\.[A-Za-z0-9_-]{43}")
GITHUB_TOKEN_RE = re.compile(r"[A-Za-z0-9._~-]{1,16384}")
CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{22,128}")
APPROVER_RE = re.compile(r"[A-Za-z0-9@._:/+\-]{3,128}")
RFC3339_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
ROLES = frozenset({"leader", "worker", "remote-member", "manager"})

ROLE_TOOLS = {
    "leader": frozenset(
        {
            "health",
            "message",
            "roomflow",
            "filesync",
            "artifact",
            "projectflow",
            "taskflow",
        }
    ),
    "worker": frozenset({"health", "taskflow"}),
    "remote-member": frozenset({"health", "taskflow"}),
    "manager": frozenset({"health", "message"}),
}

ROLE_ACTIONS = {
    "leader": {
        "message": frozenset({"send"}),
        "roomflow": frozenset({"create_task_room", "list_rooms", "describe_room", "archive_room"}),
        "filesync": frozenset({"list", "stat", "pull", "push"}),
        "artifact": frozenset({"publish_file"}),
        "projectflow": frozenset(
            {
                "create_project",
                "create_quick_project",
                "resolve_project",
                "plan_dag",
                "plan_loop",
                "ready_nodes",
                "ready_loop_nodes",
                "record_loop_iteration",
                "accept_task_result",
                "mark_requester_report_sent",
                "pause_project",
                "resume_project",
                "complete_project",
            }
        ),
        "taskflow": frozenset({"delegate_task", "cancel_task", "check_task"}),
    },
    "worker": {"taskflow": frozenset({"ack_task", "submit_task"})},
    "remote-member": {"taskflow": frozenset({"ack_task", "submit_task"})},
    "manager": {"message": frozenset({"send"})},
}

TERMINAL_TASK_STATES = frozenset(
    {
        "accepted",
        "cancelled",
        "canceled",
        "completed",
        "done",
        "failed",
        "rejected",
        "submitted",
        "success",
    }
)
SUCCESSFUL_SUBMIT_STATES = frozenset({"accepted", "completed", "done", "submitted", "success"})
ACKED_TASK_STATES = frozenset({"acknowledged", "acked", "in_progress", "running"})
FILESYNC_ACTIONS = frozenset({"list", "stat", "pull", "push"})
FILESYNC_MAX_TREE_ENTRIES = 10_000
FILESYNC_MAX_TREE_BYTES = 64 * 1024 * 1024
FILESYNC_MAX_PUSH_OBJECTS = 32
FILESYNC_MAX_LIST_ENTRIES = 10_000
FILESYNC_MAX_LIST_ENTRY_BYTES = 2_048
FILESYNC_MAX_LIST_BYTES = 1_048_576
FILESYNC_HASH_CHUNK_BYTES = 1_048_576
RISK_ONLY_PROJECT_BINDING_FIELDS = frozenset({"riskTier", "createdTargetDigest"})
LEGACY_PROJECT_BINDING_FIELDS = frozenset(
    {"riskTier", "createdTargetDigest", "source", "bindingDigest"}
)
PROJECT_BINDING_FIELDS = frozenset(
    {
        "riskTier",
        "createdTargetDigest",
        "source",
        "incarnation",
        "audience",
        "approvalDomain",
        "policyKeySha256",
        "projectBindingDigest",
    }
)
LEDGER_LOCK_OWNER_SCHEMA = "devflow.approval-ledger-lock/v1"
LEDGER_LOCK_OWNER_FILE = "owner.json"
LEDGER_LOCK_OWNER_FIELDS = frozenset(
    {"schemaVersion", "pid", "processIdentity", "nonce"}
)
LEDGER_LOCK_NONCE_RE = re.compile(r"[0-9a-f]{64}")
LEDGER_LOCK_MAX_OWNER_BYTES = 4_096


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain an object")
    return value


def _hostname(manifest: dict[str, Any]) -> str:
    if manifest.get("sourcePolicy") == "test-only":
        fixture = manifest.get("testHostnameFixture")
        if isinstance(fixture, str) and fixture.strip():
            return fixture.strip()
    return HOSTNAME_PATH.read_text(encoding="utf-8").strip()


def runtime_identity() -> dict[str, str] | None:
    """Derive identity only from fixed workspace evidence, never environment."""

    try:
        manifest = _load_object(INSTALL_MANIFEST)
        manifest_identity = manifest.get("runtimeIdentity")
        if not isinstance(manifest_identity, dict):
            return None
        runtime = manifest_identity if PRODUCTION_MODE else _load_object(RUNTIME_IDENTITY)
        identity_keys = (
            "role",
            "runtimeName",
            "matrixUserId",
            "hostname",
            "teamName",
            "memberName",
            "podName",
        )
        identity = {key: str(runtime.get(key) or "").strip() for key in identity_keys}
        if any(not value for value in identity.values()):
            return None
        if identity["role"] not in ROLES:
            return None
        if manifest_identity != identity or manifest.get("role") != identity["role"]:
            return None
        if not PRODUCTION_MODE:
            files = manifest.get("files")
            relative = "runtime/runtime.json"
            if not isinstance(files, dict) or files.get(relative) != _sha256(RUNTIME_IDENTITY):
                return None
        expected_server = manifest.get("sourceFiles", {}).get("mcp/server.py")
        server_path = PRODUCTION_SERVER if PRODUCTION_MODE else HERE / "server.py"
        actual_server = _sha256(server_path)
        if not isinstance(expected_server, str) or expected_server != actual_server:
            return None
        if PRODUCTION_MODE:
            if (
                actual_server != PINNED_UPSTREAM_SERVER_SHA256
                or manifest.get("sourcePolicy") != "production-pinned"
                or manifest.get("guardPath") != str(PRODUCTION_GUARD)
                or manifest.get("guardSha256") != _sha256(SELF_PATH)
                or manifest.get("adapterPath") != str(PRODUCTION_ADAPTER)
                or manifest.get("adapterSha256") != _sha256(PRODUCTION_ADAPTER)
                or manifest.get("serverPath") != str(PRODUCTION_SERVER)
                or manifest.get("serverSha256") != actual_server
                or manifest.get("runtimeBindingPath") != str(PRODUCTION_RUNTIME_BINDING)
                or "testRuntimeBindingFixture" in manifest
                or "testHostnameFixture" in manifest
            ):
                return None
            binding_path = PRODUCTION_RUNTIME_BINDING
        elif (
            manifest.get("sourcePolicy") == "test-only"
            and manifest.get("testRuntimeBindingFixture") is True
            and actual_server != PINNED_UPSTREAM_SERVER_SHA256
        ):
            binding_path = Path(str(manifest.get("runtimeBindingPath") or ""))
        else:
            return None
        binding = _load_object(binding_path)
        if (
            set(binding) != RUNTIME_BINDING_FIELDS
            or binding != manifest.get("runtimeBinding")
            or manifest.get("runtimeBindingSha256") != _sha256(binding_path)
            or binding.get("teamHarnessRole") != identity["role"]
            or binding.get("runtimeName") != identity["runtimeName"]
            or binding.get("podName") != identity["hostname"]
            or binding.get("podName") != identity["podName"]
            or binding.get("teamName") != identity["teamName"]
            or binding.get("memberName") != identity["memberName"]
        ):
            return None
        if identity["hostname"] != _hostname(manifest):
            return None
        matrix_match = re.fullmatch(r"@([^:]+):([^:]+)", identity["matrixUserId"])
        if matrix_match is None or matrix_match.group(1) != identity["runtimeName"]:
            return None
        return identity
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, TypeError):
        return None


def _workspace_path() -> Path:
    if not PRODUCTION_MODE:
        return TEST_WORKSPACE
    manifest = _load_object(PRODUCTION_INSTALL_MANIFEST)
    value = manifest.get("workspacePath")
    manifest_identity = manifest.get("runtimeIdentity")
    if not isinstance(value, str) or not isinstance(manifest_identity, dict):
        raise ValueError("external manifest workspacePath is missing")
    runtime_name = manifest_identity.get("runtimeName")
    if (
        not isinstance(runtime_name, str)
        or len(runtime_name) > 128
        or SAFE_ID_RE.fullmatch(runtime_name) is None
    ):
        raise ValueError("external manifest runtimeName is invalid")
    workspace = Path(value)
    expected_root = PRODUCTION_WORKSPACE_ROOT
    expected_workspace = expected_root / runtime_name
    if not workspace.is_absolute() or workspace != expected_workspace:
        raise ValueError("external manifest workspacePath is not the runtime role root")
    try:
        resolved = workspace.resolve(strict=True)
    except OSError as exc:
        raise ValueError("external manifest workspacePath is unavailable") from exc
    if workspace.is_symlink() or resolved != expected_workspace or not workspace.is_dir():
        raise ValueError("external manifest workspacePath is not a real role directory")
    return workspace


def _approval_policy(manifest: dict[str, Any]) -> dict[str, Any] | None:
    policy = manifest.get("approvalPolicy")
    required = {
        "schemaVersion",
        "algorithm",
        "audience",
        "approvalDomain",
        "adapterSha256",
        "guardSha256",
        "policyAttestationPath",
        "publicKeyPath",
        "publicKeySha256",
        "policyKeySha256",
        "serverSha256",
        "ledgerPath",
        "opensslPath",
        "maxApprovalLifetimeSeconds",
        "remainingThreat",
    }
    if not isinstance(policy, dict) or set(policy) != required:
        return None
    if (
        policy.get("schemaVersion") != "1.1"
        or policy.get("algorithm") != "Ed25519"
        or policy.get("audience") != APPROVAL_AUDIENCE
        or not isinstance(policy.get("approvalDomain"), str)
        or DIGEST_RE.fullmatch(str(policy.get("approvalDomain"))) is None
        or policy.get("maxApprovalLifetimeSeconds") != 900
        or policy.get("guardSha256") != _sha256(Path(__file__).resolve())
        or policy.get("serverSha256")
        != _sha256(PRODUCTION_SERVER if PRODUCTION_MODE else HERE / "server.py")
        or (PRODUCTION_MODE and policy.get("adapterSha256") != _sha256(PRODUCTION_ADAPTER))
    ):
        return None
    source_policy = manifest.get("sourcePolicy")
    if source_policy == "production-pinned":
        if (
            policy.get("publicKeyPath") != str(PRODUCTION_APPROVAL_PUBLIC_KEY)
            or policy.get("policyAttestationPath") != str(PRODUCTION_APPROVAL_POLICY)
            or policy.get("ledgerPath") != str(PRODUCTION_APPROVAL_LEDGER)
            or policy.get("opensslPath") != str(PRODUCTION_OPENSSL)
            or manifest.get("approvalPolicyPath") != str(PRODUCTION_APPROVAL_POLICY)
            or manifest.get("approvalPolicySha256") != _sha256(PRODUCTION_APPROVAL_POLICY)
            or manifest.get("approvalPublicKeyPath") != str(PRODUCTION_APPROVAL_PUBLIC_KEY)
            or manifest.get("approvalPublicKeySha256") != policy.get("publicKeySha256")
        ):
            return None
    elif source_policy != "test-only":
        return None
    public_key = Path(str(policy.get("publicKeyPath") or ""))
    policy_attestation = Path(str(policy.get("policyAttestationPath") or ""))
    ledger = Path(str(policy.get("ledgerPath") or ""))
    openssl_path = Path(str(policy.get("opensslPath") or ""))
    expected_hash = policy.get("publicKeySha256")
    policy_key_hash = policy.get("policyKeySha256")
    try:
        if (
            not isinstance(expected_hash, str)
            or DIGEST_RE.fullmatch(expected_hash) is None
            or policy_key_hash != expected_hash
            or not public_key.is_file()
            or _sha256(public_key) != expected_hash
            or not policy_attestation.is_file()
            or not ledger.is_file()
            or not openssl_path.is_file()
        ):
            return None
        attested_policy = _load_object(policy_attestation)
        if attested_policy != policy:
            return None
    except OSError:
        return None
    return policy


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class GitHubCapabilityError(ValueError):
    """A stable, non-sensitive GitHub delegation failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class GuardPolicyError(ValueError):
    """A stable, non-sensitive guard failure safe for an MCP response."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class MatrixStateReader(Protocol):
    """Read only the Matrix state required to attest one task room."""

    def read(self, room_id: str) -> dict[str, Any]: ...


class HTTPMatrixStateReader:
    """Read bounded Matrix room state through the pinned upstream credentials."""

    @staticmethod
    def _get_json(url: str, token: str) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": "devflow-teamharness-guard/1",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=MATRIX_STATE_TIMEOUT_SECONDS,
            ) as response:
                content_type = str(response.headers.get("Content-Type") or "")
                if content_type.split(";", 1)[0].strip().lower() != "application/json":
                    raise GuardPolicyError("matrix_state_invalid")
                announced = response.headers.get("Content-Length")
                if announced is not None:
                    try:
                        content_length = int(announced)
                    except ValueError:
                        raise GuardPolicyError("matrix_state_invalid") from None
                    if not 1 <= content_length <= MATRIX_MAX_RESPONSE_BYTES:
                        raise GuardPolicyError("matrix_state_invalid")
                else:
                    content_length = None
                raw = response.read(MATRIX_MAX_RESPONSE_BYTES + 1)
        except GuardPolicyError:
            raise
        except (OSError, TimeoutError, urllib.error.URLError, urllib.error.HTTPError):
            raise GuardPolicyError("matrix_state_unavailable") from None
        if (
            not raw
            or len(raw) > MATRIX_MAX_RESPONSE_BYTES
            or (content_length is not None and len(raw) != content_length)
        ):
            raise GuardPolicyError("matrix_state_invalid")
        try:
            value = _strict_json_document(raw.decode("utf-8"), "matrix_state_invalid")
        except (GitHubCapabilityError, UnicodeError):
            raise GuardPolicyError("matrix_state_invalid") from None
        if not isinstance(value, dict):
            raise GuardPolicyError("matrix_state_invalid")
        return value

    def read(self, room_id: str) -> dict[str, Any]:
        try:
            homeserver, token = upstream._matrix_env("roomflow")
        except Exception:
            raise GuardPolicyError("matrix_state_unavailable") from None
        if (
            not isinstance(homeserver, str)
            or not homeserver.startswith(("http://", "https://"))
            or not isinstance(token, str)
            or not token
        ):
            raise GuardPolicyError("matrix_state_unavailable")
        encoded_room = urllib.parse.quote(room_id, safe="")
        join_rules = self._get_json(
            f"{homeserver.rstrip('/')}/_matrix/client/v3/rooms/"
            f"{encoded_room}/state/m.room.join_rules",
            token,
        )
        members = self._get_json(
            f"{homeserver.rstrip('/')}/_matrix/client/v3/rooms/{encoded_room}/members",
            token,
        )
        return {"joinRules": join_rules, "members": members}


class CapabilityIssuer(Protocol):
    """Small injectable boundary for the fixed capability issuer."""

    def issue(self, scope: dict[str, Any], bearer_token: str) -> dict[str, Any]: ...


class HTTPServiceCapabilityIssuer:
    """Call only the in-cluster issuer Service without redirects or overrides."""

    def issue(self, scope: dict[str, Any], bearer_token: str) -> dict[str, Any]:
        body = _canonical_json(scope)
        connection = http.client.HTTPConnection(
            GITHUB_ISSUER_HOST,
            GITHUB_ISSUER_PORT,
            timeout=GITHUB_ISSUER_TIMEOUT_SECONDS,
        )
        try:
            connection.request(
                "POST",
                GITHUB_ISSUER_PATH,
                body=body,
                headers={
                    "Authorization": f"Bearer {bearer_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "devflow-teamharness-guard/1",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if response.status != 201:
                response.read(GITHUB_MAX_RESPONSE_BYTES + 1)
                raise GitHubCapabilityError("github_issuer_unavailable")
            content_type = response.getheader("Content-Type", "")
            if content_type.split(";", 1)[0].strip().lower() != "application/json":
                response.read(GITHUB_MAX_RESPONSE_BYTES + 1)
                raise GitHubCapabilityError("github_issuer_response_invalid")
            announced = response.getheader("Content-Length")
            content_length: int | None = None
            if announced is not None:
                try:
                    content_length = int(announced)
                except ValueError:
                    raise GitHubCapabilityError("github_issuer_response_invalid") from None
                if not 1 <= content_length <= GITHUB_MAX_RESPONSE_BYTES:
                    raise GitHubCapabilityError("github_issuer_response_invalid")
            raw = response.read(GITHUB_MAX_RESPONSE_BYTES + 1)
            if (
                not raw
                or len(raw) > GITHUB_MAX_RESPONSE_BYTES
                or (content_length is not None and len(raw) != content_length)
            ):
                raise GitHubCapabilityError("github_issuer_response_invalid")
        except GitHubCapabilityError:
            raise
        except (OSError, http.client.HTTPException):
            raise GitHubCapabilityError("github_issuer_unavailable") from None
        finally:
            connection.close()
        try:
            value = _strict_json_document(raw.decode("utf-8"), "github_issuer_response_invalid")
        except UnicodeError:
            raise GitHubCapabilityError("github_issuer_response_invalid") from None
        if not isinstance(value, dict):
            raise GitHubCapabilityError("github_issuer_response_invalid")
        return value


@dataclass(frozen=True)
class GitHubAssignment:
    run_id: str
    issue_id: int
    task_id: str
    trace_id: str
    idempotency_key: str
    owner: str
    repo: str
    revision: str
    paths: tuple[str, ...]

    @property
    def issuer_scope(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "owner": self.owner,
            "repo": self.repo,
            "revision": self.revision,
            "paths": list(self.paths),
        }


def _strict_json_document(text: str, error_code: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GitHubCapabilityError(error_code)
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        raise GitHubCapabilityError(error_code)

    try:
        return json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError:
        raise GitHubCapabilityError(error_code) from None


def _safe_github_string(
    value: Any,
    pattern: re.Pattern[str],
    *,
    maximum: int,
) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or CONTROL_CHARACTER_RE.search(value) is not None
        or pattern.fullmatch(value) is None
    ):
        raise GitHubCapabilityError("github_assignment_invalid")
    return value


def _github_path(value: Any) -> str:
    if not isinstance(value, str) or GITHUB_PATH_RE.fullmatch(value) is None:
        raise GitHubCapabilityError("github_assignment_invalid")
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != value
        or value.endswith("/")
        or "//" in value
        or "\\" in value
        or CONTROL_CHARACTER_RE.search(value) is not None
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise GitHubCapabilityError("github_assignment_invalid")
    return value


def _github_assignment(value: Any) -> GitHubAssignment:
    if not isinstance(value, dict) or set(value) != GITHUB_REQUEST_FIELDS:
        raise GitHubCapabilityError("github_assignment_invalid")
    if value.get("schema") != GITHUB_REQUEST_SCHEMA:
        raise GitHubCapabilityError("github_assignment_invalid")
    run_id = _safe_github_string(value.get("run_id"), GITHUB_RUN_ID_RE, maximum=128)
    task_id = _safe_github_string(value.get("task_id"), GITHUB_TASK_ID_RE, maximum=128)
    issue_id = value.get("issue_id")
    if (
        isinstance(issue_id, bool)
        or not isinstance(issue_id, int)
        or not 1 <= issue_id <= 2**63 - 1
    ):
        raise GitHubCapabilityError("github_assignment_invalid")
    trace_id = _safe_github_string(value.get("trace_id"), GITHUB_RUN_ID_RE, maximum=128)
    idempotency_key = value.get("idempotency_key")
    if (
        not isinstance(idempotency_key, str)
        or not 1 <= len(idempotency_key) <= 300
        or idempotency_key != idempotency_key.strip()
        or CONTROL_CHARACTER_RE.search(idempotency_key) is not None
    ):
        raise GitHubCapabilityError("github_assignment_invalid")
    if trace_id != f"{run_id}:{task_id}" or idempotency_key != (
        f"{run_id}:{task_id}:{GITHUB_CONSUMER}:{GITHUB_SKILL}"
    ):
        raise GitHubCapabilityError("github_assignment_invalid")
    repository = value.get("repository")
    if not isinstance(repository, dict) or set(repository) != {"owner", "repo"}:
        raise GitHubCapabilityError("github_assignment_invalid")
    owner = _safe_github_string(repository.get("owner"), GITHUB_OWNER_RE, maximum=39)
    repo = _safe_github_string(repository.get("repo"), GITHUB_REPO_RE, maximum=100)
    if "--" in owner or repo in {".", ".."}:
        raise GitHubCapabilityError("github_assignment_invalid")
    revision = _safe_github_string(value.get("revision"), GITHUB_REVISION_RE, maximum=40)
    raw_paths = value.get("paths")
    if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= 32:
        raise GitHubCapabilityError("github_assignment_invalid")
    paths = tuple(_github_path(path) for path in raw_paths)
    if list(paths) != sorted(set(paths)):
        raise GitHubCapabilityError("github_assignment_invalid")
    return GitHubAssignment(
        run_id=run_id,
        issue_id=issue_id,
        task_id=task_id,
        trace_id=trace_id,
        idempotency_key=idempotency_key,
        owner=owner,
        repo=repo,
        revision=revision,
        paths=paths,
    )


def _task_payload(arguments: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    raw = arguments.get("payload")
    if isinstance(raw, dict):
        return dict(raw), False
    if isinstance(raw, str) and raw.strip().startswith("{"):
        value = _strict_json_document(raw, "github_assignment_invalid")
        if not isinstance(value, dict):
            raise GitHubCapabilityError("github_assignment_invalid")
        return value, True
    if raw is None:
        return {}, False
    return {}, False


def _argument_value(
    arguments: dict[str, Any],
    payload: dict[str, Any],
    aliases: tuple[str, ...],
) -> Any:
    values = [
        container[key] for container in (arguments, payload) for key in aliases if key in container
    ]
    if not values or any(value != values[0] for value in values[1:]):
        raise GitHubCapabilityError("github_assignment_scope_mismatch")
    return values[0]


def _github_spec(
    arguments: dict[str, Any], payload: dict[str, Any]
) -> tuple[dict[str, Any] | None, bool]:
    specs = [container["spec"] for container in (arguments, payload) if "spec" in container]
    if not specs:
        return None, False
    github_candidate = False
    parsed: list[Any] = []
    for raw in specs:
        if not isinstance(raw, str):
            continue
        stripped = raw.strip()
        if not stripped.startswith("{"):
            continue
        mentions_schema = GITHUB_REQUEST_SCHEMA_PREFIX in stripped
        try:
            value = _strict_json_document(stripped, "github_assignment_invalid")
        except GitHubCapabilityError:
            if mentions_schema:
                raise
            continue
        parsed.append(value)
        if (
            isinstance(value, dict)
            and isinstance(value.get("schema"), str)
            and value["schema"].startswith(GITHUB_REQUEST_SCHEMA_PREFIX)
        ):
            github_candidate = True
    if not github_candidate:
        return None, False
    if (
        any(not isinstance(raw, str) for raw in specs)
        or len(set(cast(str, raw) for raw in specs)) != 1
        or len(parsed) != len(specs)
        or not isinstance(parsed[0], dict)
        or any(
            not isinstance(value, dict) or _canonical_json(value).decode("utf-8") != cast(str, raw)
            for raw, value in zip(specs, parsed, strict=True)
        )
    ):
        raise GitHubCapabilityError("github_assignment_invalid")
    return cast(dict[str, Any], parsed[0]), True


def _token_source(path: Path) -> Path:
    try:
        if not path.is_symlink():
            return path
        if path != PRODUCTION_SERVICE_ACCOUNT_TOKEN:
            raise GitHubCapabilityError("github_service_account_token_invalid")
        if os.readlink(path) != "..data/token":
            raise GitHubCapabilityError("github_service_account_token_invalid")
        parent = path.parent.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(parent)
        return resolved
    except (OSError, RuntimeError, ValueError):
        raise GitHubCapabilityError("github_service_account_token_invalid") from None


def _service_account_token(path: Path) -> str:
    source = _token_source(path)
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 1
            or metadata.st_size > GITHUB_MAX_TOKEN_BYTES
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise GitHubCapabilityError("github_service_account_token_invalid")
        chunks: list[bytes] = []
        remaining = GITHUB_MAX_TOKEN_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != metadata.st_size:
            raise GitHubCapabilityError("github_service_account_token_invalid")
    except GitHubCapabilityError:
        raise
    except OSError:
        raise GitHubCapabilityError("github_service_account_token_invalid") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        token = raw.decode("ascii").rstrip("\r\n")
    except UnicodeError:
        raise GitHubCapabilityError("github_service_account_token_invalid") from None
    if not token or len(raw) > GITHUB_MAX_TOKEN_BYTES or GITHUB_TOKEN_RE.fullmatch(token) is None:
        raise GitHubCapabilityError("github_service_account_token_invalid")
    return token


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_capability_claims(capability: str) -> dict[str, Any]:
    if GITHUB_CAPABILITY_RE.fullmatch(capability) is None:
        raise GitHubCapabilityError("github_issuer_response_invalid")
    encoded, _signature = capability.split(".", 1)
    try:
        raw = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        raise GitHubCapabilityError("github_issuer_response_invalid") from None
    if _base64url(raw) != encoded:
        raise GitHubCapabilityError("github_issuer_response_invalid")
    try:
        claims = _strict_json_document(raw.decode("utf-8"), "github_issuer_response_invalid")
    except UnicodeError:
        raise GitHubCapabilityError("github_issuer_response_invalid") from None
    if (
        not isinstance(claims, dict)
        or set(claims) != GITHUB_CAPABILITY_FIELDS
        or _canonical_json(claims) != raw
    ):
        raise GitHubCapabilityError("github_issuer_response_invalid")
    return claims


def _capability_from_response(
    response: dict[str, Any],
    assignment: GitHubAssignment,
    now: dt.datetime,
) -> str:
    if set(response) != GITHUB_RESPONSE_FIELDS:
        raise GitHubCapabilityError("github_issuer_response_invalid")
    capability = response.get("capability")
    expires_at = response.get("expires_at")
    jti = response.get("jti")
    if (
        response.get("schema") != GITHUB_CAPABILITY_SCHEMA
        or not isinstance(capability, str)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or not isinstance(jti, str)
        or GITHUB_JTI_RE.fullmatch(jti) is None
    ):
        raise GitHubCapabilityError("github_issuer_response_invalid")
    claims = _decode_capability_claims(capability)
    if (
        claims.get("schema") != GITHUB_CAPABILITY_SCHEMA
        or claims.get("task_id") != assignment.task_id
        or claims.get("owner") != assignment.owner
        or claims.get("repo") != assignment.repo
        or claims.get("revision") != assignment.revision
        or claims.get("paths") != list(assignment.paths)
        or claims.get("jti") != jti
        or claims.get("exp") != expires_at
    ):
        raise GitHubCapabilityError("github_issuer_scope_mismatch")
    iat = claims.get("iat")
    exp = claims.get("exp")
    current = int(now.timestamp())
    if (
        isinstance(iat, bool)
        or not isinstance(iat, int)
        or isinstance(exp, bool)
        or not isinstance(exp, int)
        or not iat <= current < exp
        or not 1 <= exp - iat <= GITHUB_MAX_CAPABILITY_LIFETIME_SECONDS
    ):
        raise GitHubCapabilityError("github_issuer_response_invalid")
    return capability


def _utc_now(clock: Callable[[], dt.datetime]) -> dt.datetime:
    now = clock()
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise GitHubCapabilityError("github_clock_invalid")
    return now.astimezone(dt.timezone.utc).replace(microsecond=0)


def _github_handoff(assignment: GitHubAssignment, capability: str, now: dt.datetime) -> str:
    inline = {
        "repository": {"owner": assignment.owner, "repo": assignment.repo},
        "revision": assignment.revision,
        "paths": list(assignment.paths),
        "capability": capability,
    }
    envelope = {
        "envelope_version": "1.0",
        "run_id": assignment.run_id,
        "issue_id": assignment.issue_id,
        "task_id": assignment.task_id,
        "producer": GITHUB_PRODUCER,
        "consumer": GITHUB_CONSUMER,
        "skill": GITHUB_SKILL,
        "trace_id": assignment.trace_id,
        "idempotency_key": assignment.idempotency_key,
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "ready",
        "artifact": {
            "type": GITHUB_ARTIFACT_TYPE,
            "schema_version": "1.0",
            "inline": inline,
            "sha256": hashlib.sha256(_canonical_json(inline)).hexdigest(),
        },
    }
    return _canonical_json(envelope).decode("utf-8")


def _guard_github_delegation(
    arguments: dict[str, Any],
    *,
    role: str,
    action: str,
    issuer: CapabilityIssuer,
    clock: Callable[[], dt.datetime],
    token_path: Path,
) -> dict[str, Any]:
    payload, serialized_payload = _task_payload(arguments)
    document, is_github = _github_spec(arguments, payload)
    if not is_github:
        return arguments
    if role != "leader" or action != "delegate_task" or document is None:
        raise GitHubCapabilityError("github_assignment_scope_mismatch")
    assignment = _github_assignment(document)
    delegated_task = _safe_github_string(
        _argument_value(arguments, payload, ("taskId", "task_id")),
        GITHUB_TASK_ID_RE,
        maximum=128,
    )
    assigned_to = _argument_value(arguments, payload, ("assignedTo", "assigned_to"))
    if delegated_task != assignment.task_id or assigned_to != GITHUB_CONSUMER:
        raise GitHubCapabilityError("github_assignment_scope_mismatch")
    now = _utc_now(clock)
    token = _service_account_token(token_path)
    try:
        response = issuer.issue(assignment.issuer_scope, token)
    except GitHubCapabilityError:
        raise
    except Exception:
        raise GitHubCapabilityError("github_issuer_unavailable") from None
    if not isinstance(response, dict):
        raise GitHubCapabilityError("github_issuer_response_invalid")
    capability = _capability_from_response(response, assignment, now)
    spec = _github_handoff(assignment, capability, now)
    guarded = dict(arguments)
    guarded["spec"] = spec
    if "payload" in arguments:
        payload["spec"] = spec
        guarded["payload"] = (
            _canonical_json(payload).decode("utf-8") if serialized_payload else payload
        )
    return guarded


def _payload_object(arguments: dict[str, Any]) -> dict[str, Any]:
    raw = arguments.get("payload")
    if isinstance(raw, dict):
        if len(_canonical_json(raw)) > MAX_PAYLOAD_BYTES:
            raise GuardPolicyError("payload_too_large")
        return dict(raw)
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8")
        except UnicodeError:
            raise GuardPolicyError("payload_invalid") from None
        if not 1 <= len(encoded) <= MAX_PAYLOAD_BYTES:
            raise GuardPolicyError("payload_too_large")
        try:
            decoded = _strict_json_document(raw, "payload_invalid")
        except GitHubCapabilityError:
            raise GuardPolicyError("payload_invalid") from None
        if isinstance(decoded, dict):
            return decoded
    if raw is None:
        return {}
    raise GuardPolicyError("payload_invalid")


def _bound_value(arguments: dict[str, Any], aliases: tuple[str, ...], field: str) -> str:
    payload = _payload_object(arguments)
    values = {
        str(container.get(alias)).strip()
        for container in (arguments, payload)
        for alias in aliases
        if container.get(alias) is not None and str(container.get(alias)).strip()
    }
    if len(values) != 1:
        raise ValueError(f"{field} must be present and unambiguous")
    value = values.pop()
    if field in {"projectId", "taskId"} and SAFE_ID_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a safe id")
    return value


def _optional_risk_tier(arguments: dict[str, Any]) -> str | None:
    payload = _payload_object(arguments)
    values = {
        str(container.get("riskTier")).strip()
        for container in (arguments, payload)
        if container.get("riskTier") is not None and str(container.get("riskTier")).strip()
    }
    values.update(
        str(container.get("risk_tier")).strip()
        for container in (arguments, payload)
        if container.get("risk_tier") is not None and str(container.get("risk_tier")).strip()
    )
    if len(values) > 1:
        raise ValueError("riskTier must be unambiguous")
    if not values:
        return None
    value = values.pop()
    if value not in RISK_TIERS:
        raise ValueError("riskTier must be one of T1, T2, T3, T4, T5")
    return value


def _optional_source(arguments: dict[str, Any]) -> str | None:
    payload = _payload_object(arguments)
    values = {
        str(container.get("source")).strip()
        for container in (arguments, payload)
        if container.get("source") is not None and str(container.get("source")).strip()
    }
    if len(values) > 1:
        raise GuardPolicyError("project_source_ambiguous")
    if not values:
        return None
    value = values.pop()
    if SOURCE_RE.fullmatch(value) is None:
        raise GuardPolicyError("project_source_invalid")
    return value


def _required_source(arguments: dict[str, Any]) -> str:
    source = _optional_source(arguments)
    if source is None:
        raise GuardPolicyError("project_source_required")
    return source


def _target_digest(arguments: dict[str, Any]) -> str:
    target = json.loads(json.dumps(arguments))
    if not isinstance(target, dict):
        raise ValueError("projectflow arguments must be an object")
    target.pop("approval", None)
    target.pop("role", None)
    target.pop("workspaceDir", None)
    if isinstance(target.get("payload"), str):
        target["payload"] = _payload_object(arguments)
    return hashlib.sha256(_canonical_json({"tool": "projectflow", "arguments": target})).hexdigest()


def _read_ledger(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError:
        raise GuardPolicyError("approval_ledger_unavailable") from None
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or (
            PRODUCTION_MODE
            and (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600)
        )
    ):
        raise GuardPolicyError("approval_ledger_permissions_invalid")
    value = _load_object(path)
    if set(value) != {"schemaVersion", "projects", "usedNonces"}:
        raise GuardPolicyError("approval_ledger_schema_invalid")
    if (
        value.get("schemaVersion") != "1.0"
        or not isinstance(value.get("projects"), dict)
        or not isinstance(value.get("usedNonces"), dict)
    ):
        raise GuardPolicyError("approval_ledger_schema_invalid")
    return value


def _write_ledger(path: Path, ledger: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(_canonical_json(ledger) + b"\n")
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _process_identity(pid: int) -> tuple[bool, str | None]:
    """Return ``(alive, identity)`` without treating an unknown live PID as stale."""

    if pid < 1:
        return False, None
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            process = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
            if not process:
                error = ctypes.get_last_error()
                return (True, None) if error == 5 else (False, None)
            try:
                created = wintypes.FILETIME()
                exited = wintypes.FILETIME()
                kernel = wintypes.FILETIME()
                user = wintypes.FILETIME()
                if not ctypes.windll.kernel32.GetProcessTimes(
                    process,
                    ctypes.byref(created),
                    ctypes.byref(exited),
                    ctypes.byref(kernel),
                    ctypes.byref(user),
                ):
                    return True, None
                created_ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
            finally:
                ctypes.windll.kernel32.CloseHandle(process)
            raw = f"windows\0{pid}\0{created_ticks}".encode("ascii")
            return True, hashlib.sha256(raw).hexdigest()
        except (AttributeError, OSError, ValueError):
            return True, None

    stat_path = Path(f"/proc/{pid}/stat")
    try:
        process_stat = stat_path.read_text(encoding="ascii")
        closing = process_stat.rfind(")")
        fields = process_stat[closing + 2 :].split()
        start_ticks = fields[19]
        try:
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()
        except OSError:
            boot_id = "unknown-boot"
        raw = f"proc\0{pid}\0{boot_id}\0{start_ticks}".encode("ascii")
        return True, hashlib.sha256(raw).hexdigest()
    except (IndexError, OSError, UnicodeError):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False, None
        except PermissionError:
            return True, None
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                return False, None
            return True, None
        return True, None


def _read_lock_owner(lock_path: Path) -> tuple[dict[str, Any], bytes] | None:
    owner_path = lock_path / LEDGER_LOCK_OWNER_FILE
    try:
        metadata = owner_path.lstat()
        if (
            owner_path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > LEDGER_LOCK_MAX_OWNER_BYTES
        ):
            return None
        payload = owner_path.read_bytes()
        value = json.loads(payload)
    except (OSError, UnicodeError, ValueError):
        return None
    if (
        not isinstance(value, dict)
        or set(value) != LEDGER_LOCK_OWNER_FIELDS
        or value.get("schemaVersion") != LEDGER_LOCK_OWNER_SCHEMA
        or isinstance(value.get("pid"), bool)
        or not isinstance(value.get("pid"), int)
        or value["pid"] < 1
        or not isinstance(value.get("processIdentity"), str)
        or DIGEST_RE.fullmatch(value["processIdentity"]) is None
        or not isinstance(value.get("nonce"), str)
        or LEDGER_LOCK_NONCE_RE.fullmatch(value["nonce"]) is None
    ):
        return None
    return value, payload


def _remove_stale_ledger_lock(lock_path: Path) -> bool:
    """Remove only an unchanged lock whose recorded process is provably gone."""

    owner = _read_lock_owner(lock_path)
    if owner is None:
        return False
    value, original_payload = owner
    alive, observed_identity = _process_identity(value["pid"])
    if alive and (
        observed_identity is None or observed_identity == value["processIdentity"]
    ):
        return False
    owner_path = lock_path / LEDGER_LOCK_OWNER_FILE
    try:
        if owner_path.read_bytes() != original_payload:
            return False
        owner_path.unlink()
        lock_path.rmdir()
    except OSError:
        return False
    return True


@contextmanager
def _ledger_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(f".{path.name}.lock")
    acquired = False
    for attempt in range(2):
        try:
            lock_path.mkdir(mode=0o700)
            acquired = True
            break
        except FileExistsError as exc:
            if attempt == 0 and _remove_stale_ledger_lock(lock_path):
                continue
            raise ValueError("approval ledger is busy") from exc
    if not acquired:  # pragma: no cover - bounded loop invariant
        raise ValueError("approval ledger is busy")

    alive, identity = _process_identity(os.getpid())
    if not alive or identity is None:
        with suppress(OSError):
            lock_path.rmdir()
        raise ValueError("approval ledger lock identity is unavailable")
    nonce = secrets.token_hex(32)
    owner = {
        "schemaVersion": LEDGER_LOCK_OWNER_SCHEMA,
        "pid": os.getpid(),
        "processIdentity": identity,
        "nonce": nonce,
    }
    owner_path = lock_path / LEDGER_LOCK_OWNER_FILE
    try:
        descriptor = os.open(
            owner_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical_json(owner) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        with suppress(OSError):
            owner_path.unlink()
        with suppress(OSError):
            lock_path.rmdir()
        raise
    try:
        yield
    finally:
        retained = _read_lock_owner(lock_path)
        if retained is None or retained[0] != owner:
            raise ValueError("approval ledger lock ownership was lost")
        owner_path.unlink()
        lock_path.rmdir()


def _parse_timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or RFC3339_UTC_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be canonical UTC RFC3339")
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def _verify_ed25519(policy: dict[str, Any], canonical_evidence: bytes, signature: str) -> bool:
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error):
        return False
    if len(signature_bytes) != 64:
        return False
    with tempfile.TemporaryDirectory(prefix="devflow-approval-") as directory:
        root = Path(directory)
        evidence_path = root / "evidence.json"
        signature_path = root / "signature.bin"
        evidence_path.write_bytes(canonical_evidence)
        signature_path.write_bytes(signature_bytes)
        try:
            completed = subprocess.run(
                [
                    str(policy["opensslPath"]),
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(policy["publicKeyPath"]),
                    "-rawin",
                    "-in",
                    str(evidence_path),
                    "-sigfile",
                    str(signature_path),
                ],
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return False
    return completed.returncode == 0


def _bind_project_risk(
    policy: dict[str, Any],
    project_id: str,
    risk_tier: str,
    source: str,
    target_digest: str,
) -> None:
    ledger_path = Path(str(policy["ledgerPath"]))
    with _ledger_lock(ledger_path):
        ledger = _read_ledger(ledger_path)
        projects = cast(dict[str, Any], ledger["projects"])
        if project_id in projects:
            raise ValueError("project risk is already bound")
        incarnation = secrets.token_hex(32)
        binding = {
            "riskTier": risk_tier,
            "createdTargetDigest": target_digest,
            "source": source,
            "incarnation": incarnation,
            "audience": policy["audience"],
            "approvalDomain": policy["approvalDomain"],
            "policyKeySha256": policy["policyKeySha256"],
        }
        binding["projectBindingDigest"] = _project_binding_digest(
            project_id,
            binding,
        )
        projects[project_id] = binding
        _write_ledger(ledger_path, ledger)


def _legacy_project_binding_digest(project_id: str, risk_tier: str, source: str) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "projectId": project_id,
                "riskTier": risk_tier,
                "source": source,
            }
        )
    ).hexdigest()


def _project_binding_digest(project_id: str, binding: dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "schema": "devflow.project-binding/v2",
                "audience": binding.get("audience"),
                "approvalDomain": binding.get("approvalDomain"),
                "policyKeySha256": binding.get("policyKeySha256"),
                "projectId": project_id,
                "riskTier": binding.get("riskTier"),
                "source": binding.get("source"),
                "createdTargetDigest": binding.get("createdTargetDigest"),
                "incarnation": binding.get("incarnation"),
            }
        )
    ).hexdigest()


def _ledger_project(
    policy: dict[str, Any],
    project_id: str,
) -> tuple[dict[str, Any], bool]:
    ledger = _read_ledger(Path(str(policy["ledgerPath"])))
    project = cast(dict[str, Any], ledger["projects"]).get(project_id)
    if not isinstance(project, dict) or frozenset(project) not in {
        RISK_ONLY_PROJECT_BINDING_FIELDS,
        LEGACY_PROJECT_BINDING_FIELDS,
        PROJECT_BINDING_FIELDS,
    }:
        raise GuardPolicyError("project_binding_missing")
    risk_tier = project.get("riskTier")
    target_digest = project.get("createdTargetDigest")
    if risk_tier not in RISK_TIERS or not isinstance(target_digest, str) or re.fullmatch(
        r"[0-9a-f]{64}", target_digest
    ) is None:
        raise GuardPolicyError("project_binding_invalid")
    fields = frozenset(project)
    legacy = fields != PROJECT_BINDING_FIELDS
    if fields == LEGACY_PROJECT_BINDING_FIELDS:
        source = project.get("source")
        expected = _legacy_project_binding_digest(
            project_id, str(risk_tier), str(source or "")
        )
        if (
            not isinstance(source, str)
            or SOURCE_RE.fullmatch(source) is None
            or project.get("bindingDigest") != expected
        ):
            raise GuardPolicyError("project_binding_invalid")
    elif fields == PROJECT_BINDING_FIELDS:
        source = project.get("source")
        incarnation = project.get("incarnation")
        if (
            not isinstance(source, str)
            or SOURCE_RE.fullmatch(source) is None
            or not isinstance(incarnation, str)
            or DIGEST_RE.fullmatch(incarnation) is None
            or project.get("audience") != policy.get("audience")
            or project.get("approvalDomain") != policy.get("approvalDomain")
            or project.get("policyKeySha256") != policy.get("policyKeySha256")
            or project.get("projectBindingDigest")
            != _project_binding_digest(project_id, project)
        ):
            raise GuardPolicyError("project_binding_invalid")
    return dict(project), legacy


def _project_risk(policy: dict[str, Any], project_id: str, arguments: dict[str, Any]) -> str:
    project, _legacy = _ledger_project(policy, project_id)
    risk_tier = str(project["riskTier"])
    requested = _optional_risk_tier(arguments)
    if requested is not None and requested != risk_tier:
        raise ValueError("request riskTier conflicts with the project binding")
    return risk_tier


def _action_payload(response: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(response, dict):
        return None
    result = response.get("result")
    if not isinstance(result, dict):
        return None
    if isinstance(result.get("ok"), bool):
        return dict(result)
    content = result.get("content")
    if not isinstance(content, list) or len(content) != 1:
        return None
    item = content[0]
    if not isinstance(item, dict) or item.get("type") != "text":
        return None
    text = item.get("text")
    if not isinstance(text, str):
        return None
    try:
        if not 1 <= len(text.encode("utf-8")) <= MAX_PAYLOAD_BYTES:
            return None
        decoded = _strict_json_document(text, "upstream_response_invalid")
    except (GitHubCapabilityError, UnicodeError):
        return None
    return dict(decoded) if isinstance(decoded, dict) else None


def _replace_action_payload(
    response: dict[str, Any],
    payload: dict[str, Any],
) -> dict[str, Any]:
    result = response.get("result")
    if not isinstance(result, dict):
        raise GuardPolicyError("upstream_response_invalid")
    if isinstance(result.get("ok"), bool):
        return {"jsonrpc": "2.0", "id": response.get("id"), "result": payload}
    content = result.get("content")
    if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict):
        raise GuardPolicyError("upstream_response_invalid")
    return {
        "jsonrpc": "2.0",
        "id": response.get("id"),
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": _canonical_json(payload).decode("utf-8"),
                }
            ]
        },
    }


def _project_from_payload(payload: dict[str, Any], project_id: str) -> dict[str, Any]:
    project = payload.get("project")
    if not isinstance(project, dict) or project.get("project_id") != project_id:
        raise GuardPolicyError("project_state_invalid")
    source = project.get("source")
    if not isinstance(source, str) or SOURCE_RE.fullmatch(source) is None:
        raise GuardPolicyError("project_state_invalid")
    return dict(project)


def _project_probe(
    request_id: Any,
    project_id: str,
    workspace: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    response = upstream.handle_request(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": "projectflow",
                "arguments": {
                    "action": "resolve_project",
                    "payload": {"projectId": project_id},
                    "workspaceDir": workspace,
                },
            },
        }
    )
    if not isinstance(response, dict):
        raise GuardPolicyError("project_state_unavailable")
    payload = _action_payload(response)
    if payload is None or payload.get("ok") is not True:
        raise GuardPolicyError("project_state_unavailable")
    return dict(response), _project_from_payload(payload, project_id)


def _upgrade_legacy_project_binding(
    policy: dict[str, Any],
    project_id: str,
    source: str,
) -> dict[str, Any]:
    ledger_path = Path(str(policy["ledgerPath"]))
    with _ledger_lock(ledger_path):
        ledger = _read_ledger(ledger_path)
        projects = cast(dict[str, Any], ledger["projects"])
        current = projects.get(project_id)
        if not isinstance(current, dict):
            raise GuardPolicyError("project_binding_changed")
        fields = frozenset(current)
        if fields == PROJECT_BINDING_FIELDS:
            checked, legacy = _ledger_project(policy, project_id)
            if legacy or checked.get("source") != source:
                raise GuardPolicyError("project_binding_changed")
            return checked
        if fields not in {
            RISK_ONLY_PROJECT_BINDING_FIELDS,
            LEGACY_PROJECT_BINDING_FIELDS,
        }:
            raise GuardPolicyError("project_binding_changed")
        risk_tier = str(current.get("riskTier") or "")
        target_digest = current.get("createdTargetDigest")
        if (
            risk_tier not in RISK_TIERS
            or not isinstance(target_digest, str)
            or DIGEST_RE.fullmatch(target_digest) is None
            or (
                fields == LEGACY_PROJECT_BINDING_FIELDS
                and (
                    current.get("source") != source
                    or current.get("bindingDigest")
                    != _legacy_project_binding_digest(project_id, risk_tier, source)
                )
            )
        ):
            raise GuardPolicyError("project_binding_changed")
        upgraded = {
            "riskTier": risk_tier,
            "createdTargetDigest": target_digest,
            "source": source,
            "incarnation": secrets.token_hex(32),
            "audience": policy["audience"],
            "approvalDomain": policy["approvalDomain"],
            "policyKeySha256": policy["policyKeySha256"],
        }
        upgraded["projectBindingDigest"] = _project_binding_digest(project_id, upgraded)
        projects[project_id] = upgraded
        _write_ledger(ledger_path, ledger)
        return dict(upgraded)


def _verified_project_binding(
    policy: dict[str, Any],
    request_id: Any,
    arguments: dict[str, Any],
    project_id: str,
    workspace: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    binding, legacy = _ledger_project(policy, project_id)
    _response, project = _project_probe(request_id, project_id, workspace)
    source = str(project["source"])
    if legacy:
        binding = _upgrade_legacy_project_binding(policy, project_id, source)
    elif binding.get("source") != source:
        raise GuardPolicyError("project_source_state_mismatch")
    risk_tier = str(binding["riskTier"])
    requested_risk = _optional_risk_tier(arguments)
    requested_source = _optional_source(arguments)
    if requested_risk is not None and requested_risk != risk_tier:
        raise GuardPolicyError("project_risk_request_mismatch")
    if requested_source is not None and requested_source != source:
        raise GuardPolicyError("project_source_request_mismatch")
    expected_digest = _project_binding_digest(project_id, binding)
    if binding.get("projectBindingDigest") != expected_digest:
        raise GuardPolicyError("project_binding_invalid")
    return binding, project


def _project_binding_attestation(binding: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "devflow.project-binding/v2",
        "audience": binding["audience"],
        "approvalDomain": binding["approvalDomain"],
        "policyKeySha256": binding["policyKeySha256"],
        "riskTierAuthority": "root-only-approval-ledger",
        "sourceAuthority": "persistent-project-state",
        "incarnationAuthority": "guard-generated-root-only-approval-ledger",
        "projectBindingDigest": binding["projectBindingDigest"],
    }


def _attest_project_response(
    response: dict[str, Any],
    project_id: str,
    binding: dict[str, Any],
) -> dict[str, Any]:
    payload = _action_payload(response)
    if payload is None or payload.get("ok") is not True:
        raise GuardPolicyError("project_action_failed")
    project = payload.get("project")
    if project is not None:
        checked = _project_from_payload(payload, project_id)
        if checked["source"] != binding["source"]:
            raise GuardPolicyError("project_source_state_mismatch")
        existing_risk = checked.get("risk_tier")
        if existing_risk is not None and existing_risk != binding["riskTier"]:
            raise GuardPolicyError("project_risk_state_mismatch")
        checked["risk_tier"] = binding["riskTier"]
        checked["binding"] = _project_binding_attestation(binding)
        payload["project"] = checked
    payload["binding"] = _project_binding_attestation(binding)
    return _replace_action_payload(response, payload)


def _task_room_invitees(arguments: dict[str, Any], identity: dict[str, str]) -> list[str]:
    payload = _payload_object(arguments)
    forbidden = {
        "admin",
        "adminUser",
        "admin_user",
        "creation_content",
        "initial_state",
        "isPublic",
        "power_level_content_override",
        "preset",
        "private",
        "visibility",
    }
    if any(key in arguments or key in payload for key in forbidden):
        raise GuardPolicyError("task_room_security_override_forbidden")
    if "invite" in arguments or not isinstance(payload.get("invite"), list):
        raise GuardPolicyError("task_room_invite_invalid")
    raw = cast(list[Any], payload["invite"])
    if len(raw) != 1 or not isinstance(raw[0], str):
        raise GuardPolicyError("task_room_invite_invalid")
    invitee = raw[0]
    if (
        invitee != invitee.strip()
        or MATRIX_USER_RE.fullmatch(invitee) is None
        or invitee == identity["matrixUserId"]
    ):
        raise GuardPolicyError("task_room_invite_invalid")
    if arguments.get("dryRun") is not None or payload.get("dryRun") is not None:
        raise GuardPolicyError("task_room_dry_run_forbidden")
    return [invitee]


def _upstream_admin() -> str:
    getter = getattr(upstream, "_runtime_team_admin_user_id", None)
    if not callable(getter):
        return ""
    try:
        value = getter()
    except Exception:
        raise GuardPolicyError("task_room_admin_unavailable") from None
    if not isinstance(value, str):
        raise GuardPolicyError("task_room_admin_invalid")
    value = value.strip()
    if value and MATRIX_USER_RE.fullmatch(value) is None:
        raise GuardPolicyError("task_room_admin_invalid")
    return value


def _matrix_membership_state(
    state: dict[str, Any],
) -> tuple[str, dict[str, str]]:
    if set(state) != {"joinRules", "members"}:
        raise GuardPolicyError("matrix_state_invalid")
    join_rules = state.get("joinRules")
    members = state.get("members")
    if not isinstance(join_rules, dict) or join_rules.get("join_rule") != "invite":
        raise GuardPolicyError("matrix_room_not_private")
    if not isinstance(members, dict) or not isinstance(members.get("chunk"), list):
        raise GuardPolicyError("matrix_state_invalid")
    active: dict[str, str] = {}
    for event in cast(list[Any], members["chunk"]):
        if not isinstance(event, dict):
            raise GuardPolicyError("matrix_state_invalid")
        user_id = event.get("state_key")
        content = event.get("content")
        membership = content.get("membership") if isinstance(content, dict) else None
        if membership not in {"join", "invite", "leave", "ban", "knock"}:
            raise GuardPolicyError("matrix_state_invalid")
        if not isinstance(user_id, str) or MATRIX_USER_RE.fullmatch(user_id) is None:
            raise GuardPolicyError("matrix_state_invalid")
        if membership in {"join", "invite"}:
            if user_id in active:
                raise GuardPolicyError("matrix_state_invalid")
            active[user_id] = str(membership)
    return "invite", active


def _attest_task_room_response(
    response: dict[str, Any],
    *,
    identity: dict[str, str],
    project_id: str,
    invitees: list[str],
    binding: dict[str, Any],
    state_reader: MatrixStateReader,
) -> dict[str, Any]:
    payload = _action_payload(response)
    if payload is None or payload.get("ok") is not True:
        raise GuardPolicyError("task_room_creation_failed")
    room_id = payload.get("roomId")
    reused_value = payload.get("reused", False)
    content = payload.get("content")
    if (
        not isinstance(room_id, str)
        or MATRIX_ROOM_RE.fullmatch(room_id) is None
        or not isinstance(reused_value, bool)
        or not isinstance(content, dict)
        or content.get("preset") != "trusted_private_chat"
    ):
        raise GuardPolicyError("task_room_response_invalid")
    upstream_invites = content.get("invite")
    if not isinstance(upstream_invites, list) or any(
        not isinstance(item, str) or MATRIX_USER_RE.fullmatch(item) is None
        for item in upstream_invites
    ):
        raise GuardPolicyError("task_room_response_invalid")
    admin = _upstream_admin()
    expected_invites = list(invitees)
    if admin and admin not in expected_invites:
        expected_invites.append(admin)
    if upstream_invites != expected_invites:
        raise GuardPolicyError("task_room_invite_state_mismatch")
    join_rule, active_members = _matrix_membership_state(state_reader.read(room_id))
    creator = identity["matrixUserId"]
    expected_members = {creator, *expected_invites}
    if set(active_members) != expected_members or active_members.get(creator) != "join":
        raise GuardPolicyError("task_room_membership_state_mismatch")
    if any(active_members.get(invitee) not in {"join", "invite"} for invitee in expected_invites):
        raise GuardPolicyError("task_room_membership_state_mismatch")
    member_digest = hashlib.sha256(_canonical_json(sorted(expected_members))).hexdigest()
    secured = {
        "ok": True,
        "tool": "roomflow",
        "action": "create_task_room",
        "projectId": project_id,
        "roomId": room_id,
        "reused": reused_value,
        "private": True,
        "invite": invitees,
        # Compatibility name: these are the exact non-creator authorized invitees,
        # not a claim that the Matrix creator is absent from room state.
        "members": invitees,
        "membershipProjection": "non-creator-requested-worker-invitees",
        "creator": creator,
        "joinRule": join_rule,
        "membershipStateVerified": True,
        "authorizedMemberCount": len(expected_members),
        "authorizedMembersSha256": member_digest,
        "binding": _project_binding_attestation(binding),
    }
    return _replace_action_payload(response, secured)


def _validate_approval(
    policy: dict[str, Any],
    arguments: dict[str, Any],
    *,
    binding: dict[str, Any],
    action: str,
    project_id: str,
    task_id: str | None,
    risk_tier: str,
) -> tuple[dict[str, Any], str]:
    approval = arguments.get("approval")
    if not isinstance(approval, dict) or set(approval) != {"evidence", "signature"}:
        raise ValueError("approval must contain exactly evidence and signature")
    evidence = approval.get("evidence")
    expected_fields = {
        "schemaVersion",
        "audience",
        "approvalDomain",
        "policyKeySha256",
        "projectBindingDigest",
        "approvalRequestDigest",
        "action",
        "projectId",
        "riskTier",
        "targetDigest",
        "approvedBy",
        "issuedAt",
        "expiresAt",
        "nonce",
    }
    if task_id is not None:
        expected_fields.add("taskId")
    if not isinstance(evidence, dict) or set(evidence) != expected_fields:
        raise ValueError("approval evidence schema mismatch")
    if (
        evidence.get("schemaVersion") != "1.1"
        or evidence.get("audience") != policy.get("audience")
        or evidence.get("approvalDomain") != policy.get("approvalDomain")
        or evidence.get("policyKeySha256") != policy.get("policyKeySha256")
        or evidence.get("projectBindingDigest")
        != binding.get("projectBindingDigest")
        or evidence.get("action") != action
        or evidence.get("projectId") != project_id
        or evidence.get("riskTier") != risk_tier
        or (task_id is not None and evidence.get("taskId") != task_id)
    ):
        raise ValueError("approval evidence scope mismatch")
    target_digest = _target_digest(arguments)
    if evidence.get("targetDigest") != target_digest:
        raise ValueError("approval targetDigest mismatch")
    approval_request: dict[str, Any] = {
        "schema": APPROVAL_REQUEST_SCHEMA,
        "audience": policy["audience"],
        "approvalDomain": policy["approvalDomain"],
        "policyKeySha256": policy["policyKeySha256"],
        "projectBindingDigest": binding["projectBindingDigest"],
        "action": action,
        "projectId": project_id,
        "riskTier": risk_tier,
        "targetDigest": target_digest,
    }
    if task_id is not None:
        approval_request["taskId"] = task_id
    expected_request_digest = hashlib.sha256(
        _canonical_json(approval_request)
    ).hexdigest()
    if evidence.get("approvalRequestDigest") != expected_request_digest:
        raise ValueError("approval request digest mismatch")
    approved_by = evidence.get("approvedBy")
    nonce = evidence.get("nonce")
    if not isinstance(approved_by, str) or APPROVER_RE.fullmatch(approved_by) is None:
        raise ValueError("approvedBy is invalid")
    if not isinstance(nonce, str) or NONCE_RE.fullmatch(nonce) is None:
        raise ValueError("approval nonce is invalid")
    issued_at = _parse_timestamp(evidence.get("issuedAt"), "issuedAt")
    expires_at = _parse_timestamp(evidence.get("expiresAt"), "expiresAt")
    now = dt.datetime.now(tz=dt.timezone.utc).replace(microsecond=0)
    if issued_at > now or expires_at <= now or expires_at <= issued_at:
        raise ValueError("approval is not currently valid")
    if (expires_at - issued_at).total_seconds() > policy["maxApprovalLifetimeSeconds"]:
        raise ValueError("approval lifetime exceeds policy")
    signature = approval.get("signature")
    if not isinstance(signature, str) or not _verify_ed25519(
        policy, _canonical_json(evidence), signature
    ):
        raise ValueError("approval signature verification failed")

    return evidence, nonce


def _consume_approval_in_locked_ledger(
    ledger_path: Path,
    current: dict[str, Any],
    *,
    evidence: dict[str, Any],
    nonce: str,
    project_id: str,
    risk_tier: str,
    required_project_status: str | None = None,
    project: dict[str, Any] | None = None,
) -> None:
    current_project = cast(dict[str, Any], current["projects"]).get(project_id)
    if (
        not isinstance(current_project, dict)
        or current_project.get("riskTier") != risk_tier
        or current_project.get("projectBindingDigest")
        != evidence.get("projectBindingDigest")
    ):
        raise ValueError("project risk binding changed during approval")
    used_nonces = cast(dict[str, Any], current["usedNonces"])
    if nonce in used_nonces:
        raise ValueError("approval nonce was already used")
    if required_project_status is not None:
        status = project.get("status") if isinstance(project, dict) else None
        if not isinstance(status, str) or status.strip().lower() != required_project_status:
            raise GuardPolicyError("resume_requires_paused_project")
    used_nonces[nonce] = evidence["expiresAt"]
    _write_ledger(ledger_path, current)


def _validate_and_consume_approval(
    policy: dict[str, Any],
    arguments: dict[str, Any],
    *,
    binding: dict[str, Any],
    action: str,
    project_id: str,
    task_id: str | None,
    risk_tier: str,
) -> None:
    evidence, nonce = _validate_approval(
        policy,
        arguments,
        binding=binding,
        action=action,
        project_id=project_id,
        task_id=task_id,
        risk_tier=risk_tier,
    )
    ledger_path = Path(str(policy["ledgerPath"]))
    with _ledger_lock(ledger_path):
        current = _read_ledger(ledger_path)
        _consume_approval_in_locked_ledger(
            ledger_path,
            current,
            evidence=evidence,
            nonce=nonce,
            project_id=project_id,
            risk_tier=risk_tier,
        )


def _response_succeeded(response: dict[str, Any] | None) -> bool:
    if not isinstance(response, dict):
        return False
    ok_values = {
        value.get("ok")
        for value in _walk(response)
        if isinstance(value, dict) and isinstance(value.get("ok"), bool)
    }
    return ok_values == {True}


def _error(
    request_id: Any,
    *,
    tool: str,
    action: str = "",
    error: str = "forbidden_tool",
    role: str = "unknown",
) -> dict[str, Any]:
    payload = {"ok": False, "error": error, "tool": tool, "role": role}
    if action:
        payload["action"] = action
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}]},
    }


def _visible_tools(role: str) -> list[dict[str, Any]]:
    allowed = ROLE_TOOLS.get(role, frozenset())
    visible = [
        json.loads(json.dumps(tool))
        for tool in upstream.list_tools()
        if tool.get("name") in allowed
    ]
    for tool in visible:
        if tool.get("name") == "taskflow" and role == "leader":
            tool["description"] = (
                str(tool.get("description") or "")
                + " GitHub evidence delegation is capability-gated: assignedTo "
                "must be devflow-locator and spec must be the exact JSON request "
                "described by the spec property; the guard replaces it with a "
                "complete HandoffEnvelope v1 before delegation."
            ).strip()
            properties = tool.setdefault("inputSchema", {}).setdefault("properties", {})
            spec = properties.setdefault("spec", {"type": "string"})
            spec["description"] = (
                "Ordinary bounded task text, or canonical JSON with exactly: "
                '{"schema":"devflow.github-assignment-request/v1",'
                '"run_id":"<safe-id>","issue_id":1,'
                '"task_id":"<same-as-payload-taskId>",'
                '"trace_id":"<run_id>:<task_id>",'
                '"idempotency_key":"<run_id>:<task_id>:'
                'devflow-locator:github-evidence",'
                '"repository":{"owner":"<owner>","repo":"<repo>"},'
                '"revision":"<40-lowercase-hex>",'
                '"paths":["<1..32 sorted unique relative paths>"]}. '
                "Unknown or duplicate fields fail closed. Never include a "
                "capability, issuer URL, or token path in this request."
            )
            spec["examples"] = [
                _canonical_json(
                    {
                        "schema": GITHUB_REQUEST_SCHEMA,
                        "run_id": "run-1",
                        "issue_id": 1,
                        "task_id": "1-locate",
                        "trace_id": "run-1:1-locate",
                        "idempotency_key": ("run-1:1-locate:devflow-locator:github-evidence"),
                        "repository": {"owner": "example", "repo": "repo"},
                        "revision": "0" * 40,
                        "paths": ["README.md"],
                    }
                ).decode("utf-8")
            ]
            assigned_to = properties.setdefault("assignedTo", {"type": "string"})
            assigned_to["description"] = (
                "For GitHub assignment requests this must be exactly "
                "devflow-locator; other bounded tasks keep upstream semantics."
            )
        if tool.get("name") == "filesync":
            schema = tool.setdefault("inputSchema", {})
            properties = schema.setdefault("properties", {})
            for property_name in tuple(properties):
                if property_name not in {"action", "path", "dryRun"}:
                    properties.pop(property_name, None)
            action_property = properties.setdefault("action", {"type": "string"})
            action_property["enum"] = sorted(FILESYNC_ACTIONS)
            action_property["description"] = "Required shared-artifact operation."
            path_property = properties.setdefault("path", {"type": "string"})
            path_property["description"] = (
                "Canonical shared/... path; global-shared/... is read-only and "
                "the attested role workspace/storage binding cannot be overridden."
            )
            dry_run = properties.setdefault("dryRun", {"type": "boolean"})
            dry_run["description"] = (
                "Optional boolean; it uses the same attested binding and returns no command "
                "or remote storage path."
            )
            schema["type"] = "object"
            schema["required"] = ["action", "path"]
            schema["additionalProperties"] = False
        if tool.get("name") != "projectflow":
            continue
        properties = tool.setdefault("inputSchema", {}).setdefault("properties", {})
        properties["riskTier"] = {
            "type": "string",
            "enum": sorted(RISK_TIERS),
            "description": "Required on create and immutably bound to the project.",
        }
        properties["approval"] = {
            "type": "object",
            "additionalProperties": False,
            "required": ["evidence", "signature"],
            "properties": {
                "evidence": {
                    "type": "object",
                    "description": (
                        "Canonical JSON signed with the external Ed25519 key; "
                        "taskId is required only for accept_task_result."
                    ),
                    "additionalProperties": False,
                },
                "signature": {"type": "string", "description": "Base64 signature."},
            },
        }
    return visible


def _walk(value: Any) -> list[Any]:
    values = [value]
    if isinstance(value, dict):
        for nested in value.values():
            values.extend(_walk(nested))
    elif isinstance(value, list):
        for nested in value:
            values.extend(_walk(nested))
    elif isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        with suppress(json.JSONDecodeError):
            values.extend(_walk(json.loads(value)))
    return values


def _checked_task(response: dict[str, Any]) -> dict[str, Any] | None:
    candidates = [
        value
        for value in _walk(response)
        if isinstance(value, dict)
        and isinstance(value.get("status"), str)
        and isinstance(value.get("assigned_to") or value.get("assignedTo"), str)
    ]
    return candidates[0] if len(candidates) == 1 else None


def _new_submission_digest(arguments: dict[str, Any]) -> str:
    payload = _payload_object(arguments)
    task_id = _bound_value(arguments, ("taskId", "task_id"), "taskId")
    deliverables = payload.get("deliverables", arguments.get("deliverables", []))
    status = payload.get("status", arguments.get("status", "SUCCESS"))
    summary = payload.get("summary", arguments.get("summary", ""))
    if (
        not isinstance(deliverables, list)
        or len(deliverables) > 64
        or any(
            not isinstance(item, str)
            or not 1 <= len(item) <= 1_024
            or CONTROL_CHARACTER_RE.search(item) is not None
            for item in deliverables
        )
    ):
        raise ValueError("submit_task deliverables must be a list")
    if (
        not isinstance(status, str)
        or not 1 <= len(status) <= 64
        or CONTROL_CHARACTER_RE.search(status) is not None
        or not isinstance(summary, str)
        or len(summary.encode("utf-8")) > 16_384
        or CONTROL_CHARACTER_RE.search(summary) is not None
    ):
        raise ValueError("submit_task result fields are invalid")
    submission = {
        "taskId": task_id,
        "status": status,
        "summary": summary,
        "deliverables": deliverables,
    }
    return hashlib.sha256(_canonical_json(submission)).hexdigest()


def _existing_submission_digest(probe: dict[str, Any]) -> str:
    task = _checked_task(probe)
    if task is None:
        return ""
    task_id = str(task.get("task_id") or task.get("taskId") or "").strip()
    result_status = str(task.get("result_status") or task.get("resultStatus") or "").strip()
    summary = task.get("summary")
    deliverables = task.get("deliverables")
    if (
        SAFE_ID_RE.fullmatch(task_id) is None
        or not result_status
        or not isinstance(summary, str)
        or not isinstance(deliverables, list)
    ):
        return ""
    return hashlib.sha256(
        _canonical_json(
            {
                "taskId": task_id,
                "status": result_status,
                "summary": summary,
                "deliverables": deliverables,
            }
        )
    ).hexdigest()


def _check_task(
    request_id: Any,
    arguments: dict[str, Any],
    identity: dict[str, str],
) -> tuple[dict[str, Any] | None, str]:
    probe_arguments = dict(arguments)
    probe_arguments["action"] = "check_task"
    # The pinned upstream permits check_task only for Leader. This is an
    # internal read-only guard probe; the Worker-facing action remains hidden.
    probe_arguments["role"] = "leader"
    probe = upstream.handle_request(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": "taskflow", "arguments": probe_arguments},
        }
    )
    if not isinstance(probe, dict):
        return None, "task_probe_failed"
    task = _checked_task(probe)
    if task is None:
        return None, "task_probe_failed"
    try:
        requested_task_id = _bound_value(arguments, ("taskId", "task_id"), "taskId")
    except (GuardPolicyError, ValueError):
        return None, "task_probe_failed"
    probed_task_id = str(task.get("task_id") or task.get("taskId") or "").strip()
    if probed_task_id != requested_task_id:
        return None, "task_probe_failed"
    assigned_to = str(task.get("assigned_to") or task.get("assignedTo") or "")
    status = str(task.get("status") or "").lower()
    if assigned_to not in {identity["runtimeName"], identity["matrixUserId"]}:
        return None, "task_assignment_mismatch"
    if not status:
        return None, "task_probe_failed"
    return probe, status


def _idempotent_response(
    request_id: Any,
    *,
    action: str,
    role: str,
    state: str,
    task_id: str,
    submission_digest: str | None = None,
) -> dict[str, Any]:
    payload = {
        "ok": True,
        "idempotent": True,
        "action": action,
        "role": role,
        "taskState": state,
        "taskId": task_id,
    }
    if submission_digest is not None:
        payload["submissionDigest"] = submission_digest
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}]},
    }


def _submit_conflict_response(
    request_id: Any,
    *,
    role: str,
    task_id: str,
    current_digest: str,
    requested_digest: str,
) -> dict[str, Any]:
    payload = {
        "ok": False,
        "error": "submit_result_conflict",
        "tool": "taskflow",
        "action": "submit_task",
        "role": role,
        "taskId": task_id,
        "currentDigest": current_digest,
        "requestedDigest": requested_digest,
    }
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}]},
    }


def _guard_filesync_arguments(arguments: dict[str, Any]) -> tuple[str, str, bool]:
    if "payload" in arguments:
        raise GuardPolicyError("filesync_payload_forbidden")
    forbidden = {
        "globalSharedPrefix",
        "sharedPrefix",
        "storage",
        "workspaceDir",
        "workspace_dir",
    }
    if any(key in arguments for key in forbidden):
        raise GuardPolicyError("filesync_binding_override_forbidden")
    if "exclude" in arguments:
        raise GuardPolicyError("filesync_exclude_forbidden")
    unknown = set(arguments) - {"action", "path", "dryRun"}
    if unknown:
        raise GuardPolicyError("filesync_argument_unknown")
    action = arguments.get("action")
    raw_path = arguments.get("path")
    dry_run = arguments.get("dryRun", False)
    if not isinstance(action, str) or action not in FILESYNC_ACTIONS:
        raise GuardPolicyError("filesync_action_invalid")
    if not isinstance(dry_run, bool):
        raise GuardPolicyError("filesync_dry_run_invalid")
    if (
        not isinstance(raw_path, str)
        or raw_path != raw_path.strip()
        or not 1 <= len(raw_path.encode("utf-8")) <= 2_048
        or CONTROL_CHARACTER_RE.search(raw_path) is not None
        or raw_path.startswith("/")
        or "\\" in raw_path
        or "//" in raw_path
        or FILESYNC_SCOPE_META_RE.search(raw_path) is not None
    ):
        raise GuardPolicyError("filesync_path_invalid")
    explicit_directory = raw_path.endswith("/")
    core = raw_path[:-1] if explicit_directory else raw_path
    candidate = PurePosixPath(core)
    if (
        not core
        or candidate.is_absolute()
        or candidate.as_posix() != core
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or any(FILESYNC_SEGMENT_RE.fullmatch(part) is None for part in candidate.parts)
    ):
        raise GuardPolicyError("filesync_path_invalid")
    parts = candidate.parts
    if parts[0] not in {"shared", "global-shared"}:
        raise GuardPolicyError("filesync_path_invalid")
    if parts[0] == "global-shared":
        if action == "push":
            raise GuardPolicyError("filesync_global_push_forbidden")
        if len(parts) < 2:
            raise GuardPolicyError("filesync_path_invalid")
    elif action in {"push", "pull"} and len(parts) < 3:
        raise GuardPolicyError("filesync_path_invalid")
    inferred_directory = action in {"pull", "push", "list"} and len(parts) <= 3
    normalized = core + "/" if explicit_directory or inferred_directory else core
    return action, normalized, dry_run


@dataclass(frozen=True)
class FilesyncTreeEntry:
    absolute_path: str
    relative_path: str
    device: int
    inode: int
    kind: int
    size: int
    mtime_ns: int
    content_sha256: str


@dataclass(frozen=True)
class FilesyncPathAttestation:
    action: str
    path: str
    workspace: Path
    local_path: Path
    directory: bool
    dry_run: bool
    protected: tuple[tuple[str, int, int, int], ...]
    push_tree: tuple[FilesyncTreeEntry, ...]
    push_objects: tuple[str, ...]
    local_tree_sha256: str
    pull_tree_before: tuple[FilesyncTreeEntry, ...] | None


def _path_identity(path: Path) -> tuple[str, int, int, int]:
    try:
        metadata = path.lstat()
    except OSError:
        raise GuardPolicyError("filesync_local_path_invalid") from None
    if stat.S_ISLNK(metadata.st_mode):
        raise GuardPolicyError("filesync_symlink_forbidden")
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise GuardPolicyError("filesync_local_path_invalid") from None
    if resolved != path:
        raise GuardPolicyError("filesync_symlink_forbidden")
    kind = stat.S_IFMT(metadata.st_mode)
    if kind not in {stat.S_IFDIR, stat.S_IFREG}:
        raise GuardPolicyError("filesync_local_path_invalid")
    return str(path), int(metadata.st_dev), int(metadata.st_ino), kind


def _filesync_relative_path(root: Path, path: Path) -> str:
    relative = path.relative_to(root)
    if relative == Path("."):
        return "."
    if any(
        FILESYNC_SEGMENT_RE.fullmatch(part) is None
        or CONTROL_CHARACTER_RE.search(part) is not None
        or FILESYNC_SCOPE_META_RE.search(part) is not None
        for part in relative.parts
    ):
        raise GuardPolicyError("filesync_tree_entry_invalid")
    return PurePosixPath(*relative.parts).as_posix()


def _stable_regular_file(
    path: Path,
    identity: tuple[str, int, int, int],
    remaining_bytes: int,
) -> tuple[int, int, str]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise GuardPolicyError("filesync_local_path_invalid") from None
    try:
        before = os.fstat(descriptor)
        before_identity = (
            str(path),
            int(before.st_dev),
            int(before.st_ino),
            stat.S_IFMT(before.st_mode),
        )
        if before_identity != identity:
            raise GuardPolicyError("filesync_path_replaced")
        if int(before.st_nlink) != 1:
            raise GuardPolicyError("filesync_hardlink_forbidden")
        size = int(before.st_size)
        if size < 0 or size > remaining_bytes:
            raise GuardPolicyError("filesync_tree_too_large")
        digest = hashlib.sha256()
        bytes_read = 0
        while True:
            chunk = os.read(descriptor, FILESYNC_HASH_CHUNK_BYTES)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > remaining_bytes:
                raise GuardPolicyError("filesync_tree_too_large")
            digest.update(chunk)
        after = os.fstat(descriptor)
        stable_fields = (
            int(before.st_dev),
            int(before.st_ino),
            stat.S_IFMT(before.st_mode),
            size,
            int(before.st_mtime_ns),
            int(before.st_nlink),
        )
        if (
            bytes_read != size
            or stable_fields
            != (
                int(after.st_dev),
                int(after.st_ino),
                stat.S_IFMT(after.st_mode),
                int(after.st_size),
                int(after.st_mtime_ns),
                int(after.st_nlink),
            )
        ):
            raise GuardPolicyError("filesync_path_replaced")
        return size, int(after.st_mtime_ns), digest.hexdigest()
    finally:
        os.close(descriptor)


def _filesync_tree_entry(
    root: Path,
    path: Path,
    remaining_bytes: int,
) -> FilesyncTreeEntry:
    identity = _path_identity(path)
    try:
        metadata = path.lstat()
    except OSError:
        raise GuardPolicyError("filesync_local_path_invalid") from None
    relative_path = _filesync_relative_path(root, path)
    if identity[3] == stat.S_IFREG:
        size, mtime_ns, content_sha256 = _stable_regular_file(
            path,
            identity,
            remaining_bytes,
        )
    else:
        size = 0
        mtime_ns = int(metadata.st_mtime_ns)
        content_sha256 = ""
    return FilesyncTreeEntry(
        absolute_path=identity[0],
        relative_path=relative_path,
        device=identity[1],
        inode=identity[2],
        kind=identity[3],
        size=size,
        mtime_ns=mtime_ns,
        content_sha256=content_sha256,
    )


def _raise_filesync_walk_error(_error: OSError) -> None:
    raise GuardPolicyError("filesync_local_path_invalid")


def _scan_filesync_tree(path: Path) -> tuple[FilesyncTreeEntry, ...]:
    root_entry = _filesync_tree_entry(path, path, FILESYNC_MAX_TREE_BYTES)
    entries: dict[str, FilesyncTreeEntry] = {".": root_entry}
    total_bytes = root_entry.size
    if root_entry.kind == stat.S_IFREG:
        return (root_entry,)
    for root, directories, files in os.walk(
        path,
        topdown=True,
        onerror=_raise_filesync_walk_error,
        followlinks=False,
    ):
        directories.sort()
        files.sort()
        root_path = Path(root)
        for name, expected_kind in [
            *((name, stat.S_IFDIR) for name in directories),
            *((name, stat.S_IFREG) for name in files),
        ]:
            child = root_path / name
            entry = _filesync_tree_entry(
                path,
                child,
                FILESYNC_MAX_TREE_BYTES - total_bytes,
            )
            if entry.kind != expected_kind:
                error = (
                    "filesync_symlink_forbidden"
                    if expected_kind == stat.S_IFDIR
                    else "filesync_local_path_invalid"
                )
                raise GuardPolicyError(error)
            entries[entry.relative_path] = entry
            total_bytes += entry.size
            if len(entries) > FILESYNC_MAX_TREE_ENTRIES:
                raise GuardPolicyError("filesync_tree_too_large")
    return tuple(entries[key] for key in sorted(entries))


def _filesync_tree_sha256(entries: tuple[FilesyncTreeEntry, ...]) -> str:
    evidence = [
        {
            "path": entry.relative_path,
            "kind": "file" if entry.kind == stat.S_IFREG else "directory",
            "size": entry.size,
            "mtimeNs": entry.mtime_ns,
            "sha256": entry.content_sha256,
        }
        for entry in entries
    ]
    return hashlib.sha256(_canonical_json(evidence)).hexdigest()


def _filesync_push_objects(
    path: str,
    directory: bool,
    entries: tuple[FilesyncTreeEntry, ...],
) -> tuple[str, ...]:
    files = [entry for entry in entries if entry.kind == stat.S_IFREG]
    if not files:
        raise GuardPolicyError("filesync_push_source_empty")
    if len(files) > FILESYNC_MAX_PUSH_OBJECTS:
        raise GuardPolicyError("filesync_tree_too_large")
    if not directory:
        if len(files) != 1 or files[0].relative_path != ".":
            raise GuardPolicyError("filesync_local_path_invalid")
        return (path,)
    prefix = path.rstrip("/")
    return tuple(f"{prefix}/{entry.relative_path}" for entry in files)


def _prepare_filesync_path(
    workspace: Path,
    action: str,
    path: str,
    dry_run: bool,
) -> FilesyncPathAttestation:
    workspace_identity = _path_identity(workspace)
    if workspace_identity[3] != stat.S_IFDIR or not workspace.is_absolute():
        raise GuardPolicyError("filesync_workspace_invalid")
    parts = PurePosixPath(path.rstrip("/")).parts
    local_path = workspace.joinpath(*parts)
    protected: list[tuple[str, int, int, int]] = [workspace_identity]
    missing = False
    for index, _part in enumerate(parts):
        current = workspace.joinpath(*parts[: index + 1])
        if missing:
            continue
        try:
            identity = _path_identity(current)
        except GuardPolicyError as exc:
            if exc.code != "filesync_local_path_invalid" or current.exists() or current.is_symlink():
                raise
            missing = True
            continue
        if current != local_path and identity[3] != stat.S_IFDIR:
            raise GuardPolicyError("filesync_local_path_invalid")
        protected.append(identity)
    directory = path.endswith("/")
    push_tree: tuple[FilesyncTreeEntry, ...] = ()
    push_objects: tuple[str, ...] = ()
    local_tree_sha256 = ""
    pull_tree_before: tuple[FilesyncTreeEntry, ...] | None = None
    if action == "push":
        if missing:
            raise GuardPolicyError("filesync_push_source_missing")
        push_tree = _scan_filesync_tree(local_path)
        expected_kind = stat.S_IFDIR if directory else stat.S_IFREG
        if _path_identity(local_path)[3] != expected_kind:
            raise GuardPolicyError("filesync_local_path_invalid")
        push_objects = _filesync_push_objects(path, directory, push_tree)
        local_tree_sha256 = _filesync_tree_sha256(push_tree)
    elif action == "pull" and not missing:
        pull_tree_before = _scan_filesync_tree(local_path)
        expected_kind = stat.S_IFDIR if directory else stat.S_IFREG
        if _path_identity(local_path)[3] != expected_kind:
            raise GuardPolicyError("filesync_local_path_invalid")
        if not directory:
            protected = [item for item in protected if item[0] != str(local_path)]
    return FilesyncPathAttestation(
        action=action,
        path=path,
        workspace=workspace,
        local_path=local_path,
        directory=directory,
        dry_run=dry_run,
        protected=tuple(protected),
        push_tree=push_tree,
        push_objects=push_objects,
        local_tree_sha256=local_tree_sha256,
        pull_tree_before=pull_tree_before,
    )


def _verify_filesync_path(attestation: FilesyncPathAttestation) -> None:
    for expected in attestation.protected:
        if _path_identity(Path(expected[0])) != expected:
            raise GuardPolicyError("filesync_path_replaced")
    if attestation.action == "push":
        if _scan_filesync_tree(attestation.local_path) != attestation.push_tree:
            raise GuardPolicyError("filesync_path_replaced")
    elif attestation.action == "pull" and not attestation.dry_run:
        pull_tree_after = _scan_filesync_tree(attestation.local_path)
        expected_kind = stat.S_IFDIR if attestation.directory else stat.S_IFREG
        if _path_identity(attestation.local_path)[3] != expected_kind:
            raise GuardPolicyError("filesync_local_path_invalid")
        if (
            attestation.pull_tree_before is not None
            and pull_tree_after == attestation.pull_tree_before
        ):
            raise GuardPolicyError("filesync_pull_unverified")


def _attest_filesync_response(
    response: dict[str, Any],
    *,
    action: str,
    path: str,
    workspace: Path,
    dry_run: bool,
) -> dict[str, Any]:
    payload = _action_payload(response)
    if payload is None or payload.get("ok") is not True:
        raise GuardPolicyError("filesync_action_failed")
    local_path = payload.get("localPath")
    kind = path.split("/", 1)[0]
    expected_local = workspace.joinpath(*PurePosixPath(path.rstrip("/")).parts)
    if (
        payload.get("tool") != "filesync"
        or payload.get("action") != action
        or payload.get("path") != path
        or payload.get("kind") != kind
        or not isinstance(local_path, str)
        or Path(local_path) != expected_local
        or (payload.get("dryRun") is True) != dry_run
    ):
        raise GuardPolicyError("filesync_response_binding_invalid")
    secured: dict[str, Any] = {
        "ok": True,
        "tool": "filesync",
        "action": action,
        "kind": kind,
        "path": path,
        "localPath": str(expected_local),
        "workspaceBindingSha256": hashlib.sha256(
            str(workspace).encode("utf-8")
        ).hexdigest(),
    }
    if dry_run:
        secured["dryRun"] = True
    if action == "list":
        if not dry_run:
            entries = payload.get("entries")
            if (
                not isinstance(entries, list)
                or len(entries) > FILESYNC_MAX_LIST_ENTRIES
                or any(
                    not isinstance(item, str)
                    or not 1 <= len(item.encode("utf-8")) <= FILESYNC_MAX_LIST_ENTRY_BYTES
                    or CONTROL_CHARACTER_RE.search(item) is not None
                    for item in entries
                )
                or sum(len(item.encode("utf-8")) for item in entries)
                > FILESYNC_MAX_LIST_BYTES
            ):
                raise GuardPolicyError("filesync_response_invalid")
            secured["entries"] = entries
    elif action == "stat":
        if not dry_run and not isinstance(payload.get("exists"), bool):
            raise GuardPolicyError("filesync_response_invalid")
        if not dry_run:
            secured["exists"] = payload["exists"]
    elif action == "push" and payload.get("exclude") != []:
        raise GuardPolicyError("filesync_response_invalid")
    return _replace_action_payload(response, secured)


def _verify_filesync_push_readback(
    request_id: Any,
    attestation: FilesyncPathAttestation,
) -> int:
    verified = 0
    for object_path in attestation.push_objects:
        probe = upstream.handle_request(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {
                    "name": "filesync",
                    "arguments": {
                        "action": "stat",
                        "path": object_path,
                        "workspaceDir": str(attestation.workspace),
                    },
                },
            }
        )
        if not isinstance(probe, dict):
            raise GuardPolicyError("filesync_push_readback_failed")
        try:
            secured = _attest_filesync_response(
                probe,
                action="stat",
                path=object_path,
                workspace=attestation.workspace,
                dry_run=False,
            )
        except GuardPolicyError:
            raise GuardPolicyError("filesync_push_readback_failed") from None
        payload = _action_payload(secured)
        if payload is None or payload.get("exists") is not True:
            raise GuardPolicyError("filesync_push_readback_failed")
        verified += 1
    if verified != len(attestation.push_objects):
        raise GuardPolicyError("filesync_push_readback_failed")
    return verified


def _add_filesync_push_evidence(
    response: dict[str, Any],
    attestation: FilesyncPathAttestation,
    verified_object_count: int | None,
) -> dict[str, Any]:
    payload = _action_payload(response)
    if payload is None:
        raise GuardPolicyError("filesync_response_invalid")
    payload["expectedObjectCount"] = len(attestation.push_objects)
    payload["localTreeSha256"] = attestation.local_tree_sha256
    if verified_object_count is not None:
        payload["verifiedObjectCount"] = verified_object_count
    return _replace_action_payload(response, payload)


def handle_request(
    request: dict[str, Any],
    *,
    github_issuer: CapabilityIssuer | None = None,
    github_clock: Callable[[], dt.datetime] | None = None,
    github_token_path: Path | None = None,
    matrix_state_reader: MatrixStateReader | None = None,
) -> dict[str, Any] | None:
    """Enforce attested identity, capability and safe task transitions."""

    try:
        if len(_canonical_json(request)) > MAX_REQUEST_BYTES:
            return _error(None, tool="", error="request_too_large")
    except (TypeError, UnicodeError, ValueError):
        return _error(None, tool="", error="request_invalid")

    method = request.get("method")
    request_id = request.get("id")
    if request_id is None and isinstance(method, str) and method.startswith("notifications/"):
        return None

    identity = runtime_identity()
    role = identity["role"] if identity else "unknown"
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"tools": _visible_tools(role)},
        }
    if method != "tools/call":
        return cast(dict[str, Any] | None, upstream.handle_request(request))

    params = request.get("params")
    params = dict(params) if isinstance(params, dict) else {}
    tool = str(params.get("name") or "")
    arguments = params.get("arguments")
    arguments = dict(arguments) if isinstance(arguments, dict) else {}
    action = str(arguments.get("action") or "")

    if identity is None:
        return _error(
            request_id,
            tool=tool,
            action=action,
            error="identity_attestation_failed",
        )
    if tool not in ROLE_TOOLS.get(role, frozenset()):
        return _error(request_id, tool=tool, action=action, role=role)
    allowed_actions = ROLE_ACTIONS.get(role, {}).get(tool)
    if allowed_actions is not None and action not in allowed_actions:
        return _error(request_id, tool=tool, action=action, role=role)

    if tool == "taskflow":
        arguments["role"] = role
        try:
            arguments["workspaceDir"] = str(_workspace_path())
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            return _error(
                request_id,
                tool=tool,
                action=action,
                error="identity_attestation_failed",
                role=role,
            )
        try:
            effective_issuer = (
                HTTPServiceCapabilityIssuer()
                if PRODUCTION_MODE or github_issuer is None
                else github_issuer
            )
            effective_clock = (
                (lambda: dt.datetime.now(dt.timezone.utc))
                if PRODUCTION_MODE or github_clock is None
                else github_clock
            )
            effective_token_path = (
                PRODUCTION_SERVICE_ACCOUNT_TOKEN
                if PRODUCTION_MODE or github_token_path is None
                else github_token_path
            )
            arguments = _guard_github_delegation(
                arguments,
                role=role,
                action=action,
                issuer=effective_issuer,
                clock=effective_clock,
                token_path=effective_token_path,
            )
        except GitHubCapabilityError as exc:
            return _error(
                request_id,
                tool=tool,
                action=action,
                error=exc.code,
                role=role,
            )
    if role in {"worker", "remote-member"} and tool == "taskflow":
        probe, state = _check_task(request_id, arguments, identity)
        if state in {"task_probe_failed", "task_assignment_mismatch"}:
            return _error(
                request_id,
                tool=tool,
                action=action,
                error=state,
                role=role,
            )
        if action == "submit_task" and state in SUCCESSFUL_SUBMIT_STATES:
            try:
                task_id = _bound_value(arguments, ("taskId", "task_id"), "taskId")
                current_digest = _existing_submission_digest(probe or {})
                requested_digest = _new_submission_digest(arguments)
            except (GuardPolicyError, TypeError, ValueError):
                return _error(
                    request_id,
                    tool=tool,
                    action=action,
                    error="submit_result_invalid",
                    role=role,
                )
            if not current_digest:
                return _error(
                    request_id,
                    tool=tool,
                    action=action,
                    error="task_probe_failed",
                    role=role,
                )
            if current_digest == requested_digest:
                return _idempotent_response(
                    request_id,
                    action=action,
                    role=role,
                    state=state,
                    task_id=task_id,
                    submission_digest=current_digest,
                )
            second_probe, second_state = _check_task(request_id, arguments, identity)
            second_digest = _existing_submission_digest(second_probe or {})
            if second_state != state or second_digest != current_digest:
                return _error(
                    request_id,
                    tool=tool,
                    action=action,
                    error="task_state_changed",
                    role=role,
                )
            return _submit_conflict_response(
                request_id,
                role=role,
                task_id=task_id,
                current_digest=current_digest,
                requested_digest=requested_digest,
            )
        if state in TERMINAL_TASK_STATES:
            return _error(
                request_id,
                tool=tool,
                action=action,
                error="terminal_task_transition",
                role=role,
            )
        if action == "ack_task" and state in ACKED_TASK_STATES:
            try:
                task_id = _bound_value(arguments, ("taskId", "task_id"), "taskId")
            except (GuardPolicyError, ValueError):
                return _error(
                    request_id,
                    tool=tool,
                    action=action,
                    error="task_probe_failed",
                    role=role,
                )
            return _idempotent_response(
                request_id,
                action=action,
                role=role,
                state=state,
                task_id=task_id,
            )

    if tool == "filesync":
        try:
            filesync_action, filesync_path, dry_run = _guard_filesync_arguments(arguments)
            workspace_path = _workspace_path()
            path_attestation = _prepare_filesync_path(
                workspace_path,
                filesync_action,
                filesync_path,
                dry_run,
            )
            arguments["workspaceDir"] = str(workspace_path)
            arguments["path"] = filesync_path
            params["arguments"] = arguments
            guarded = dict(request)
            guarded["params"] = params
            response = upstream.handle_request(guarded)
            if not isinstance(response, dict):
                raise GuardPolicyError("filesync_action_failed")
            secured = _attest_filesync_response(
                response,
                action=filesync_action,
                path=filesync_path,
                workspace=workspace_path,
                dry_run=dry_run,
            )
            _verify_filesync_path(path_attestation)
            if filesync_action == "push":
                verified_object_count = None
                if not dry_run:
                    verified_object_count = _verify_filesync_push_readback(
                        request_id,
                        path_attestation,
                    )
                    _verify_filesync_path(path_attestation)
                secured = _add_filesync_push_evidence(
                    secured,
                    path_attestation,
                    verified_object_count,
                )
            return secured
        except GuardPolicyError as exc:
            return _error(
                request_id,
                tool=tool,
                action=action,
                error=exc.code,
                role=role,
            )
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            return _error(
                request_id,
                tool=tool,
                action=action,
                error="identity_attestation_failed",
                role=role,
            )

    if tool == "roomflow" and action == "create_task_room":
        try:
            workspace = str(_workspace_path())
            arguments["workspaceDir"] = workspace
            manifest = _load_object(INSTALL_MANIFEST)
            policy = _approval_policy(manifest)
            if policy is None:
                raise GuardPolicyError("approval_policy_invalid")
            project_id = _bound_value(arguments, ("projectId", "project_id"), "projectId")
            invitees = _task_room_invitees(arguments, identity)
            binding, _project = _verified_project_binding(
                policy,
                request_id,
                arguments,
                project_id,
                workspace,
            )
            effective_reader = (
                HTTPMatrixStateReader()
                if PRODUCTION_MODE or matrix_state_reader is None
                else matrix_state_reader
            )
            params["arguments"] = arguments
            guarded = dict(request)
            guarded["params"] = params
            response = upstream.handle_request(guarded)
            if not isinstance(response, dict):
                raise GuardPolicyError("task_room_creation_failed")
            return _attest_task_room_response(
                response,
                identity=identity,
                project_id=project_id,
                invitees=invitees,
                binding=binding,
                state_reader=effective_reader,
            )
        except GuardPolicyError as exc:
            return _error(
                request_id,
                tool=tool,
                action=action,
                error=exc.code,
                role=role,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
            return _error(
                request_id,
                tool=tool,
                action=action,
                error="task_room_security_denied",
                role=role,
            )

    if tool == "projectflow":
        try:
            workspace = str(_workspace_path())
            arguments["workspaceDir"] = workspace
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            return _error(
                request_id,
                tool=tool,
                action=action,
                error="identity_attestation_failed",
                role=role,
            )
        try:
            manifest = _load_object(INSTALL_MANIFEST)
            policy = _approval_policy(manifest)
            if policy is None:
                raise GuardPolicyError("approval_policy_invalid")
            payload = _payload_object(arguments)
            if "approval" in payload:
                raise GuardPolicyError("approval_must_be_top_level")
            if action in {"create_project", "create_quick_project"}:
                if "approval" in arguments:
                    raise GuardPolicyError("project_creation_approval_forbidden")
                project_id = _bound_value(arguments, ("projectId", "project_id"), "projectId")
                risk_tier = _optional_risk_tier(arguments)
                if risk_tier is None:
                    raise GuardPolicyError("project_risk_required")
                source = _required_source(arguments)
                try:
                    _ledger_project(policy, project_id)
                except GuardPolicyError as exc:
                    if exc.code != "project_binding_missing":
                        raise
                else:
                    raise GuardPolicyError("project_binding_exists")
                create_digest = _target_digest(arguments)
                params["arguments"] = arguments
                guarded = dict(request)
                guarded["params"] = params
                response = upstream.handle_request(guarded)
                if not isinstance(response, dict):
                    raise GuardPolicyError("project_action_failed")
                response_payload = _action_payload(response)
                if response_payload is None or response_payload.get("ok") is not True:
                    raise GuardPolicyError("project_action_failed")
                created_project = _project_from_payload(response_payload, project_id)
                if created_project["source"] != source:
                    raise GuardPolicyError("project_source_state_mismatch")
                _bind_project_risk(policy, project_id, risk_tier, source, create_digest)
                binding, _legacy = _ledger_project(policy, project_id)
                return _attest_project_response(response, project_id, binding)

            project_id = _bound_value(arguments, ("projectId", "project_id"), "projectId")
            try:
                binding, project = _verified_project_binding(
                    policy,
                    request_id,
                    arguments,
                    project_id,
                    workspace,
                )
            except GuardPolicyError as exc:
                if action != "resolve_project" or exc.code != "project_binding_missing":
                    raise
                params["arguments"] = arguments
                guarded = dict(request)
                guarded["params"] = params
                missing_response = upstream.handle_request(guarded)
                missing_payload = _action_payload(
                    missing_response if isinstance(missing_response, dict) else None
                )
                if (
                    isinstance(missing_response, dict)
                    and missing_payload is not None
                    and missing_payload.get("ok") is False
                    and missing_payload.get("error") == "project not found"
                ):
                    return missing_response
                raise GuardPolicyError("unbound_project_state") from None

            if action == "resume_project":
                ledger_path = Path(str(policy["ledgerPath"]))
                with _ledger_lock(ledger_path):
                    # Re-read both authorities while holding the same cross-process
                    # lock used to consume the approval and perform the transition.
                    # The first read above also upgrades any legacy binding before
                    # entering this non-reentrant critical section.
                    binding, project = _verified_project_binding(
                        policy,
                        request_id,
                        arguments,
                        project_id,
                        workspace,
                    )
                    risk_tier = str(binding["riskTier"])
                    if risk_tier in HIGH_RISK_TIERS:
                        evidence, nonce = _validate_approval(
                            policy,
                            arguments,
                            binding=binding,
                            action=action,
                            project_id=project_id,
                            task_id=None,
                            risk_tier=risk_tier,
                        )
                        current = _read_ledger(ledger_path)
                        _consume_approval_in_locked_ledger(
                            ledger_path,
                            current,
                            evidence=evidence,
                            nonce=nonce,
                            project_id=project_id,
                            risk_tier=risk_tier,
                            required_project_status="paused",
                            project=project,
                        )
                    else:
                        if "approval" in arguments:
                            raise GuardPolicyError("low_risk_approval_forbidden")
                        status = project.get("status")
                        if not isinstance(status, str) or status.strip().lower() != "paused":
                            raise GuardPolicyError("resume_requires_paused_project")
                    arguments.pop("approval", None)

                    params["arguments"] = arguments
                    guarded = dict(request)
                    guarded["params"] = params
                    response = upstream.handle_request(guarded)
                    if not isinstance(response, dict):
                        raise GuardPolicyError("project_action_failed")
                    post_binding, post_project = _verified_project_binding(
                        policy,
                        request_id,
                        arguments,
                        project_id,
                        workspace,
                    )
                    if post_binding != binding:
                        raise GuardPolicyError("project_binding_changed")
                    post_status = post_project.get("status")
                    if (
                        not isinstance(post_status, str)
                        or post_status.strip().lower() != "active"
                    ):
                        raise GuardPolicyError("resume_did_not_become_active")
                    return _attest_project_response(response, project_id, binding)

            if action in APPROVAL_ACTIONS:
                approval_task_id = (
                    _bound_value(arguments, ("taskId", "task_id"), "taskId")
                    if action == "accept_task_result"
                    else None
                )
                risk_tier = str(binding["riskTier"])
                if risk_tier in HIGH_RISK_TIERS:
                    _validate_and_consume_approval(
                        policy,
                        arguments,
                        binding=binding,
                        action=action,
                        project_id=project_id,
                        task_id=approval_task_id,
                        risk_tier=risk_tier,
                    )
                elif "approval" in arguments:
                    raise GuardPolicyError("low_risk_approval_forbidden")
                arguments.pop("approval", None)
            elif action == "pause_project" and "approval" in arguments:
                raise GuardPolicyError("pause_approval_forbidden")

            params["arguments"] = arguments
            guarded = dict(request)
            guarded["params"] = params
            response = upstream.handle_request(guarded)
            if not isinstance(response, dict):
                raise GuardPolicyError("project_action_failed")
            post_binding, _post_project = _verified_project_binding(
                policy,
                request_id,
                arguments,
                project_id,
                workspace,
            )
            if post_binding != binding:
                raise GuardPolicyError("project_binding_changed")
            return _attest_project_response(response, project_id, binding)
        except GuardPolicyError as exc:
            return _error(
                request_id,
                tool=tool,
                action=action,
                error=f"approval_denied:{exc.code}",
                role=role,
            )
        except ValueError as exc:
            # These ValueErrors originate only from fixed guard validation strings.
            safe = str(exc)
            if CONTROL_CHARACTER_RE.search(safe) is not None or len(safe) > 160:
                safe = "project_guard_denied"
            return _error(
                request_id,
                tool=tool,
                action=action,
                error=f"approval_denied:{safe}",
                role=role,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError):
            return _error(
                request_id,
                tool=tool,
                action=action,
                error="approval_denied:project_guard_internal_error",
                role=role,
            )

    params["arguments"] = arguments
    guarded = dict(request)
    guarded["params"] = params
    return cast(dict[str, Any] | None, upstream.handle_request(guarded))


def main() -> int:
    stream = sys.stdin.buffer
    while True:
        raw_line = stream.readline(MAX_REQUEST_BYTES + 2)
        if not raw_line:
            break
        response: dict[str, Any] | None = None
        truncated = len(raw_line) == MAX_REQUEST_BYTES + 2 and not raw_line.endswith(b"\n")
        if truncated:
            while raw_line and not raw_line.endswith(b"\n"):
                raw_line = stream.readline(MAX_REQUEST_BYTES + 2)
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request"},
            }
            print(json.dumps(response, ensure_ascii=False), flush=True)
            continue
        raw = raw_line.strip()
        if not raw:
            continue
        if len(raw) > MAX_REQUEST_BYTES:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request"},
            }
        else:
            try:
                parsed = _strict_json_document(raw.decode("utf-8"), "invalid_request")
            except (GitHubCapabilityError, UnicodeError):
                response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                }
            else:
                if not isinstance(parsed, dict):
                    response = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32600, "message": "Invalid Request"},
                    }
                else:
                    try:
                        response = handle_request(parsed)
                    except Exception:
                        response = _error(
                            parsed.get("id"),
                            tool="",
                            error="guard_internal_error",
                        )
        if response is not None:
            print(json.dumps(response, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
