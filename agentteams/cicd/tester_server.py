#!/usr/bin/env python3
"""Credential-free, Tester-only MCP implementation for one CI-owned action.

The server intentionally uses only the Python standard library so it can be
deployed as an independent CI service without adding packages to a Worker.
It exposes exactly one tool, ``run_tests``.  Repository paths, commands,
network isolation, resource limits, and task authorizations are all supplied
by root-owned policy files rather than by an Agent request.

The receipt private key must never enter a Tester Worker.  A same-UID/root
process beside the Agent is not a strong boundary; production requires an
independent service Pod or a sidecar with an actually separate security
identity.  Neither form is a hostile-node, kernel, or container-escape boundary.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import difflib
import hashlib
import importlib
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Protocol, TextIO, cast

SERVER_NAME = "devflow-cicd"
SERVER_VERSION = "2.1.0"
TOOL_NAME = "run_tests"
TEAM_NAME = "devflow-swe"
TESTER_ROLE = "devflow-tester"
TESTER_SKILL = "test-runner"
SERVICE_IDENTITY = "devflow-tester-cicd.agentteams-system.svc.cluster.local"
PRODUCTION_SERVER = Path("/opt/devflow/agentteams-cicd/tester_server.py")
POLICY_PATH = Path("/etc/devflow/agentteams-cicd/policy.json")
TEST_RECEIPT_POLICY_PATH = Path(
    "/etc/devflow/agentteams-cicd/test-receipt-policy.json"
)
REPOSITORY_ROOT = Path("/var/lib/devflow/agentteams-cicd/repository")
WORKSPACE_ROOT = Path("/var/lib/devflow/agentteams-cicd/workspaces")
ASSIGNMENT_ROOT = Path("/var/lib/devflow/agentteams-cicd/assignments")
NETWORK_ISOLATION_PREFIX = (
    "/usr/bin/bwrap",
    "--die-with-parent",
    "--new-session",
    "--unshare-all",
    "--cap-drop",
    "ALL",
    "--ro-bind",
    "/",
    "/",
    "--tmpfs",
    "/etc",
    "--tmpfs",
    "/home",
    "--tmpfs",
    "/root",
    "--tmpfs",
    "/run",
    "--tmpfs",
    "/tmp",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
)
MAX_REQUEST_BYTES = 1_048_576
PROTOCOL_VERSION = "2025-03-26"
SUPPORTED_PROTOCOL_VERSIONS = frozenset({PROTOCOL_VERSION})
SOCKET_READ_TIMEOUT_SECONDS = 5.0
MAX_CONCURRENT_EXECUTIONS = 1
MAX_BATCH_SIZE = 8
MAX_HTTP_CONNECTIONS = 16
ASSIGNMENT_MAX_AGE_SECONDS = 24 * 60 * 60
ASSIGNMENT_EXPIRY_ACTION = (
    "fail-liveness-and-readiness-refresh-on-container-restart"
)
SERVICE_UID = 10_001
SERVICE_GID = 10_001
DYNAMIC_CANDIDATE_SUPPORTED = False
TEST_PATH_MUTATION_SUPPORTED = False
TEST_COMPLETION_POLICY = "fixed-candidate-pytest-terminal-summary/v1"
MINIMUM_EXECUTED_TESTS = 1
RESULT_SCHEMA = "devflow.agentteams.cicd-result/v2"
TEST_EXECUTION_RECEIPT_SCHEMA = "devflow.test-execution-receipt/v1"
TEST_EXECUTION_RECEIPT_ALGORITHM = "Ed25519"
TEST_EXECUTION_RECEIPT_ISSUER = "devflow-tester-cicd"
TEST_EXECUTION_RECEIPT_AUDIENCE = "devflow-teamharness"
TEST_EXECUTION_RECEIPT_SIGNATURE_DOMAIN = b"devflow.test-execution-receipt/v1\0"
TEST_EXECUTION_RECEIPT_TTL_SECONDS = 120
TEST_EXECUTION_RECEIPT_REPLAY_SCOPE = "pod-incarnation"
TEST_EXECUTION_RECEIPT_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT = False
ASSIGNMENT_SOURCE = "image-fixed-demo-fixture/v1"
ASSIGNMENT_SOURCE_LIVE_AGENTTEAMS = False
REPOSITORY_MODE = "image-fixed-clean-commit-fixture/v1"
TEST_COMMAND_SOURCE = "image-policy-fixed-argv/v1"
FIXTURE_TASK_IDS = ("devflow-demo-focused", "devflow-demo-full")
FIXTURE_TASK_TIERS = {
    "devflow-demo-focused": "T2",
    "devflow-demo-full": "T3",
}
TEST_EXECUTION_RECEIPT_PRIVATE_KEY = Path(
    "/var/run/secrets/devflow-test-receipt/receipt-ed25519.pem"
)
PRODUCTION_OPENSSL = Path("/usr/bin/openssl")
PRODUCTION_PRLIMIT = Path("/usr/bin/prlimit")
TEAMHARNESS_RECEIPT_PUBLIC_KEY_PATH = (
    "/etc/devflow/teamharness/test-receipt-ed25519.pub"
)
TEAMHARNESS_RECEIPT_POLICY_PATH = (
    "/etc/devflow/teamharness/test-receipt-policy.json"
)
TEAMHARNESS_RECEIPT_LEDGER_PATH = (
    "/var/lib/devflow/teamharness/test-receipt-ledger.json"
)
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ED25519_SPKI_BYTES = 44
ED25519_SIGNATURE_BYTES = 64
OPENSSL_TIMEOUT_SECONDS = 10
PORTABLE_EXECUTION_PROFILE = "portable-process-only/v1"
INTEGRITY_POLICY = "agentteams-bwrap-tests/v1"
INTEGRITY_POLICY_DIGEST = (
    "e1527ec714370ab983443b14559953d1a0d6a0a4d838930a120c3559f095fe13"
)
ISOLATION_BOUNDARY = (
    "linux-bubblewrap-unshare-all-cap-drop-process-boundary-not-node-root-or-kernel"
)
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
JTI = re.compile(r"^[0-9a-f]{32}$")
RECEIPT_CLAIM_FIELDS = frozenset(
    {
        "schema",
        "algorithm",
        "issuer",
        "audience",
        "run_id",
        "task_id",
        "trace_id",
        "issue_id",
        "repository",
        "revision",
        "workspace_binding",
        "candidate_digest",
        "tier",
        "execution_profile",
        "isolation_profile",
        "test_result_digest",
        "execution_policy_digest",
        "policy_digest",
        "server_digest",
        "key_sha256",
        "iat",
        "exp",
        "jti",
    }
)
TEST_EVIDENCE_REQUIRED_FIELDS = frozenset(
    {
        "issue_id",
        "tier",
        "candidate_digest",
        "repository",
        "revision",
        "workspace_binding",
        "execution_profile",
        "isolation_profile",
        "execution_policy",
        "test_result",
        "test_result_redacted",
        "failing_tests",
        "test_execution_receipt",
    }
)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|"
    r"sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|Bearer[ \t]+[A-Za-z0-9._~+/=-]{12,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)
IGNORED_PARTS = frozenset(
    {
        ".devflow",
        ".git",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "node_modules",
        "venv",
    }
)
TEST_CONTROL_NAMES = frozenset(
    {
        ".coveragerc",
        ".mocharc",
        ".mocharc.cjs",
        ".mocharc.js",
        ".mocharc.json",
        ".mocharc.yaml",
        ".mocharc.yml",
        "conftest.py",
        "pytest.py",
        "sitecustomize.py",
        "usercustomize.py",
        "jest.config.js",
        "jest.config.cjs",
        "jest.config.json",
        "jest.config.mjs",
        "jest.config.ts",
        "karma.conf.js",
        "playwright.config.cjs",
        "playwright.config.js",
        "playwright.config.ts",
        "pyproject.toml",
        "pytest.ini",
        "setup.cfg",
        "tox.ini",
        "vitest.config.cjs",
        "vitest.config.js",
        "vitest.config.mjs",
        "vitest.config.ts",
    }
)
POLICY_FIELDS = frozenset(
    {
        "schemaVersion",
        "teamName",
        "serviceIdentity",
        "repositoryRoot",
        "workspaceRoot",
        "repositoryRevision",
        "repositoryArchiveSha256",
        "repositoryManifestSha256",
        "serverSha256",
        "receiptPublicKeySha256",
        "testCommands",
        "testExecutableSha256",
        "networkIsolationPrefix",
        "networkIsolationExecutableSha256",
        "resourceLimitLauncher",
        "resourceLimitLauncherSha256",
        "resourceLimitsApplied",
        "assignmentSource",
        "assignmentSourceLiveAgentTeams",
        "dynamicCandidateSupported",
        "testPathMutationSupported",
        "fixedCandidateSha256",
        "testCompletionPolicy",
        "minimumExecutedTests",
        "timeoutSeconds",
        "cpuSeconds",
        "addressSpaceBytes",
        "maxProcesses",
        "maxOpenFiles",
        "maxOutputBytes",
        "maxPatchBytes",
        "maxPatchFiles",
        "maxFileBytes",
        "maxRepositoryFiles",
        "maxRepositoryBytes",
        "credentialPolicy",
        "networkPolicy",
        "workspaceBinding",
        "remainingThreat",
    }
)
RECEIPT_POLICY_FIELDS = frozenset(
    {
        "schemaVersion",
        "algorithm",
        "audience",
        "issuer",
        "signatureDomain",
        "publicKeyPath",
        "publicKeyFileSha256",
        "publicKeySha256",
        "policyAttestationPath",
        "opensslPath",
        "replayLedgerPath",
        "replayScope",
        "replayLedgerPersistentAcrossPodReplacement",
        "receiptLifetimeSeconds",
        "maxReceiptLifetimeSeconds",
        "maxClockSkewSeconds",
        "ciServerSha256",
        "ciPolicySha256",
        "repositoryArchiveSha256",
        "repositoryManifestSha256",
        "repositoryRevision",
        "remainingThreat",
    }
)
HANDOFF_REQUIRED_FIELDS = frozenset(
    {
        "envelope_version",
        "run_id",
        "issue_id",
        "task_id",
        "producer",
        "consumer",
        "skill",
        "trace_id",
        "idempotency_key",
        "created_at",
        "status",
        "artifact",
    }
)
HANDOFF_OPTIONAL_FIELDS = frozenset({"parent_task_id", "parent_handoff_sha256"})
ACKED_TASK_STATES = frozenset({"acknowledged", "acked", "in_progress", "running"})
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
CANDIDATE_FIELDS = frozenset(
    {
        "schema_version",
        "issue_id",
        "tier",
        "patch",
        "candidate_digest",
        "evidence_boundary",
        "model_call_attempt",
        "retry_attempt",
        "revision_of",
    }
)
PATCH_FIELDS = frozenset(
    {"branch_name", "changes", "commit_message", "description"}
)
CHANGE_FIELDS = frozenset(
    {"file_path", "change_type", "original_content", "new_content", "diff"}
)
BOUNDARY_FIELDS = frozenset(
    {"schema_version", "located_context_digest", "allowed_files", "scope_digest"}
)


class BoundaryError(RuntimeError):
    """A fixed CI boundary check failed."""


class BusyError(BoundaryError):
    """The single isolated execution slot is already occupied."""


class ReceiptSigner(Protocol):
    """Sign one domain-separated receipt outside every Agent Worker."""

    @property
    def public_key_sha256(self) -> str: ...

    def sign(self, value: dict[str, Any]) -> str: ...


_EXECUTION_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_EXECUTIONS)
_INFLIGHT_LOCK = threading.Lock()
_INFLIGHT_TASKS: set[str] = set()
_COMPLETED_LOCK = threading.Lock()
_COMPLETED_RESULTS: dict[str, tuple[str, dict[str, Any]]] = {}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BoundaryError("duplicate_json_field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise BoundaryError("non_standard_json")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise BoundaryError("trusted_file_unavailable") from exc
    return digest.hexdigest()


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class OpenSSLEd25519ReceiptSigner:
    """Sign receipts with the CI-only key mounted at one fixed production path.

    The key must be mounted only into an independent CI service (or a genuinely
    isolated sidecar with a different security identity).  Installing it in the
    Tester Worker, or treating two root processes in one Pod as an isolation
    boundary, invalidates the trust model.
    """

    def __init__(
        self,
        private_key_path: Path,
        *,
        openssl_path: Path = PRODUCTION_OPENSSL,
        enforce_production_metadata: bool = False,
    ) -> None:
        self._private_key_path = private_key_path
        self._openssl_path = openssl_path
        self._validate_paths(enforce_production_metadata=enforce_production_metadata)
        public_der = self._run(
            [
                str(self._openssl_path),
                "pkey",
                "-in",
                str(self._private_key_path),
                "-pubout",
                "-outform",
                "DER",
            ],
            maximum=ED25519_SPKI_BYTES,
            label="receipt_signing_key_validation",
        )
        if (
            len(public_der) != ED25519_SPKI_BYTES
            or not public_der.startswith(ED25519_SPKI_PREFIX)
        ):
            raise BoundaryError("receipt_signing_key_invalid")
        self._public_key_sha256 = _sha256_bytes(public_der)

    @property
    def public_key_sha256(self) -> str:
        return self._public_key_sha256

    def _validate_paths(self, *, enforce_production_metadata: bool) -> None:
        try:
            key_metadata = self._private_key_path.lstat()
            openssl_metadata = self._openssl_path.lstat()
        except OSError as exc:
            raise BoundaryError("receipt_signing_dependency_unavailable") from exc
        if (
            not stat.S_ISREG(key_metadata.st_mode)
            or self._private_key_path.is_symlink()
            or key_metadata.st_nlink != 1
            or not stat.S_ISREG(openssl_metadata.st_mode)
            or self._openssl_path.is_symlink()
            or not os.access(self._openssl_path, os.X_OK)
        ):
            raise BoundaryError("receipt_signing_dependency_invalid")
        if enforce_production_metadata and (
            self._private_key_path != TEST_EXECUTION_RECEIPT_PRIVATE_KEY
            or self._openssl_path != PRODUCTION_OPENSSL
            or os.name == "posix"
            and (
                key_metadata.st_uid != 0
                or key_metadata.st_gid != SERVICE_GID
                or stat.S_IMODE(key_metadata.st_mode) != 0o440
                or openssl_metadata.st_uid != 0
                or openssl_metadata.st_gid != 0
                or stat.S_IMODE(openssl_metadata.st_mode) & 0o022
            )
        ):
            raise BoundaryError("receipt_signing_dependency_invalid")

    @staticmethod
    def _run(args: list[str], *, maximum: int, label: str) -> bytes:
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                check=False,
                timeout=OPENSSL_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise BoundaryError(label) from exc
        if completed.returncode != 0 or not 1 <= len(completed.stdout) <= maximum:
            raise BoundaryError(label)
        return completed.stdout

    def sign(self, value: dict[str, Any]) -> str:
        message = TEST_EXECUTION_RECEIPT_SIGNATURE_DOMAIN + _canonical(value)
        message_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix="devflow-test-receipt-",
                suffix=".msg",
                delete=False,
            ) as stream:
                message_path = Path(stream.name)
                stream.write(message)
                stream.flush()
            message_path.chmod(0o600)
            signature = self._run(
                [
                    str(self._openssl_path),
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    str(self._private_key_path),
                    "-rawin",
                    "-in",
                    str(message_path),
                ],
                maximum=ED25519_SIGNATURE_BYTES,
                label="receipt_signing_failed",
            )
        finally:
            if message_path is not None:
                with contextlib.suppress(OSError):
                    message_path.unlink()
        if len(signature) != ED25519_SIGNATURE_BYTES:
            raise BoundaryError("receipt_signing_failed")
        return _base64url(signature)


def _trusted_runtime_file(path: Path) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("trusted_runtime_file_unavailable") from exc
    if (
        not path.is_absolute()
        or path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or (os.name == "posix" and metadata.st_uid != 0)
    ):
        raise BoundaryError("trusted_runtime_file_policy_failed")
    return path


def _read_json(path: Path, *, maximum: int = MAX_REQUEST_BYTES) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > maximum
            or (os.name == "posix" and metadata.st_uid != 0)
            or metadata.st_mode & 0o022
        ):
            raise BoundaryError("trusted_file_policy_failed")
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BoundaryError("trusted_json_invalid") from exc
    if not isinstance(value, dict):
        raise BoundaryError("trusted_json_not_object")
    return value


def _integer(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise BoundaryError(f"{label}_invalid")
    return value


def _safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise BoundaryError(f"{label}_invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise BoundaryError(f"{label}_invalid")
    return value


def _revision(value: Any) -> str:
    if not isinstance(value, str) or REVISION.fullmatch(value) is None:
        raise BoundaryError("revision_invalid")
    return value


def _repository_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\\" in value
        or CONTROL.search(value) is not None
    ):
        raise BoundaryError("repository_path_invalid")
    path = PurePosixPath(value)
    normalized = path.as_posix()
    if (
        path.is_absolute()
        or ".." in path.parts
        or normalized in {"", "."}
        or normalized != value
        or re.match(r"^[A-Za-z]:", value) is not None
    ):
        raise BoundaryError("repository_path_invalid")
    if any(part.lower() in IGNORED_PARTS for part in path.parts):
        raise BoundaryError("repository_path_forbidden")
    return normalized


def _canonical_patch_diff(
    path: str,
    change_type: str,
    original: str | None,
    new: str | None,
) -> str:
    """Recompute the only accepted unified diff from the supplied contents."""

    before = "" if change_type == "create" else original
    after = "" if change_type == "delete" else new
    if not isinstance(before, str) or not isinstance(after, str):
        raise BoundaryError(f"patch_{change_type}_invalid")
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            lineterm="\n",
        )
    )


def _command(value: Any, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 64
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 1024
            or "\x00" in item
            for item in value
        )
        or not PurePosixPath(value[0]).is_absolute()
        or "\\" in value[0]
    ):
        raise BoundaryError(f"{label}_invalid")
    executable = PurePosixPath(value[0]).name.lower()
    if executable in {
        "bash",
        "cmd",
        "cmd.exe",
        "dash",
        "fish",
        "powershell",
        "pwsh",
        "sh",
        "zsh",
    }:
        raise BoundaryError(f"{label}_invalid")
    if (
        executable.startswith(("python", "pypy")) and "-c" in value[1:]
    ) or (
        executable in {"node", "nodejs"}
        and any(argument in {"-e", "--eval"} for argument in value[1:])
    ):
        raise BoundaryError(f"{label}_invalid")
    return list(value)


def policy_binding_body(policy: Mapping[str, Any]) -> dict[str, Any]:
    """Return every enforcement field covered by ``workspaceBinding``."""

    return {
        key: policy[key]
        for key in sorted(POLICY_FIELDS - {"workspaceBinding", "remainingThreat"})
    }


def validate_receipt_policy(
    value: dict[str, Any],
    *,
    execution_policy: Mapping[str, Any],
    public_key_sha256: str,
) -> dict[str, Any]:
    """Validate the exact public verifier policy exported to TeamHarness."""

    if (
        set(value) != RECEIPT_POLICY_FIELDS
        or value.get("schemaVersion") != "1.0"
        or value.get("algorithm") != TEST_EXECUTION_RECEIPT_ALGORITHM
        or value.get("issuer") != TEST_EXECUTION_RECEIPT_ISSUER
        or value.get("audience") != TEST_EXECUTION_RECEIPT_AUDIENCE
        or value.get("signatureDomain") != TEST_EXECUTION_RECEIPT_SCHEMA
        or value.get("publicKeyPath") != TEAMHARNESS_RECEIPT_PUBLIC_KEY_PATH
        or value.get("publicKeySha256") != public_key_sha256
        or value.get("policyAttestationPath")
        != TEAMHARNESS_RECEIPT_POLICY_PATH
        or value.get("opensslPath") != str(PRODUCTION_OPENSSL)
        or value.get("replayLedgerPath") != TEAMHARNESS_RECEIPT_LEDGER_PATH
        or value.get("replayScope") != TEST_EXECUTION_RECEIPT_REPLAY_SCOPE
        or value.get("replayLedgerPersistentAcrossPodReplacement")
        is not TEST_EXECUTION_RECEIPT_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
        or value.get("receiptLifetimeSeconds")
        != TEST_EXECUTION_RECEIPT_TTL_SECONDS
        or value.get("maxReceiptLifetimeSeconds")
        != TEST_EXECUTION_RECEIPT_TTL_SECONDS
        or value.get("maxClockSkewSeconds") != 5
        or value.get("ciServerSha256") != execution_policy["serverSha256"]
        or value.get("ciPolicySha256") != execution_policy["workspaceBinding"]
        or value.get("repositoryArchiveSha256")
        != execution_policy["repositoryArchiveSha256"]
        or value.get("repositoryManifestSha256")
        != execution_policy["repositoryManifestSha256"]
        or value.get("repositoryRevision")
        != execution_policy["repositoryRevision"]
        or not isinstance(value.get("remainingThreat"), str)
        or "leader pod replacement" not in value["remainingThreat"].lower()
        or "120" not in value["remainingThreat"]
    ):
        raise BoundaryError("receipt_policy_binding_invalid")
    _digest(value.get("publicKeyFileSha256"), "receipt_public_key_file_sha256")
    return value


def validate_policy(value: dict[str, Any], *, verify_files: bool = True) -> dict[str, Any]:
    """Validate the exact root-owned execution policy."""

    if set(value) != POLICY_FIELDS:
        raise BoundaryError("policy_fields_invalid")
    if (
        value.get("schemaVersion") != "1.0"
        or value.get("teamName") != TEAM_NAME
        or value.get("serviceIdentity") != SERVICE_IDENTITY
        or value.get("repositoryRoot") != str(REPOSITORY_ROOT)
        or value.get("workspaceRoot") != str(WORKSPACE_ROOT)
        or value.get("credentialPolicy") != "empty-environment"
        or value.get("networkPolicy")
        != "bubblewrap-unshare-all-mask-runtime-credentials"
        or value.get("networkIsolationPrefix") != list(NETWORK_ISOLATION_PREFIX)
        or value.get("resourceLimitLauncher") != [PRODUCTION_PRLIMIT.as_posix()]
        or value.get("resourceLimitsApplied") is not True
        or value.get("assignmentSource") != ASSIGNMENT_SOURCE
        or value.get("assignmentSourceLiveAgentTeams") is not False
        or value.get("dynamicCandidateSupported") is not False
        or value.get("testPathMutationSupported") is not False
        or value.get("testCompletionPolicy") != TEST_COMPLETION_POLICY
        or not isinstance(value.get("remainingThreat"), str)
        or "root" not in value["remainingThreat"].lower()
    ):
        raise BoundaryError("policy_identity_invalid")
    _revision(value.get("repositoryRevision"))
    for field in (
        "repositoryArchiveSha256",
        "repositoryManifestSha256",
        "serverSha256",
        "receiptPublicKeySha256",
        "networkIsolationExecutableSha256",
        "resourceLimitLauncherSha256",
        "workspaceBinding",
    ):
        _digest(value.get(field), field)
    commands = value.get("testCommands")
    executable_digests = value.get("testExecutableSha256")
    if (
        not isinstance(commands, dict)
        or set(commands) != {"focused", "full"}
        or not isinstance(executable_digests, dict)
        or set(executable_digests) != {"focused", "full"}
    ):
        raise BoundaryError("test_commands_invalid")
    parsed_commands = {
        name: _command(commands[name], f"{name}_command")
        for name in ("focused", "full")
    }
    for name in ("focused", "full"):
        _digest(executable_digests[name], f"{name}_executable_digest")
    fixed_candidates = value.get("fixedCandidateSha256")
    if (
        not isinstance(fixed_candidates, dict)
        or set(fixed_candidates) != set(FIXTURE_TASK_IDS)
    ):
        raise BoundaryError("fixed_candidate_policy_invalid")
    for task_id in FIXTURE_TASK_IDS:
        _digest(fixed_candidates[task_id], "fixed_candidate_sha256")
    _integer(
        value.get("minimumExecutedTests"),
        "minimum_executed_tests",
        minimum=1,
        maximum=10_000,
    )
    limits = {
        "timeoutSeconds": (1, 900),
        "cpuSeconds": (1, 900),
        "addressSpaceBytes": (64 * 1024 * 1024, 8 * 1024 * 1024 * 1024),
        "maxProcesses": (1, 256),
        "maxOpenFiles": (16, 4096),
        "maxOutputBytes": (1024, 64 * 1024),
        "maxPatchBytes": (1024, 4 * 1024 * 1024),
        "maxPatchFiles": (1, 256),
        "maxFileBytes": (1024, 8 * 1024 * 1024),
        "maxRepositoryFiles": (1, 200_000),
        "maxRepositoryBytes": (1024, 2 * 1024 * 1024 * 1024),
    }
    for field, (minimum, maximum) in limits.items():
        _integer(value.get(field), field, minimum=minimum, maximum=maximum)
    expected_binding = _sha256_bytes(_canonical(policy_binding_body(value)))
    if value["workspaceBinding"] != expected_binding:
        raise BoundaryError("workspace_binding_invalid")
    if verify_files:
        if os.name != "posix":
            raise BoundaryError("service_identity_not_non_root")
        posix_module = importlib.import_module("posix")
        geteuid = cast(Callable[[], int], posix_module.geteuid)
        getegid = cast(Callable[[], int], posix_module.getegid)
        if (
            geteuid() != SERVICE_UID
            or getegid() != SERVICE_GID
        ):
            raise BoundaryError("service_identity_not_non_root")
        if (
            _sha256_file(_trusted_runtime_file(PRODUCTION_SERVER))
            != value["serverSha256"]
        ):
            raise BoundaryError("server_digest_mismatch")
        isolation = _trusted_runtime_file(Path(NETWORK_ISOLATION_PREFIX[0]))
        if _sha256_file(isolation) != value["networkIsolationExecutableSha256"]:
            raise BoundaryError("network_isolator_digest_mismatch")
        launcher = _trusted_runtime_file(PRODUCTION_PRLIMIT)
        if _sha256_file(launcher) != value["resourceLimitLauncherSha256"]:
            raise BoundaryError("resource_limit_launcher_digest_mismatch")
        receipt_policy = _read_json(TEST_RECEIPT_POLICY_PATH)
        signer = OpenSSLEd25519ReceiptSigner(
            TEST_EXECUTION_RECEIPT_PRIVATE_KEY,
            openssl_path=PRODUCTION_OPENSSL,
            enforce_production_metadata=True,
        )
        if signer.public_key_sha256 != value["receiptPublicKeySha256"]:
            raise BoundaryError("receipt_policy_binding_invalid")
        validate_receipt_policy(
            receipt_policy,
            execution_policy=value,
            public_key_sha256=signer.public_key_sha256,
        )
        for name, command in parsed_commands.items():
            if (
                _sha256_file(_trusted_runtime_file(Path(command[0])))
                != executable_digests[name]
            ):
                raise BoundaryError("test_executable_digest_mismatch")
    return value


def validate_runtime_binding(value: dict[str, Any]) -> dict[str, Any]:
    if (
        set(value) != RUNTIME_BINDING_FIELDS
        or value.get("schemaVersion") != "1.0"
        or value.get("teamName") != TEAM_NAME
        or value.get("runtimeName") != TESTER_ROLE
        or value.get("teamHarnessRole") != "worker"
        or not isinstance(value.get("memberName"), str)
        or not value["memberName"]
        or not isinstance(value.get("podName"), str)
        or not value["podName"]
    ):
        raise BoundaryError("runtime_binding_invalid")
    return value


def load_execution_policy() -> dict[str, Any]:
    try:
        if Path(__file__).resolve(strict=True) != PRODUCTION_SERVER:
            raise BoundaryError("server_execution_path_invalid")
    except OSError as exc:
        raise BoundaryError("server_execution_path_invalid") from exc
    return validate_policy(_read_json(POLICY_PATH))


def _is_test_path(relative: str) -> bool:
    path = PurePosixPath(relative)
    directories = {part.lower() for part in path.parts[:-1]}
    name = path.name.lower()
    stem = name.rsplit(".", 1)[0]
    return bool(
        directories.intersection({"test", "tests", "__tests__", "spec", "specs"})
        or stem.startswith(("test_", "test-"))
        or stem.endswith(("_test", "-test", ".test", "_spec", "-spec", ".spec"))
        or ".test." in name
        or ".spec." in name
    )


def _is_protected(relative: str) -> bool:
    name = PurePosixPath(relative).name.lower()
    return (
        _is_test_path(relative)
        or name in TEST_CONTROL_NAMES
        or name.endswith(".pth")
    )


@dataclass(frozen=True)
class TreeManifest:
    entries: tuple[tuple[str, str], ...]
    file_count: int
    total_bytes: int

    @property
    def digest(self) -> str:
        return _sha256_bytes(
            _canonical([{"path": path, "sha256": digest} for path, digest in self.entries])
        )


def repository_manifest(
    root: Path,
    *,
    max_files: int,
    max_bytes: int,
    protected_only: bool = False,
) -> TreeManifest:
    """Hash a bounded regular-file tree and reject links or special files."""

    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("repository_unavailable") from exc
    if root.is_symlink() or resolved != root or not root.is_dir():
        raise BoundaryError("repository_root_invalid")
    entries: list[tuple[str, str]] = []
    total = 0
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        names[:] = sorted(name for name in names if name not in IGNORED_PARTS)
        base = Path(directory)
        for name in names:
            child = base / name
            if child.is_symlink():
                raise BoundaryError("repository_symlink_forbidden")
        for name in sorted(files):
            if name in IGNORED_PARTS:
                continue
            path = base / name
            metadata = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise BoundaryError("repository_special_file_forbidden")
            relative = path.relative_to(root).as_posix()
            if protected_only and not _is_protected(relative):
                continue
            total += metadata.st_size
            if len(entries) >= max_files or total > max_bytes:
                raise BoundaryError("repository_limit_exceeded")
            entries.append((relative, _sha256_file(path)))
    return TreeManifest(tuple(entries), len(entries), total)


def _validate_candidate(value: Any, policy: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != CANDIDATE_FIELDS:
        raise BoundaryError("candidate_fields_invalid")
    encoded = _canonical(value)
    if len(encoded) > policy["maxPatchBytes"] or SECRET.search(encoded.decode("utf-8")):
        raise BoundaryError("candidate_content_forbidden")
    if value.get("schema_version") != "1.2":
        raise BoundaryError("candidate_schema_invalid")
    _integer(value.get("issue_id"), "issue_id", minimum=1, maximum=2**31 - 1)
    if value.get("tier") not in {"T1", "T2", "T3", "T4", "T5"}:
        raise BoundaryError("candidate_tier_invalid")
    model_attempt = _integer(
        value.get("model_call_attempt"),
        "model_call_attempt",
        minimum=1,
        maximum=3,
    )
    retry_attempt = _integer(
        value.get("retry_attempt"),
        "retry_attempt",
        minimum=1,
        maximum=3,
    )
    revision_of = value.get("revision_of")
    if (
        model_attempt < retry_attempt
        or (retry_attempt == 1 and revision_of is not None)
        or (
            retry_attempt > 1
            and (not isinstance(revision_of, str) or DIGEST.fullmatch(revision_of) is None)
        )
    ):
        raise BoundaryError("candidate_retry_binding_invalid")
    boundary = value.get("evidence_boundary")
    if not isinstance(boundary, dict) or set(boundary) != BOUNDARY_FIELDS:
        raise BoundaryError("candidate_scope_invalid")
    allowed = boundary.get("allowed_files")
    if (
        boundary.get("schema_version") != "1.0"
        or not isinstance(allowed, list)
        or not 1 <= len(allowed) <= 256
    ):
        raise BoundaryError("candidate_scope_invalid")
    normalized = [_repository_path(path) for path in allowed]
    if normalized != sorted(set(normalized)):
        raise BoundaryError("candidate_scope_invalid")
    _digest(boundary.get("located_context_digest"), "located_context_digest")
    expected_scope = _sha256_bytes(
        _canonical(
            {
                "schema_version": "1.0",
                "located_context_digest": boundary["located_context_digest"],
                "allowed_files": normalized,
            }
        )
    )
    if boundary.get("scope_digest") != expected_scope:
        raise BoundaryError("candidate_scope_invalid")
    patch = value.get("patch")
    if not isinstance(patch, dict) or set(patch) != PATCH_FIELDS:
        raise BoundaryError("patch_fields_invalid")
    for field in ("branch_name", "commit_message", "description"):
        text = patch.get(field)
        if (
            not isinstance(text, str)
            or not text
            or len(text.encode("utf-8")) > 16_384
            or CONTROL.search(text) is not None
        ):
            raise BoundaryError("patch_metadata_invalid")
    changes = patch.get("changes")
    if (
        not isinstance(changes, list)
        or not 1 <= len(changes) <= policy["maxPatchFiles"]
    ):
        raise BoundaryError("patch_changes_invalid")
    seen: set[str] = set()
    for change in changes:
        if not isinstance(change, dict) or set(change) != CHANGE_FIELDS:
            raise BoundaryError("patch_change_fields_invalid")
        path = _repository_path(change.get("file_path"))
        if path in seen or path not in normalized:
            raise BoundaryError("patch_path_outside_scope")
        seen.add(path)
        kind = change.get("change_type")
        if kind not in {"create", "modify", "delete"}:
            raise BoundaryError("patch_change_type_invalid")
        for field in ("original_content", "new_content"):
            content = change.get(field)
            if content is not None and (
                not isinstance(content, str)
                or len(content.encode("utf-8")) > policy["maxFileBytes"]
            ):
                raise BoundaryError("patch_file_content_invalid")
        diff = change.get("diff")
        if not isinstance(diff, str) or not diff or len(diff.encode("utf-8")) > 262_144:
            raise BoundaryError("patch_diff_invalid")
        original = change.get("original_content")
        new = change.get("new_content")
        if kind == "create" and (original is not None or new is None):
            raise BoundaryError("patch_create_invalid")
        if kind == "modify" and (
            original is None or new is None or original == new
        ):
            raise BoundaryError("patch_modify_invalid")
        if kind == "delete" and (original is None or new is not None):
            raise BoundaryError("patch_delete_invalid")
        if diff != _canonical_patch_diff(path, kind, original, new):
            raise BoundaryError("patch_diff_mismatch")
        if _is_protected(path):
            raise BoundaryError("test_or_runner_change_forbidden")
    if value.get("candidate_digest") != _sha256_bytes(_canonical(patch)):
        raise BoundaryError("candidate_digest_invalid")
    return value


def _walk(value: Any) -> list[Any]:
    result = [value]
    if isinstance(value, dict):
        for nested in value.values():
            result.extend(_walk(nested))
    elif isinstance(value, list):
        for nested in value:
            result.extend(_walk(nested))
    return result


def _task_alias(task: Mapping[str, Any], aliases: tuple[str, ...], label: str) -> Any:
    values = [task[name] for name in aliases if name in task]
    if not values or any(value != values[0] for value in values[1:]):
        raise BoundaryError(f"task_{label}_invalid")
    return values[0]


def validate_teamharness_task(
    evidence: dict[str, Any],
    *,
    task_id: str,
    revision: str,
    workspace_binding: str,
    policy: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate one acknowledged TeamHarness test-runner route and candidate."""

    if set(evidence) != {"task", "spec"}:
        raise BoundaryError("teamharness_task_evidence_invalid")
    task = evidence.get("task")
    spec_text = evidence.get("spec")
    if (
        not isinstance(task, dict)
        or not isinstance(spec_text, str)
        or not 1 <= len(spec_text.encode("utf-8")) <= MAX_REQUEST_BYTES
    ):
        raise BoundaryError("teamharness_task_evidence_invalid")
    probed_task_id = _safe_id(
        _task_alias(task, ("task_id", "taskId"), "id"),
        "task_id",
    )
    assigned_to = _task_alias(task, ("assigned_to", "assignedTo"), "assignee")
    status = _task_alias(task, ("status",), "status")
    task_skill = task.get("skill")
    project_id = _safe_id(
        _task_alias(task, ("project_id", "projectId"), "project"),
        "project_id",
    )
    if (
        probed_task_id != task_id
        or assigned_to != TESTER_ROLE
        or status not in ACKED_TASK_STATES
        or (task_skill is not None and task_skill != TESTER_SKILL)
    ):
        raise BoundaryError("teamharness_task_not_authorized")
    try:
        envelope = json.loads(
            spec_text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, BoundaryError) as exc:
        raise BoundaryError("teamharness_task_spec_invalid") from exc
    if (
        not isinstance(envelope, dict)
        or not set(envelope) >= HANDOFF_REQUIRED_FIELDS
        or set(envelope) - HANDOFF_REQUIRED_FIELDS - HANDOFF_OPTIONAL_FIELDS
        or envelope.get("envelope_version") != "1.0"
        or envelope.get("task_id") != task_id
        or envelope.get("producer") not in {"devflow-lead", "TeamLeader"}
        or envelope.get("consumer") not in {TESTER_ROLE, "TesterAgent"}
        or envelope.get("skill") != TESTER_SKILL
        or envelope.get("status") != "ready"
    ):
        raise BoundaryError("teamharness_task_spec_invalid")
    run_id = _safe_id(envelope.get("run_id"), "run_id")
    issue_id = _integer(
        envelope.get("issue_id"),
        "issue_id",
        minimum=1,
        maximum=2**31 - 1,
    )
    if (
        envelope.get("trace_id") != f"{run_id}:{task_id}"
        or envelope.get("idempotency_key")
        != f"{run_id}:{task_id}:{envelope['consumer']}:{TESTER_SKILL}"
    ):
        raise BoundaryError("teamharness_task_spec_invalid")
    parent_task = envelope.get("parent_task_id")
    parent_digest = envelope.get("parent_handoff_sha256")
    if (parent_task is None) != (parent_digest is None) or (
        parent_task is not None
        and (
            not isinstance(parent_task, str)
            or SAFE_ID.fullmatch(parent_task) is None
            or not isinstance(parent_digest, str)
            or DIGEST.fullmatch(parent_digest) is None
        )
    ):
        raise BoundaryError("teamharness_task_spec_invalid")
    created_at = envelope.get("created_at")
    try:
        if not isinstance(created_at, str):
            raise ValueError
        timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError
        now = datetime.now(timezone.utc)
        timestamp = timestamp.astimezone(timezone.utc)
    except ValueError as exc:
        raise BoundaryError("teamharness_task_spec_invalid") from exc
    if timestamp < now - timedelta(
        seconds=ASSIGNMENT_MAX_AGE_SECONDS
    ) or timestamp > now + timedelta(minutes=5):
        raise BoundaryError("teamharness_task_spec_stale")
    artifact = envelope.get("artifact")
    artifact_fields = {"type", "schema_version", "inline", "sha256"}
    if (
        not isinstance(artifact, dict)
        or set(artifact) not in (artifact_fields, artifact_fields | {"ref"})
        or artifact.get("type") != "PatchCandidate"
        or artifact.get("schema_version") != "1.2"
        or not isinstance(artifact.get("inline"), dict)
        or artifact.get("ref") is not None
        or not isinstance(artifact.get("sha256"), str)
        or DIGEST.fullmatch(artifact["sha256"]) is None
        or _sha256_bytes(_canonical(artifact["inline"])) != artifact["sha256"]
    ):
        raise BoundaryError("teamharness_candidate_artifact_invalid")
    candidate = _validate_candidate(artifact["inline"], policy)
    fixed_candidates = policy["fixedCandidateSha256"]
    if (
        task_id not in FIXTURE_TASK_IDS
        or fixed_candidates.get(task_id) != artifact["sha256"]
    ):
        raise BoundaryError("dynamic_candidate_not_supported")
    if candidate["issue_id"] != issue_id:
        raise BoundaryError("teamharness_candidate_issue_mismatch")
    if revision != policy["repositoryRevision"]:
        raise BoundaryError("assignment_revision_mismatch")
    if workspace_binding != policy["workspaceBinding"]:
        raise BoundaryError("assignment_workspace_mismatch")
    tier_requires_full = candidate["tier"] in {"T3", "T4", "T5"}
    assignment = {
        "projectId": project_id,
        "runId": run_id,
        "issueId": issue_id,
        "taskId": task_id,
        "revision": revision,
        "workspaceBinding": workspace_binding,
        "candidateDigest": candidate["candidate_digest"],
        "fullSuite": tier_requires_full,
    }
    return assignment, candidate


def probe_teamharness_task(task_id: str, policy: Mapping[str, Any]) -> dict[str, Any]:
    """Read image-bound demo evidence that is unavailable to the Agent.

    The main-container startup path refreshes only the two digest-pinned demo
    fixtures.  A future live AgentTeams controller projection remains an
    explicit deployment blocker; Worker-supplied candidate bytes are never
    accepted by this service.
    """

    del policy  # all execution bindings are checked after the authoritative read
    path = ASSIGNMENT_ROOT / f"{task_id}.json"
    try:
        root_metadata = ASSIGNMENT_ROOT.lstat()
        root = ASSIGNMENT_ROOT.resolve(strict=True)
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("teamharness_task_authority_unavailable") from exc
    if (
        ASSIGNMENT_ROOT.is_symlink()
        or root != ASSIGNMENT_ROOT
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_mode & 0o002
        or path.is_symlink()
        or resolved != path
        or resolved.parent != root
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > MAX_REQUEST_BYTES
        or metadata.st_mode & 0o022
        or os.name == "posix"
        and (
            root_metadata.st_gid != SERVICE_GID
            or metadata.st_uid != SERVICE_UID
            or metadata.st_gid != SERVICE_GID
        )
    ):
        raise BoundaryError("teamharness_task_authority_invalid")
    evidence = _read_json(path)
    if set(evidence) != {"task", "spec"}:
        raise BoundaryError("teamharness_task_authority_invalid")
    return evidence


@contextlib.contextmanager
def _execution_slot(task_id: str) -> Any:
    """Reserve the only execution slot and reject duplicate in-flight work."""

    acquired = False
    with _INFLIGHT_LOCK:
        if task_id in _INFLIGHT_TASKS:
            raise BusyError("task_inflight")
        acquired = _EXECUTION_SEMAPHORE.acquire(blocking=False)
        if not acquired:
            raise BusyError("server_busy")
        _INFLIGHT_TASKS.add(task_id)
    try:
        yield
    finally:
        with _INFLIGHT_LOCK:
            _INFLIGHT_TASKS.remove(task_id)
        if acquired:
            _EXECUTION_SEMAPHORE.release()


def _execution_state() -> tuple[int, int]:
    with _INFLIGHT_LOCK:
        return len(_INFLIGHT_TASKS), MAX_CONCURRENT_EXECUTIONS


def _completed_state() -> int:
    with _COMPLETED_LOCK:
        return len(_COMPLETED_RESULTS)


def _task_execution_binding(
    assignment: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> str:
    return _sha256_bytes(
        _canonical(
            {
                "assignment": dict(assignment),
                "candidateArtifactSha256": _sha256_bytes(_canonical(candidate)),
            }
        )
    )


def _apply_patch(repository: Path, candidate: Mapping[str, Any]) -> None:
    for change in candidate["patch"]["changes"]:
        relative = PurePosixPath(change["file_path"])
        target = repository.joinpath(*relative.parts)
        try:
            resolved_parent = target.parent.resolve(strict=True)
        except OSError:
            resolved_parent = target.parent
        if repository not in resolved_parent.parents and resolved_parent != repository:
            raise BoundaryError("patch_path_escape")
        existing = target.read_text(encoding="utf-8") if target.exists() else None
        kind = change["change_type"]
        if kind == "create":
            if existing is not None:
                raise BoundaryError("patch_create_conflict")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(change["new_content"], encoding="utf-8")
        elif kind == "modify":
            if existing is None or (
                change["original_content"] is not None
                and existing != change["original_content"]
            ):
                raise BoundaryError("patch_modify_conflict")
            target.write_text(change["new_content"], encoding="utf-8")
        else:
            if existing is None or (
                change["original_content"] is not None
                and existing != change["original_content"]
            ):
                raise BoundaryError("patch_delete_conflict")
            target.unlink()


def _make_patch_targets_writable(
    repository: Path,
    candidate: Mapping[str, Any],
) -> None:
    """Restore owner write access only where the trusted patcher needs it."""

    try:
        root = repository.resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("candidate_workspace_invalid") from exc
    for change in candidate["patch"]["changes"]:
        target = repository.joinpath(*PurePosixPath(change["file_path"]).parts)
        parent = target.parent
        while not parent.exists() and parent != repository:
            parent = parent.parent
        try:
            resolved_parent = parent.resolve(strict=True)
            parent_metadata = parent.lstat()
        except OSError as exc:
            raise BoundaryError("candidate_workspace_invalid") from exc
        if (
            (resolved_parent != root and root not in resolved_parent.parents)
            or parent.is_symlink()
            or not stat.S_ISDIR(parent_metadata.st_mode)
        ):
            raise BoundaryError("candidate_workspace_invalid")
        if change["change_type"] in {"create", "delete"}:
            parent.chmod(stat.S_IMODE(parent_metadata.st_mode) | stat.S_IWUSR)
        if change["change_type"] == "modify":
            try:
                target_metadata = target.lstat()
            except OSError as exc:
                raise BoundaryError("patch_modify_conflict") from exc
            if (
                target.is_symlink()
                or not stat.S_ISREG(target_metadata.st_mode)
                or target_metadata.st_nlink != 1
            ):
                raise BoundaryError("candidate_workspace_invalid")
            target.chmod(stat.S_IMODE(target_metadata.st_mode) | stat.S_IWUSR)


def _redact(text: str, maximum: int) -> str:
    return SECRET.sub("[REDACTED]", text)[-maximum:]


@dataclass(frozen=True)
class CommandOutcome:
    returncode: int
    output: str
    duration_ms: int
    collected: int = 0
    executed: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    terminal_summary: str = ""
    terminal_evidence_sha256: str = ""
    resource_limits_applied: bool = False


_PYTEST_SUMMARY = re.compile(
    r"^(?:=+\s*)?(?P<body>.+?)\s+in\s+\d+(?:\.\d+)?s"
    r"(?:\s*\([^\r\n]*\))?(?:\s*=+)?$"
)
_PYTEST_COUNT = re.compile(
    r"(?P<count>\d+)\s+"
    r"(?P<label>passed|failed|errors?|skipped|xfailed|xpassed|deselected|warnings?)\b"
)


def _pytest_terminal_evidence(
    output: str,
    *,
    returncode: int,
    minimum_executed: int,
) -> dict[str, Any]:
    """Parse and bind pytest's final terminal summary, never stdout markers."""

    summary = ""
    counts: dict[str, int] = {}
    for raw_line in reversed(output.splitlines()):
        line = raw_line.strip()
        match = _PYTEST_SUMMARY.fullmatch(line)
        if match is None:
            continue
        found = list(_PYTEST_COUNT.finditer(match.group("body")))
        if not found:
            continue
        summary = line
        for count in found:
            label = count.group("label")
            if label == "error":
                label = "errors"
            counts[label] = counts.get(label, 0) + int(count.group("count"))
        break
    passed = counts.get("passed", 0) + counts.get("xpassed", 0)
    failed = counts.get("failed", 0)
    errors = counts.get("errors", 0)
    skipped = counts.get("skipped", 0) + counts.get("xfailed", 0)
    executed = passed + failed + errors
    collected = executed + skipped + counts.get("deselected", 0)
    if (
        not summary
        or executed < minimum_executed
        or collected < executed
        or collected > 10_000
        or (returncode == 0 and (failed or errors))
        or (returncode == 1 and not (failed or errors))
        or (returncode == 2 and not errors)
        or returncode not in {0, 1, 2}
    ):
        raise BoundaryError("test_completion_evidence_missing")
    evidence = {
        "schema": TEST_COMPLETION_POLICY,
        "returncode": returncode,
        "summary": summary,
        "collected": collected,
        "executed": executed,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
    }
    return {**evidence, "sha256": _sha256_bytes(_canonical(evidence))}


def execute_command(
    repository: Path,
    *,
    full_suite: bool,
    policy: Mapping[str, Any],
) -> CommandOutcome:
    """Run one fixed suite in a fresh network namespace with no credential env."""

    suite = "full" if full_suite else "focused"
    command = [
        *policy["networkIsolationPrefix"],
        "--ro-bind",
        str(repository),
        str(repository),
        "--chdir",
        str(repository),
        "--clearenv",
        "--setenv",
        "HOME",
        "/nonexistent",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "PYTHONHASHSEED",
        "0",
        "--setenv",
        "PYTHONDONTWRITEBYTECODE",
        "1",
        "--setenv",
        "PYTHONNOUSERSITE",
        "1",
        "--setenv",
        "PYTHONSAFEPATH",
        "1",
        "--setenv",
        "PYTEST_ADDOPTS",
        "-p no:cacheprovider",
        "--setenv",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
        "1",
        "--setenv",
        "TMPDIR",
        "/tmp",
        "--",
        *policy["resourceLimitLauncher"],
        f'--cpu={policy["cpuSeconds"]}:{policy["cpuSeconds"]}',
        f'--as={policy["addressSpaceBytes"]}:{policy["addressSpaceBytes"]}',
        f'--nproc={policy["maxProcesses"]}:{policy["maxProcesses"]}',
        f'--nofile={policy["maxOpenFiles"]}:{policy["maxOpenFiles"]}',
        f'--fsize={policy["maxFileBytes"]}:{policy["maxFileBytes"]}',
        "--",
        *policy["testCommands"][suite],
    ]
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTEST_ADDOPTS": "-p no:cacheprovider",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "TMPDIR": "/tmp",
    }
    started = time.perf_counter()
    try:
        with tempfile.TemporaryFile(mode="w+b") as capture:
            process = subprocess.Popen(
                command,
                cwd=repository,
                stdin=subprocess.DEVNULL,
                stdout=capture,
                stderr=subprocess.STDOUT,
                shell=False,
                env=environment,
                start_new_session=True,
            )
            timed_out = False
            try:
                process.communicate(timeout=policy["timeoutSeconds"])
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    kill_group = getattr(os, "killpg", None)
                    if not callable(kill_group):
                        raise BoundaryError(
                            "test_timeout_cleanup_unavailable"
                        ) from None
                    kill_group(process.pid, getattr(signal, "SIGKILL", 9))
                else:  # pragma: no cover - production is Linux
                    process.kill()
                process.communicate()
                timed_out = True
                returncode = 124
            capture.flush()
            capture.seek(0, os.SEEK_END)
            size = capture.tell()
            capture.seek(max(0, size - policy["maxOutputBytes"]))
            output = capture.read(policy["maxOutputBytes"]).decode(
                "utf-8",
                errors="replace",
            )
            if timed_out:
                output = "server-owned test command timed out\n" + output
    except OSError as exc:
        raise BoundaryError("test_isolation_unavailable") from exc
    redacted = _redact(output, policy["maxOutputBytes"])
    completion = _pytest_terminal_evidence(
        redacted,
        returncode=returncode,
        minimum_executed=policy["minimumExecutedTests"],
    )
    return CommandOutcome(
        returncode=returncode,
        output=redacted,
        duration_ms=int((time.perf_counter() - started) * 1000),
        collected=completion["collected"],
        executed=completion["executed"],
        passed=completion["passed"],
        failed=completion["failed"],
        errors=completion["errors"],
        skipped=completion["skipped"],
        terminal_summary=completion["summary"],
        terminal_evidence_sha256=completion["sha256"],
        resource_limits_applied=True,
    )


def _copy_repository(source: Path, destination: Path, policy: Mapping[str, Any]) -> None:
    def ignore(_directory: str, names: list[str]) -> set[str]:
        return {name for name in names if name in IGNORED_PARTS}

    shutil.copytree(source, destination, symlinks=False, ignore=ignore)
    repository_manifest(
        destination,
        max_files=policy["maxRepositoryFiles"],
        max_bytes=policy["maxRepositoryBytes"],
    )


def _remove_workspace(path: Path, workspace_root: Path) -> None:
    """Remove a service-owned temporary tree even when copied modes are read-only."""

    try:
        root = workspace_root.resolve(strict=True)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("candidate_workspace_cleanup_failed") from exc
    if path.is_symlink() or resolved.parent != root or not path.name.startswith("run-"):
        raise BoundaryError("candidate_workspace_cleanup_failed")
    try:
        for directory, names, files in os.walk(path, topdown=False, followlinks=False):
            base = Path(directory)
            for name in files:
                child = base / name
                metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                    raise BoundaryError("candidate_workspace_cleanup_failed")
                child.chmod(stat.S_IMODE(metadata.st_mode) | stat.S_IWUSR)
            for name in names:
                child = base / name
                metadata = child.lstat()
                if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    raise BoundaryError("candidate_workspace_cleanup_failed")
                child.chmod(stat.S_IMODE(metadata.st_mode) | stat.S_IWUSR)
        path.chmod(stat.S_IRWXU)
        shutil.rmtree(path)
    except OSError as exc:
        raise BoundaryError("candidate_workspace_cleanup_failed") from exc


def _contains_redaction(value: Any) -> bool:
    if isinstance(value, str):
        return "[REDACTED]" in value
    if isinstance(value, dict):
        return any(_contains_redaction(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_redaction(child) for child in value)
    return False


def _failure_evidence(
    test_result: Mapping[str, Any],
    *,
    issue_id: int,
    candidate_digest: str,
) -> dict[str, Any]:
    comparison = test_result["baseline_comparison"]
    all_failed_cases = [
        case
        for case in test_result["results"]
        if case["status"] in {"failed", "error"}
    ]
    failed_cases = all_failed_cases[:32]
    failing_tests = [case["name"] for case in all_failed_cases[:128]]
    all_new_failures = list(comparison["new_failures"])
    new_failures = all_new_failures[:128]
    reasons: list[str] = []
    if test_result["failed"]:
        reasons.append("test_failures")
    if test_result["errors"]:
        reasons.append("test_errors")
    if comparison["regression"]:
        reasons.append("regression")
    if new_failures:
        reasons.append("new_failures")
    diagnostics = [
        {
            "name": case["name"],
            "status": case["status"],
            "error_message": case["error_message"],
            "traceback": case["traceback"],
        }
        for case in failed_cases
    ]
    bounded_view = {
        "failing_tests": failing_tests,
        "new_failures": new_failures,
        "diagnostics": diagnostics,
    }
    return {
        "schema_version": "1.2",
        "issue_id": issue_id,
        "candidate_digest": candidate_digest,
        "test_result_digest": _sha256_bytes(_canonical(test_result)),
        "baseline_present": True,
        "failed": test_result["failed"],
        "errors": test_result["errors"],
        "regression": comparison["regression"],
        "reasons": reasons,
        **bounded_view,
        "truncated": (
            len(all_failed_cases) > len(failed_cases)
            or len(all_failed_cases) > len(failing_tests)
            or len(all_new_failures) > len(new_failures)
        ),
        "redacted": _contains_redaction(bounded_view),
    }


def _execution_policy_evidence(
    assignment: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    profile = "full" if assignment["fullSuite"] else "focused"
    return {
        "schema": "devflow.test-execution-policy/v1",
        "profile": profile,
        "isolation_profile": INTEGRITY_POLICY,
        "isolation_boundary": ISOLATION_BOUNDARY,
        "credentials_forwarded": False,
        "network": "bubblewrap-unshare-all-mask-runtime-credentials",
        "shell": False,
        "deployment_tools_exposed": False,
        "timeout_seconds": policy["timeoutSeconds"],
        "resource_limits_applied": policy["resourceLimitsApplied"],
        "resource_limit_launcher_sha256": policy[
            "resourceLimitLauncherSha256"
        ],
        "dynamic_candidate_supported": policy["dynamicCandidateSupported"],
        "test_path_mutation_supported": policy["testPathMutationSupported"],
        "test_completion_policy": policy["testCompletionPolicy"],
        "minimum_executed_tests": policy["minimumExecutedTests"],
        "policy_digest": assignment["workspaceBinding"],
        "server_digest": policy["serverSha256"],
        "repository_archive_sha256": policy["repositoryArchiveSha256"],
        "repository_manifest_sha256": policy["repositoryManifestSha256"],
        "remaining_threat": policy["remainingThreat"],
    }


def _receipt_claims(
    test_evidence: Mapping[str, Any],
    assignment: Mapping[str, Any],
    signer: ReceiptSigner,
    *,
    now: int,
    jti: str,
) -> dict[str, Any]:
    if JTI.fullmatch(jti) is None:
        raise BoundaryError("receipt_jti_invalid")
    execution_policy = test_evidence["execution_policy"]
    test_result = test_evidence["test_result"]
    return {
        "schema": TEST_EXECUTION_RECEIPT_SCHEMA,
        "algorithm": TEST_EXECUTION_RECEIPT_ALGORITHM,
        "issuer": TEST_EXECUTION_RECEIPT_ISSUER,
        "audience": TEST_EXECUTION_RECEIPT_AUDIENCE,
        "run_id": assignment["runId"],
        "task_id": assignment["taskId"],
        "trace_id": f'{assignment["runId"]}:{assignment["taskId"]}',
        "issue_id": assignment["issueId"],
        "repository": test_evidence["repository"],
        "revision": assignment["revision"],
        "workspace_binding": assignment["workspaceBinding"],
        "candidate_digest": assignment["candidateDigest"],
        "tier": test_evidence["tier"],
        "execution_profile": test_evidence["execution_profile"],
        "isolation_profile": test_evidence["isolation_profile"],
        "test_result_digest": _sha256_bytes(_canonical(test_result)),
        "execution_policy_digest": _sha256_bytes(_canonical(execution_policy)),
        "policy_digest": execution_policy["policy_digest"],
        "server_digest": execution_policy["server_digest"],
        "key_sha256": signer.public_key_sha256,
        "iat": now,
        "exp": now + TEST_EXECUTION_RECEIPT_TTL_SECONDS,
        "jti": jti,
    }


def _signed_test_evidence(
    test_result: dict[str, Any],
    assignment: Mapping[str, Any],
    candidate: Mapping[str, Any],
    policy: Mapping[str, Any],
    signer: ReceiptSigner,
    *,
    now: int,
    jti: str,
) -> dict[str, Any]:
    execution_policy = _execution_policy_evidence(assignment, policy)
    profile = str(execution_policy["profile"])
    failed_cases = [
        case["name"]
        for case in test_result["results"]
        if case["status"] in {"failed", "error"}
    ][:128]
    evidence: dict[str, Any] = {
        "issue_id": assignment["issueId"],
        "tier": candidate["tier"],
        "candidate_digest": assignment["candidateDigest"],
        "repository": {
            "archive_sha256": policy["repositoryArchiveSha256"],
            "manifest_sha256": policy["repositoryManifestSha256"],
        },
        "revision": assignment["revision"],
        "workspace_binding": assignment["workspaceBinding"],
        "execution_profile": profile,
        "isolation_profile": INTEGRITY_POLICY,
        "execution_policy": execution_policy,
        "test_result": test_result,
        "test_result_redacted": _contains_redaction(test_result),
        "failing_tests": failed_cases,
    }
    if test_result["failed"] or test_result["errors"]:
        evidence["failure_evidence"] = _failure_evidence(
            test_result,
            issue_id=assignment["issueId"],
            candidate_digest=assignment["candidateDigest"],
        )
    claims = _receipt_claims(evidence, assignment, signer, now=now, jti=jti)
    evidence["test_execution_receipt"] = {
        **claims,
        "signature": signer.sign(claims),
    }
    return evidence


def run_candidate(
    candidate: dict[str, Any],
    assignment: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    command_runner: Callable[..., CommandOutcome] = execute_command,
    receipt_signer: ReceiptSigner | None = None,
    clock: Callable[[], float] = time.time,
    jti_factory: Callable[[], str] = lambda: secrets.token_hex(16),
) -> dict[str, Any]:
    """Execute baseline and candidate copies, returning bound test evidence."""

    def checked_outcome(value: Any) -> CommandOutcome:
        if not isinstance(value, CommandOutcome):
            raise BoundaryError("test_completion_evidence_missing")
        completion = _pytest_terminal_evidence(
            value.output,
            returncode=value.returncode,
            minimum_executed=policy["minimumExecutedTests"],
        )
        expected = (
            completion["collected"],
            completion["executed"],
            completion["passed"],
            completion["failed"],
            completion["errors"],
            completion["skipped"],
            completion["summary"],
            completion["sha256"],
        )
        actual = (
            value.collected,
            value.executed,
            value.passed,
            value.failed,
            value.errors,
            value.skipped,
            value.terminal_summary,
            value.terminal_evidence_sha256,
        )
        if (
            actual != expected
            or value.resource_limits_applied is not True
            or isinstance(value.duration_ms, bool)
            or not isinstance(value.duration_ms, int)
            or not 0 <= value.duration_ms <= 604_800_000
        ):
            raise BoundaryError("test_completion_evidence_missing")
        return value

    def result_cases(prefix: str, outcome: CommandOutcome) -> list[dict[str, Any]]:
        cases: list[dict[str, Any]] = []
        terminal_name = (
            f"{prefix}::terminal-sha256={outcome.terminal_evidence_sha256};"
            f"collected={outcome.collected};executed={outcome.executed}"
        )
        first = True
        for status, count in (
            ("passed", outcome.passed),
            ("failed", outcome.failed),
            ("error", outcome.errors),
            ("skipped", outcome.skipped),
        ):
            for index in range(count):
                failed_case = status in {"failed", "error"}
                cases.append(
                    {
                        "name": terminal_name if first else f"{prefix}::{status}-{index + 1}",
                        "status": status,
                        "duration_ms": outcome.duration_ms if first else 0,
                        "error_message": (
                            "Server-owned pytest summary reported a failure."
                            if failed_case
                            else None
                        ),
                        "traceback": (
                            outcome.output[-4000:] if failed_case and first else None
                        ),
                    }
                )
                first = False
        if len(cases) != (
            outcome.passed + outcome.failed + outcome.errors + outcome.skipped
        ):
            raise BoundaryError("test_completion_evidence_missing")
        return cases
    repository = Path(policy["repositoryRoot"])
    current_manifest = repository_manifest(
        repository,
        max_files=policy["maxRepositoryFiles"],
        max_bytes=policy["maxRepositoryBytes"],
    )
    if current_manifest.digest != policy["repositoryManifestSha256"]:
        raise BoundaryError("repository_revision_drift")
    workspace_root = Path(policy["workspaceRoot"])
    try:
        if workspace_root.resolve(strict=True) != WORKSPACE_ROOT or workspace_root.is_symlink():
            raise BoundaryError("workspace_root_invalid")
    except OSError as exc:
        raise BoundaryError("workspace_root_invalid") from exc
    temporary = Path(tempfile.mkdtemp(prefix="run-", dir=workspace_root))
    try:
        baseline_root = temporary / "baseline"
        candidate_root = temporary / "candidate"
        _copy_repository(repository, baseline_root, policy)
        _copy_repository(repository, candidate_root, policy)
        baseline_protected = repository_manifest(
            baseline_root,
            max_files=policy["maxRepositoryFiles"],
            max_bytes=policy["maxRepositoryBytes"],
            protected_only=True,
        )
        baseline = checked_outcome(
            command_runner(
                baseline_root,
                full_suite=assignment["fullSuite"],
                policy=policy,
            )
        )
        baseline_after = repository_manifest(
            baseline_root,
            max_files=policy["maxRepositoryFiles"],
            max_bytes=policy["maxRepositoryBytes"],
            protected_only=True,
        )
        if baseline_after.entries != baseline_protected.entries:
            raise BoundaryError("baseline_tests_mutated")
        _make_patch_targets_writable(candidate_root, candidate)
        _apply_patch(candidate_root, candidate)
        candidate_pre = repository_manifest(
            candidate_root,
            max_files=policy["maxRepositoryFiles"],
            max_bytes=policy["maxRepositoryBytes"],
            protected_only=True,
        )
        candidate_map = dict(candidate_pre.entries)
        for path, digest in baseline_protected.entries:
            if candidate_map.get(path) != digest:
                raise BoundaryError("candidate_changed_protected_test")
        current = checked_outcome(
            command_runner(
                candidate_root,
                full_suite=assignment["fullSuite"],
                policy=policy,
            )
        )
        candidate_post = repository_manifest(
            candidate_root,
            max_files=policy["maxRepositoryFiles"],
            max_bytes=policy["maxRepositoryBytes"],
            protected_only=True,
        )
        if candidate_post.entries != candidate_pre.entries:
            raise BoundaryError("candidate_tests_mutated")
    finally:
        _remove_workspace(temporary, workspace_root)

    case_name = (
        "server-owned-full-suite"
        if assignment["fullSuite"]
        else "server-owned-focused-suite"
    )
    cases = result_cases(case_name, current)
    failed_names = [
        case["name"] for case in cases if case["status"] in {"failed", "error"}
    ]
    baseline_paths = {path for path, _digest_value in baseline_protected.entries}
    added_entries = tuple(
        entry for entry in candidate_pre.entries if entry[0] not in baseline_paths
    )
    added = TreeManifest(
        added_entries,
        len(added_entries),
        0,
    )
    test_result = {
        "total": current.passed + current.failed + current.errors + current.skipped,
        "passed": current.passed,
        "failed": current.failed,
        "errors": current.errors,
        "skipped": current.skipped,
        "duration_ms": current.duration_ms,
        "results": cases,
        "baseline_comparison": {
            "baseline_passed": baseline.passed,
            "current_passed": current.passed,
            "new_failures": (
                failed_names
                if not (baseline.failed or baseline.errors)
                and (current.failed or current.errors)
                else []
            ),
            "fixed_tests": (
                [f"{case_name}::aggregate-fixed"]
                if (baseline.failed or baseline.errors)
                and not (current.failed or current.errors)
                else []
            ),
            "regression": (
                not (baseline.failed or baseline.errors)
                and bool(current.failed or current.errors)
            ),
        },
        "integrity_attestation": {
            "schema_version": "1.0",
            "policy": INTEGRITY_POLICY,
            "policy_digest": INTEGRITY_POLICY_DIGEST,
            "command_digest": _sha256_bytes(
                _canonical(
                    {
                        "networkIsolationPrefix": policy["networkIsolationPrefix"],
                        "resourceLimitLauncher": policy["resourceLimitLauncher"],
                        "testCommand": policy["testCommands"][
                            "full" if assignment["fullSuite"] else "focused"
                        ],
                        "fullSuite": assignment["fullSuite"],
                        "baselineTerminalEvidenceSha256": (
                            baseline.terminal_evidence_sha256
                        ),
                        "candidateTerminalEvidenceSha256": (
                            current.terminal_evidence_sha256
                        ),
                        "baselineExecuted": baseline.executed,
                        "candidateExecuted": current.executed,
                    }
                )
            ),
            "baseline_manifest_digest": baseline_protected.digest,
            "candidate_baseline_manifest_digest": baseline_protected.digest,
            "candidate_pre_run_manifest_digest": candidate_pre.digest,
            "candidate_post_run_manifest_digest": candidate_post.digest,
            "added_tests_manifest_digest": added.digest,
            "baseline_protected_file_count": baseline_protected.file_count,
            "added_test_file_count": added.file_count,
            "full_suite": assignment["fullSuite"],
            "verified": True,
            "isolation_boundary": ISOLATION_BOUNDARY,
        },
    }
    signer = receipt_signer or OpenSSLEd25519ReceiptSigner(
        TEST_EXECUTION_RECEIPT_PRIVATE_KEY,
        openssl_path=PRODUCTION_OPENSSL,
        enforce_production_metadata=True,
    )
    issued_at = int(clock())
    if issued_at < 0:
        raise BoundaryError("receipt_time_invalid")
    test_evidence = _signed_test_evidence(
        test_result,
        assignment,
        candidate,
        policy,
        signer,
        now=issued_at,
        jti=jti_factory(),
    )
    return {
        "schema": RESULT_SCHEMA,
        "artifactType": "TestEvidence",
        "artifactSchemaVersion": "1.0",
        "testEvidence": test_evidence,
    }


def _validate_execution_result(
    value: Any,
    *,
    candidate: Mapping[str, Any],
    assignment: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {"schema", "artifactType", "artifactSchemaVersion", "testEvidence"}
        or value.get("schema") != RESULT_SCHEMA
        or value.get("artifactType") != "TestEvidence"
        or value.get("artifactSchemaVersion") != "1.0"
        or not isinstance(value.get("testEvidence"), dict)
    ):
        raise BoundaryError("executor_result_invalid")
    evidence = value["testEvidence"]
    if (
        not set(evidence) >= TEST_EVIDENCE_REQUIRED_FIELDS
        or set(evidence) - TEST_EVIDENCE_REQUIRED_FIELDS - {"failure_evidence"}
        or evidence.get("issue_id") != assignment["issueId"]
        or evidence.get("tier") != candidate["tier"]
        or evidence.get("candidate_digest") != assignment["candidateDigest"]
        or evidence.get("revision") != assignment["revision"]
        or evidence.get("workspace_binding") != assignment["workspaceBinding"]
        or evidence.get("execution_profile")
        != ("full" if assignment["fullSuite"] else "focused")
        or evidence.get("isolation_profile") != INTEGRITY_POLICY
    ):
        raise BoundaryError("executor_result_unbound")
    repository = evidence.get("repository")
    execution_policy = evidence.get("execution_policy")
    test_result = evidence.get("test_result")
    receipt = evidence.get("test_execution_receipt")
    if (
        repository
        != {
            "archive_sha256": policy["repositoryArchiveSha256"],
            "manifest_sha256": policy["repositoryManifestSha256"],
        }
        or not isinstance(execution_policy, dict)
        or not isinstance(test_result, dict)
        or not isinstance(receipt, dict)
        or set(receipt) != RECEIPT_CLAIM_FIELDS | {"signature"}
    ):
        raise BoundaryError("executor_result_unbound")
    claims = {key: receipt[key] for key in RECEIPT_CLAIM_FIELDS}
    expected = {
        "run_id": assignment["runId"],
        "task_id": assignment["taskId"],
        "trace_id": f'{assignment["runId"]}:{assignment["taskId"]}',
        "issue_id": assignment["issueId"],
        "repository": repository,
        "revision": assignment["revision"],
        "workspace_binding": assignment["workspaceBinding"],
        "candidate_digest": assignment["candidateDigest"],
        "tier": candidate["tier"],
        "execution_profile": evidence["execution_profile"],
        "isolation_profile": INTEGRITY_POLICY,
        "test_result_digest": _sha256_bytes(_canonical(test_result)),
        "execution_policy_digest": _sha256_bytes(_canonical(execution_policy)),
        "policy_digest": assignment["workspaceBinding"],
        "server_digest": policy["serverSha256"],
        "key_sha256": policy["receiptPublicKeySha256"],
    }
    if (
        claims.get("schema") != TEST_EXECUTION_RECEIPT_SCHEMA
        or claims.get("algorithm") != TEST_EXECUTION_RECEIPT_ALGORITHM
        or claims.get("issuer") != TEST_EXECUTION_RECEIPT_ISSUER
        or claims.get("audience") != TEST_EXECUTION_RECEIPT_AUDIENCE
        or any(claims.get(key) != expected_value for key, expected_value in expected.items())
        or isinstance(claims.get("iat"), bool)
        or not isinstance(claims.get("iat"), int)
        or isinstance(claims.get("exp"), bool)
        or not isinstance(claims.get("exp"), int)
        or claims["exp"] - claims["iat"] != TEST_EXECUTION_RECEIPT_TTL_SECONDS
        or not isinstance(claims.get("jti"), str)
        or JTI.fullmatch(claims["jti"]) is None
        or not isinstance(receipt.get("signature"), str)
    ):
        raise BoundaryError("executor_result_unbound")
    try:
        signature = base64.urlsafe_b64decode(
            receipt["signature"] + "=" * (-len(receipt["signature"]) % 4)
        )
    except (ValueError, binascii.Error) as exc:
        raise BoundaryError("executor_result_unbound") from exc
    if len(signature) != ED25519_SIGNATURE_BYTES:
        raise BoundaryError("executor_result_unbound")
    return value


def _tool_definition(policy: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": TOOL_NAME,
        "description": (
            "Run the acknowledged TeamHarness test-runner PatchCandidate against "
            "server-owned baseline and candidate copies. The candidate, commands, "
            "suite, and paths are not request fields."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["taskId", "revision", "workspaceBinding"],
            "additionalProperties": False,
            "properties": {
                "taskId": {"type": "string", "pattern": SAFE_ID.pattern},
                "revision": {
                    "type": "string",
                    "pattern": REVISION.pattern,
                    "const": policy["repositoryRevision"],
                    "description": "Copy this server-pinned revision unchanged.",
                },
                "workspaceBinding": {
                    "type": "string",
                    "pattern": DIGEST.pattern,
                    "const": policy["workspaceBinding"],
                    "description": "Copy this server-issued policy binding unchanged.",
                },
            },
        },
    }


def _success(request_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": _canonical(payload).decode("utf-8"),
                }
            ],
            "structuredContent": payload,
            "isError": False,
        },
    }


def _tool_failure(request_id: Any, reason: str) -> dict[str, Any]:
    payload = {"ok": False, "error": reason, "server": SERVER_NAME}
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": _canonical(payload).decode("utf-8"),
                }
            ],
            "structuredContent": payload,
            "isError": True,
        },
    }


def _jsonrpc_error(
    request_id: Any,
    code: int,
    message: str,
    *,
    reason: str | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if reason is not None:
        error["data"] = {"reason": reason, "server": SERVER_NAME}
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _valid_request_id(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (str, int, float))
        and (not isinstance(value, float) or value == value)
    )


def _initialize_result(
    request_id: Any,
    params: Any,
) -> dict[str, Any]:
    if not isinstance(params, dict) or set(params) != {
        "protocolVersion",
        "capabilities",
        "clientInfo",
    }:
        return _jsonrpc_error(
            request_id,
            -32602,
            "Invalid params",
            reason="initialize_params_invalid",
        )
    requested = params.get("protocolVersion")
    capabilities = params.get("capabilities")
    client_info = params.get("clientInfo")
    if (
        not isinstance(requested, str)
        or not requested
        or not isinstance(capabilities, dict)
        or not isinstance(client_info, dict)
        or set(client_info) != {"name", "version"}
        or any(
            not isinstance(client_info.get(field), str)
            or not 1 <= len(client_info[field]) <= 128
            or CONTROL.search(client_info[field]) is not None
            for field in ("name", "version")
        )
    ):
        return _jsonrpc_error(
            request_id,
            -32602,
            "Invalid params",
            reason="initialize_params_invalid",
        )
    negotiated = (
        requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
    )
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "protocolVersion": negotiated,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "Stateless Tester CI: run_tests accepts only a server-owned "
                "AgentTeams assignment and one fixed execution policy."
            ),
        },
    }


def handle_request(
    request: dict[str, Any],
    *,
    policy: dict[str, Any] | None = None,
    runtime_binding: dict[str, Any] | None = None,
    assignment: dict[str, Any] | None = None,
    executor: Callable[[dict[str, Any], dict[str, Any], dict[str, Any]], dict[str, Any]]
    | None = None,
) -> dict[str, Any] | None:
    """Handle one MCP request; injectable values exist only for unit tests."""

    if (
        set(request) - {"jsonrpc", "id", "method", "params"}
        or request.get("jsonrpc") != "2.0"
        or not isinstance(request.get("method"), str)
        or not request["method"]
    ):
        return _jsonrpc_error(
            None,
            -32600,
            "Invalid Request",
            reason="invalid_request",
        )
    has_id = "id" in request
    request_id = request.get("id")
    if has_id and not _valid_request_id(request_id):
        return _jsonrpc_error(
            None,
            -32600,
            "Invalid Request",
            reason="invalid_request_id",
        )
    method = request.get("method")
    if not has_id:
        # MCP notifications are deliberately side-effect-free here. In
        # particular, a tools/call object without an id never starts tests.
        return None
    if method == "initialize":
        return _initialize_result(request_id, request.get("params"))
    if method == "ping":
        if request.get("params", {}) != {}:
            return _jsonrpc_error(
                request_id,
                -32602,
                "Invalid params",
                reason="ping_params_invalid",
            )
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    try:
        if policy is None:
            policy = load_execution_policy()
        else:
            policy = validate_policy(policy, verify_files=False)
        if runtime_binding is not None:
            validate_runtime_binding(runtime_binding)
        if method == "tools/list":
            if request.get("params", {}) != {}:
                return _jsonrpc_error(
                    request_id,
                    -32602,
                    "Invalid params",
                    reason="tools_list_params_invalid",
                )
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"tools": [_tool_definition(policy)]},
            }
        if method != "tools/call":
            return _jsonrpc_error(
                request_id,
                -32601,
                "Method not found",
                reason="method_not_found",
            )
        params = request.get("params")
        if not isinstance(params, dict) or set(params) != {"name", "arguments"}:
            return _jsonrpc_error(
                request_id,
                -32602,
                "Invalid params",
                reason="call_tool_params_invalid",
            )
        if params.get("name") != TOOL_NAME:
            return _jsonrpc_error(
                request_id,
                -32602,
                f"Unknown tool: {params.get('name')!s}",
                reason="forbidden_tool",
            )
        if not isinstance(params.get("arguments"), dict):
            return _jsonrpc_error(
                request_id,
                -32602,
                "Invalid params",
                reason="call_tool_arguments_invalid",
            )
        arguments = params["arguments"]
        if set(arguments) != {"taskId", "revision", "workspaceBinding"}:
            return _jsonrpc_error(
                request_id,
                -32602,
                "Invalid params",
                reason="arguments_outside_policy",
            )
        try:
            task_id = _safe_id(arguments["taskId"], "task_id")
            revision = _revision(arguments["revision"])
            workspace_binding = _digest(
                arguments["workspaceBinding"],
                "workspace_binding",
            )
        except BoundaryError as exc:
            return _jsonrpc_error(
                request_id,
                -32602,
                "Invalid params",
                reason=str(exc),
            )
        with _execution_slot(task_id):
            cache_enabled = assignment is None
            task_evidence = (
                probe_teamharness_task(task_id, policy)
                if assignment is None
                else dict(assignment)
            )
            checked_assignment, candidate = validate_teamharness_task(
                task_evidence,
                task_id=task_id,
                revision=revision,
                workspace_binding=workspace_binding,
                policy=policy,
            )
            execution_binding = _task_execution_binding(
                checked_assignment,
                candidate,
            )
            if cache_enabled:
                with _COMPLETED_LOCK:
                    completed = _COMPLETED_RESULTS.get(task_id)
                    if completed is not None:
                        completed_binding, completed_result = completed
                        if completed_binding != execution_binding:
                            raise BoundaryError("task_replay_conflict")
                        return _success(
                            request_id,
                            json.loads(_canonical(completed_result)),
                        )
            operation = executor or run_candidate
            result = operation(candidate, checked_assignment, policy)
            _validate_execution_result(
                result,
                candidate=candidate,
                assignment=checked_assignment,
                policy=policy,
            )
            if cache_enabled:
                with _COMPLETED_LOCK:
                    _COMPLETED_RESULTS[task_id] = (
                        execution_binding,
                        json.loads(_canonical(result)),
                    )
            return _success(request_id, result)
    except BusyError as exc:
        return _jsonrpc_error(
            request_id,
            -32001,
            "Server busy",
            reason=str(exc),
        )
    except BoundaryError as exc:
        if method == "tools/call":
            return _tool_failure(request_id, str(exc))
        return _jsonrpc_error(
            request_id,
            -32603,
            "Internal error",
            reason=str(exc),
        )
    except Exception:
        return _jsonrpc_error(
            request_id,
            -32603,
            "Internal error",
            reason="internal_boundary_error",
        )


def _dispatch_message(
    message: Any,
    *,
    handler: Callable[[dict[str, Any]], dict[str, Any] | None],
) -> dict[str, Any] | list[dict[str, Any]] | None:
    if isinstance(message, dict):
        return handler(message)
    if (
        not isinstance(message, list)
        or not message
        or len(message) > MAX_BATCH_SIZE
    ):
        return _jsonrpc_error(
            None,
            -32600,
            "Invalid Request",
            reason=(
                "batch_size_invalid"
                if isinstance(message, list) and len(message) > MAX_BATCH_SIZE
                else "invalid_request"
            ),
        )
    if (
        sum(
            1
            for item in message
            if isinstance(item, dict) and item.get("method") == "tools/call"
        )
        > 1
    ):
        return _jsonrpc_error(
            None,
            -32600,
            "Invalid Request",
            reason="side_effecting_batch_invalid",
        )
    responses: list[dict[str, Any]] = []
    for item in message:
        if not isinstance(item, dict):
            responses.append(
                _jsonrpc_error(
                    None,
                    -32600,
                    "Invalid Request",
                    reason="invalid_batch_item",
                )
            )
            continue
        if item.get("method") == "initialize":
            responses.append(
                _jsonrpc_error(
                    item.get("id") if _valid_request_id(item.get("id")) else None,
                    -32600,
                    "Invalid Request",
                    reason="initialize_must_not_be_batched",
                )
            )
            continue
        response = handler(item)
        if response is not None:
            responses.append(response)
    return responses or None


def serve_stdio(
    stream: BinaryIO,
    output: TextIO,
    *,
    handler: Callable[[dict[str, Any]], dict[str, Any] | None] = handle_request,
) -> int:
    """Serve newline-delimited MCP JSON-RPC over the supplied stdio streams."""

    while True:
        line = stream.readline(MAX_REQUEST_BYTES + 2)
        if not line:
            break
        if len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
            output.write(
                json.dumps(
                    _jsonrpc_error(
                        None,
                        -32600,
                        "Invalid Request",
                        reason="request_too_large",
                    )
                )
                + "\n"
            )
            output.flush()
            continue
        raw = line.strip()
        if not raw:
            continue
        try:
            request = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
            response = _dispatch_message(request, handler=handler)
        except (BoundaryError, UnicodeError, json.JSONDecodeError):
            response = _jsonrpc_error(
                None,
                -32700,
                "Parse error",
                reason="parse_error",
            )
        if response is not None:
            output.write(
                json.dumps(response, ensure_ascii=False, separators=(",", ":"))
                + "\n"
            )
            output.flush()
    return 0


def _validate_assignment_fixtures(policy: Mapping[str, Any]) -> None:
    """Validate freshness and binding of the immutable demo assignment set."""

    try:
        assignment_root = ASSIGNMENT_ROOT.resolve(strict=True)
        assignment_metadata = ASSIGNMENT_ROOT.lstat()
        assignment_entries = sorted(
            ASSIGNMENT_ROOT.iterdir(),
            key=lambda path: path.name,
        )
    except OSError as exc:
        raise BoundaryError("assignment_fixture_unavailable") from exc
    expected_assignment_names = [f"{task_id}.json" for task_id in FIXTURE_TASK_IDS]
    if (
        ASSIGNMENT_ROOT.is_symlink()
        or assignment_root != ASSIGNMENT_ROOT
        or not stat.S_ISDIR(assignment_metadata.st_mode)
        or assignment_metadata.st_mode & 0o002
        or [path.name for path in assignment_entries] != expected_assignment_names
    ):
        raise BoundaryError("assignment_fixture_invalid")
    for path in assignment_entries:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or metadata.st_size > MAX_REQUEST_BYTES
            or os.name == "posix"
            and (
                assignment_metadata.st_gid != SERVICE_GID
                or metadata.st_uid != SERVICE_UID
                or metadata.st_gid != SERVICE_GID
            )
        ):
            raise BoundaryError("assignment_fixture_invalid")
        evidence = _read_json(path)
        if set(evidence) != {"task", "spec"}:
            raise BoundaryError("assignment_fixture_invalid")
        task_id = path.stem
        assignment, candidate = validate_teamharness_task(
            evidence,
            task_id=task_id,
            revision=policy["repositoryRevision"],
            workspace_binding=policy["workspaceBinding"],
            policy=policy,
        )
        expected_tier = FIXTURE_TASK_TIERS[task_id]
        if (
            assignment["taskId"] != task_id
            or candidate["tier"] != expected_tier
            or assignment["fullSuite"] != (expected_tier == "T3")
        ):
            raise BoundaryError("assignment_fixture_invalid")


def liveness_attestation() -> dict[str, Any]:
    """Fail after expiry; a main-container restart refreshes fixed fixtures."""

    policy = load_execution_policy()
    _validate_assignment_fixtures(policy)
    inflight, maximum = _execution_state()
    completed = _completed_state()
    return {
        "ok": True,
        "server": SERVER_NAME,
        "transport": "streamable-http",
        "protocolVersion": PROTOCOL_VERSION,
        "assignmentFresh": True,
        "assignmentMaxAgeSeconds": ASSIGNMENT_MAX_AGE_SECONDS,
        "assignmentExpiryAction": ASSIGNMENT_EXPIRY_ACTION,
        "inflightExecutions": inflight,
        "maxConcurrentExecutions": maximum,
        "completedTaskCount": completed,
    }


def readiness_attestation() -> dict[str, Any]:
    """Return only public, digest-bound readiness facts for the CI service."""

    policy = load_execution_policy()
    _validate_assignment_fixtures(policy)
    manifest = repository_manifest(
        REPOSITORY_ROOT,
        max_files=policy["maxRepositoryFiles"],
        max_bytes=policy["maxRepositoryBytes"],
    )
    if manifest.digest != policy["repositoryManifestSha256"]:
        raise BoundaryError("repository_revision_drift")
    signer = OpenSSLEd25519ReceiptSigner(
        TEST_EXECUTION_RECEIPT_PRIVATE_KEY,
        openssl_path=PRODUCTION_OPENSSL,
        enforce_production_metadata=True,
    )
    receipt_policy_path = _trusted_runtime_file(TEST_RECEIPT_POLICY_PATH)
    receipt_policy = validate_receipt_policy(
        _read_json(receipt_policy_path),
        execution_policy=policy,
        public_key_sha256=signer.public_key_sha256,
    )
    inflight, maximum = _execution_state()
    completed = _completed_state()
    return {
        "ok": True,
        "server": SERVER_NAME,
        "transport": "streamable-http",
        "protocolVersion": PROTOCOL_VERSION,
        "stateless": False,
        "mcpSessionsSupported": False,
        "repositoryRevision": policy["repositoryRevision"],
        "repositoryArchiveSha256": policy["repositoryArchiveSha256"],
        "serverSha256": policy["serverSha256"],
        "executionPolicySha256": policy["workspaceBinding"],
        "receiptPublicKeySha256": signer.public_key_sha256,
        "receiptPolicySha256": _sha256_file(receipt_policy_path),
        "receiptIssuer": TEST_EXECUTION_RECEIPT_ISSUER,
        "receiptLifetimeSeconds": receipt_policy["receiptLifetimeSeconds"],
        "replayScope": receipt_policy["replayScope"],
        "replayLedgerPersistentAcrossPodReplacement": receipt_policy[
            "replayLedgerPersistentAcrossPodReplacement"
        ],
        "remainingThreat": receipt_policy["remainingThreat"],
        "privateKeyLoaded": True,
        "credentialsForwarded": False,
        "repositoryMode": REPOSITORY_MODE,
        "testCommandSource": TEST_COMMAND_SOURCE,
        "assignmentSource": ASSIGNMENT_SOURCE,
        "assignmentSourceLiveAgentTeams": ASSIGNMENT_SOURCE_LIVE_AGENTTEAMS,
        "dynamicCandidateSupported": DYNAMIC_CANDIDATE_SUPPORTED,
        "testPathMutationSupported": TEST_PATH_MUTATION_SUPPORTED,
        "testCompletionPolicy": TEST_COMPLETION_POLICY,
        "minimumExecutedTests": policy["minimumExecutedTests"],
        "resourceLimitsApplied": policy["resourceLimitsApplied"],
        "runAsUser": SERVICE_UID,
        "runAsGroup": SERVICE_GID,
        "httpCallerAuthentication": "network-policy-only-no-mtls-or-spiffe",
        "testerIdentityAuthenticatedByService": False,
        "deploymentBlockers": [
            "application-layer-mtls-or-spiffe-not-configured",
            "live-agentteams-task-projection-not-configured",
            "end-to-end-consumer-replay-flow-not-exercised",
            "task-result-cache-not-persistent-across-container-restart",
        ],
        "taskReplayCacheScope": "container-incarnation",
        "endToEndReady": False,
        "taskExecutionSemantics": (
            "single-execution-per-task-per-container-incarnation-cached-response"
        ),
        "fixtureTaskIds": list(FIXTURE_TASK_IDS),
        "assignmentFresh": True,
        "assignmentMaxAgeSeconds": ASSIGNMENT_MAX_AGE_SECONDS,
        "assignmentExpiryAction": ASSIGNMENT_EXPIRY_ACTION,
        "inflightExecutions": inflight,
        "maxConcurrentExecutions": maximum,
        "completedTaskCount": completed,
    }


def _accepted_media_types(value: str) -> set[str]:
    accepted: set[str] = set()
    for part in value.split(","):
        components = [component.strip() for component in part.split(";")]
        media_type = components[0].lower()
        quality = 1.0
        for parameter in components[1:]:
            name, separator, parameter_value = parameter.partition("=")
            if separator and name.strip().lower() == "q":
                try:
                    quality = float(parameter_value.strip())
                except ValueError:
                    quality = 0.0
        if quality > 0:
            accepted.add(media_type)
    return accepted


def _single_initialize(message: Any) -> bool:
    return (
        isinstance(message, dict)
        and message.get("method") == "initialize"
        and "id" in message
    )


class CICDHTTPHandler(BaseHTTPRequestHandler):
    """Strict sessionless MCP Streamable HTTP transport with bounded state."""

    server_version = "devflow-cicd/2.0"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(SOCKET_READ_TIMEOUT_SECONDS)

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        # No browser origin is authorized for this cluster-internal service.
        # Non-browser AgentTeams clients omit Origin.
        origins = self.headers.get_all("Origin", failobj=[])
        if origins:
            self._json(
                403,
                _jsonrpc_error(
                    None,
                    -32600,
                    "Invalid Request",
                    reason="origin_forbidden",
                ),
            )
            return False
        return True

    def _json(
        self,
        status: int,
        value: Any,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        payload = _canonical(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("MCP-Protocol-Version", PROTOCOL_VERSION)
        for name, header_value in (headers or {}).items():
            self.send_header(name, header_value)
        self.end_headers()
        self.wfile.write(payload)

    def _empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("MCP-Protocol-Version", PROTOCOL_VERSION)
        self.end_headers()

    def _http_error(
        self,
        status: int,
        *,
        reason: str,
        code: int = -32600,
        message: str = "Invalid Request",
    ) -> None:
        self._json(
            status,
            _jsonrpc_error(None, code, message, reason=reason),
        )

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/mcp":
            self._json(
                405,
                _jsonrpc_error(
                    None,
                    -32600,
                    "Invalid Request",
                    reason="sse_not_supported",
                ),
                headers={"Allow": "POST"},
            )
            return
        if self.path == "/healthz":
            try:
                self._json(200, liveness_attestation())
            except Exception:
                self._json(
                    503,
                    {
                        "ok": False,
                        "server": SERVER_NAME,
                        "transport": "streamable-http",
                        "error": "boundary_not_live",
                        "assignmentExpiryAction": ASSIGNMENT_EXPIRY_ACTION,
                    },
                )
            return
        if self.path == "/readyz":
            try:
                self._json(200, readiness_attestation())
            except Exception:
                self._json(
                    503,
                    {
                        "ok": False,
                        "server": SERVER_NAME,
                        "transport": "streamable-http",
                        "error": "boundary_not_ready",
                        "assignmentExpiryAction": ASSIGNMENT_EXPIRY_ACTION,
                    },
                )
            return
        self._json(404, {"ok": False, "error": "not_found", "server": SERVER_NAME})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path != "/mcp":
            self._json(404, {"ok": False, "error": "not_found", "server": SERVER_NAME})
            return
        if self.headers.get_all("Mcp-Session-Id", failobj=[]):
            self._http_error(400, reason="sessions_not_supported")
            return
        accept_headers = self.headers.get_all("Accept", failobj=[])
        if len(accept_headers) != 1 or not {
            "application/json",
            "text/event-stream",
        }.issubset(_accepted_media_types(accept_headers[0])):
            self._http_error(406, reason="accept_header_invalid")
            return
        content_types = self.headers.get_all("Content-Type", failobj=[])
        content_lengths = self.headers.get_all("Content-Length", failobj=[])
        transfer_encodings = self.headers.get_all("Transfer-Encoding", failobj=[])
        if (
            len(content_types) != 1
            or content_types[0].split(";", 1)[0].strip().lower()
            != "application/json"
            or len(content_lengths) != 1
            or transfer_encodings
            or not content_lengths[0].isascii()
            or not content_lengths[0].isdigit()
        ):
            self._http_error(400, reason="invalid_http_request")
            return
        length = int(content_lengths[0])
        if not 1 <= length <= MAX_REQUEST_BYTES:
            self._http_error(413, reason="request_too_large")
            return
        try:
            raw = self.rfile.read(length)
        except TimeoutError:
            self.close_connection = True
            self._http_error(
                408,
                reason="request_read_timeout",
                code=-32000,
                message="Request timeout",
            )
            return
        if len(raw) != length:
            self._http_error(
                400,
                reason="incomplete_request_body",
                code=-32700,
                message="Parse error",
            )
            return
        try:
            message = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (BoundaryError, UnicodeError, json.JSONDecodeError):
            self._http_error(
                400,
                reason="parse_error",
                code=-32700,
                message="Parse error",
            )
            return
        versions = self.headers.get_all("MCP-Protocol-Version", failobj=[])
        if _single_initialize(message):
            if len(versions) > 1 or versions and versions[0] != PROTOCOL_VERSION:
                self._http_error(400, reason="protocol_version_invalid")
                return
        elif len(versions) > 1 or versions and versions[0] != PROTOCOL_VERSION:
            self._http_error(400, reason="protocol_version_invalid")
            return
        response = _dispatch_message(message, handler=handle_request)
        if response is None:
            self._empty(202)
            return
        self._json(200, response)

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        self._json(
            405,
            _jsonrpc_error(
                None,
                -32600,
                "Invalid Request",
                reason="method_not_allowed",
            ),
            headers={"Allow": "GET, POST"},
        )

    do_DELETE = do_PUT  # noqa: N815 - BaseHTTPRequestHandler dispatch contract
    do_PATCH = do_PUT  # noqa: N815 - BaseHTTPRequestHandler dispatch contract
    do_OPTIONS = do_PUT  # noqa: N815 - BaseHTTPRequestHandler dispatch contract
    do_HEAD = do_PUT  # noqa: N815 - BaseHTTPRequestHandler dispatch contract


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Bound request threads and reject overload before allocating a worker."""

    daemon_threads = True
    request_queue_size = MAX_HTTP_CONNECTIONS

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._connection_slots = threading.BoundedSemaphore(MAX_HTTP_CONNECTIONS)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Length: 0\r\n"
                    b"Cache-Control: no-store\r\n"
                    b"Connection: close\r\n\r\n"
                )
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


def serve_http(host: str, port: int) -> int:
    """Serve the fixed stateless MCP endpoint for the isolated CI Deployment."""

    if host not in {"0.0.0.0", "127.0.0.1"} or not 1 <= port <= 65_535:
        raise BoundaryError("http_bind_invalid")
    server = BoundedThreadingHTTPServer((host, port), CICDHTTPHandler)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:  # pragma: no cover - operator shutdown
        pass
    finally:
        server.server_close()
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the isolated Tester CI MCP without Worker credentials."
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.transport == "stdio":
        return serve_stdio(sys.stdin.buffer, sys.stdout)
    return serve_http(args.host, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
