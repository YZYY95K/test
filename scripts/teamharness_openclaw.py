#!/usr/bin/env python3
"""Install or verify upstream TeamHarness assets for an OpenClaw workspace.

This adapter is intentionally offline. It never reads Kubernetes Secrets and
never embeds Matrix, gateway, or object-storage credentials in mcporter.json.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "agentteams" / "teamharness" / "guarded_server.py"
ROLES = {"leader", "worker", "remote-member", "manager"}
SENSITIVE_ENV_PARTS = ("TOKEN", "SECRET", "PASSWORD", "ACCESS_KEY", "API_KEY")
REQUIRED_MCP_FILES = ("server.py", "message_tool.py", "roomflow_tool.py")
UPSTREAM_AGENTTEAMS_COMMIT = "78d0ceda336befa6e62bf89fc1a6b08b965e128d"
TEAMHARNESS_VERSION = "0.1.0"
PRODUCTION_APPROVAL_PUBLIC_KEY = Path("/etc/devflow/teamharness/approval-ed25519.pub")
PRODUCTION_APPROVAL_POLICY = Path("/etc/devflow/teamharness/approval-policy.json")
PRODUCTION_APPROVAL_LEDGER = Path("/var/lib/devflow/teamharness/approval-ledger.json")
PRODUCTION_OPENSSL = Path("/usr/bin/openssl")
PRODUCTION_GITHUB_RECEIPT_PUBLIC_KEY = Path(
    "/etc/devflow/github-evidence/receipt-ed25519.pub"
)
PRODUCTION_GITHUB_RECEIPT_POLICY = Path(
    "/etc/devflow/github-evidence/receipt-policy.json"
)
PRODUCTION_TEST_RECEIPT_PUBLIC_KEY = Path(
    "/etc/devflow/teamharness/test-receipt-ed25519.pub"
)
PRODUCTION_TEST_RECEIPT_POLICY = Path(
    "/etc/devflow/teamharness/test-receipt-policy.json"
)
PRODUCTION_TEST_RECEIPT_LEDGER = Path(
    "/var/lib/devflow/teamharness/test-receipt-ledger.json"
)
PRODUCTION_RUNTIME_BINDING = Path("/etc/devflow/teamharness/runtime-binding.json")
PRODUCTION_INSTALL_MANIFEST = Path("/etc/devflow/teamharness/install-manifest.json")
PRODUCTION_EXECUTION_ROOT = Path("/opt/devflow/teamharness")
PRODUCTION_GUARD = PRODUCTION_EXECUTION_ROOT / "guarded_server.py"
PRODUCTION_ADAPTER = PRODUCTION_EXECUTION_ROOT / "teamharness_openclaw.py"
PRODUCTION_PLUGIN_ROOT = PRODUCTION_EXECUTION_ROOT / "plugin"
PRODUCTION_SERVER = PRODUCTION_PLUGIN_ROOT / "mcp" / "server.py"
PRODUCTION_PYTHON = Path("/usr/bin/python3")
APPROVAL_AUDIENCE = "devflow.agentteams.projectflow.approval/v1"
GITHUB_RECEIPT_AUDIENCE = "devflow.github-content-response/v2"
GITHUB_RECEIPT_SIGNATURE_DOMAIN = "devflow.github-content-receipt/v2"
GITHUB_RECEIPT_CONSUMER = "devflow-locator"
TEST_RECEIPT_SCHEMA = "devflow.test-execution-receipt/v1"
TEST_RECEIPT_LEDGER_SCHEMA = "devflow.test-execution-receipt-ledger/v2"
TEST_RECEIPT_ISSUER = "devflow-tester-cicd"
TEST_RECEIPT_AUDIENCE = "devflow-teamharness"
TEST_RECEIPT_REPLAY_SCOPE = "pod-incarnation"
TEST_RECEIPT_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT = False
TEST_RECEIPT_LIFETIME_SECONDS = 120
TEST_RECEIPT_RESERVATION_LEASE_SECONDS = 30
TEST_RECEIPT_LEDGER_MAX_RECORDS = 100_000
TEST_RECEIPT_CONSUMPTION_PROTOCOL = (
    "reserve-upstream-dual-authority-readback-commit/v1"
)
TEST_RECEIPT_AUTHORITATIVE_READBACK = [
    "taskflow.check_task",
    "projectflow.resolve_project",
]
TEST_RECEIPT_RESERVATION_FIELDS = frozenset(
    {
        "state",
        "exp",
        "receiptSha256",
        "runId",
        "taskId",
        "acceptRequestSha256",
        "acceptResultSha256",
        "ownerId",
        "ownerPid",
        "ownerProcessIdentity",
        "reservedAt",
        "leaseExpiresAt",
        "committedAt",
        "authoritativeResultSha256",
        "upstreamResponseSha256",
    }
)
TEST_RECEIPT_POLICY_FIELDS = frozenset(
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
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
APPROVAL_DOMAIN_RE = re.compile(r"[0-9a-f]{64}")
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
REVISION_RE = re.compile(r"[0-9a-f]{40}")
SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
JTI_RE = re.compile(r"[0-9a-f]{32}")
RUNTIME_BINDING_FIELDS = {
    "schemaVersion",
    "teamName",
    "memberName",
    "runtimeName",
    "podName",
    "teamHarnessRole",
}
UPSTREAM_FILE_SHA256 = {
    "plugin.yaml": "40121114d1f2a5897e90e21f819f34491bd8062eae25634825f9e7b50b61d518",
    "mcp/server.py": "cb9971baae3545f440821ecf1fd18c76078962a1fe1591141cc88026bf5b684f",
    "mcp/message_tool.py": "03e8fcfcaf002c5d9dd0c023b85bd4d2f4641b83cb59c6d89be08a9c1689c47c",
    "mcp/roomflow_tool.py": "db127d550cf9155c133657ab7c89fee48292c07587a061954bd60b4c14991680",
}
AGENTS_BEGIN = "<!-- BEGIN DEVFLOW TEAMHARNESS COLLABORATION -->"
AGENTS_END = "<!-- END DEVFLOW TEAMHARNESS COLLABORATION -->"
_SIMPLE_MAPPING = re.compile(r"^(?P<indent> *)(?P<key>[A-Za-z][A-Za-z0-9_-]*) *:(?P<tail>.*)$")
FORBIDDEN_RUNTIME_VALUE_PATHS = (
    ("matrix", "accessToken"),
    ("desired", "model", "gatewayKey"),
    ("desired", "channels", "dingtalk", "clientSecret"),
    ("desired", "channels", "dingtalk", "client_secret"),
)

# The fallback is intentionally tied to the already hash-verified upstream
# plugin. It does not attempt to become a general-purpose YAML parser.
_AUDITED_PLUGIN_MANIFEST: dict[str, Any] = {
    "apiVersion": "hiclaw.agentteam/v1alpha1",
    "kind": "AgentTeamPlugin",
    "metadata": {"name": "teamharness", "version": TEAMHARNESS_VERSION},
    "prompts": {
        "team": "prompts/team/TEAMS.md",
        "agent": {
            "leader": "prompts/agent/leader.md",
            "worker": "prompts/agent/worker.md",
            "remoteMember": "prompts/agent/remote-member.md",
        },
        "manager": {
            "agents": "prompts/manager/AGENTS.md",
            "tools": "prompts/manager/TOOLS.md",
            "heartbeat": "prompts/manager/HEARTBEAT.md",
        },
    },
    "skills": {
        "agent": [
            {
                "id": "mcporter",
                "path": "skills/agent/mcporter",
                "roles": ["leader", "worker", "manager", "remote-member"],
            },
            {
                "id": "find-skills",
                "path": "skills/agent/find-skills",
                "roles": ["leader", "worker", "manager", "remote-member"],
            },
        ],
        "team": [
            {
                "id": "communication",
                "path": "skills/team/communication",
                "roles": ["leader", "worker", "manager", "remote-member"],
            },
            {
                "id": "file-sharing",
                "path": "skills/team/file-sharing",
                "roles": ["leader", "worker", "manager", "remote-member"],
            },
            {
                "id": "roomflow",
                "path": "skills/team/roomflow",
                "roles": ["leader"],
            },
            {
                "id": "team-coordination",
                "path": "skills/team/team-coordination",
                "roles": ["leader"],
            },
            {
                "id": "project-management",
                "path": "skills/team/project-management",
                "roles": ["leader"],
            },
            {
                "id": "task-delegation",
                "path": "skills/team/task-delegation",
                "roles": ["leader"],
            },
            {
                "id": "task-execution",
                "path": "skills/team/task-execution",
                "roles": ["worker", "remote-member"],
            },
        ],
    },
}


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _approval_ledger_template() -> dict[str, Any]:
    return {"schemaVersion": "1.0", "projects": {}, "usedNonces": {}}


def _validate_approval_ledger(path: Path) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "projects",
        "usedNonces",
    }:
        raise ValueError("approval ledger has an invalid schema")
    if (
        value.get("schemaVersion") != "1.0"
        or not isinstance(value.get("projects"), dict)
        or not isinstance(value.get("usedNonces"), dict)
    ):
        raise ValueError("approval ledger has invalid field types")


def _validate_ed25519_public_key(path: Path, openssl_path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"approval public key does not exist: {path}")
    if not openssl_path.is_file():
        raise ValueError(f"system OpenSSL does not exist: {openssl_path}")
    completed = subprocess.run(
        [
            str(openssl_path),
            "pkey",
            "-pubin",
            "-in",
            str(path),
            "-text",
            "-noout",
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0 or "ED25519" not in output.upper():
        raise ValueError("approval public key must be a valid Ed25519 public key")


def _install_approval_policy(
    public_key: Path,
    approval_domain: str,
    policy_path: Path,
    ledger_path: Path,
    openssl_path: Path,
    guard_sha256: str,
    adapter_sha256: str,
    server_sha256: str,
) -> dict[str, Any]:
    if (
        not isinstance(approval_domain, str)
        or APPROVAL_DOMAIN_RE.fullmatch(approval_domain) is None
    ):
        raise ValueError("approval domain must be exactly 64 lowercase hex characters")
    _validate_ed25519_public_key(public_key, openssl_path)
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    if public_key.resolve() != policy_path.resolve():
        if policy_path.exists():
            policy_path.chmod(0o644)
        shutil.copy2(public_key, policy_path)
    policy_path.chmod(0o444)
    if policy_path == PRODUCTION_APPROVAL_PUBLIC_KEY and hasattr(os, "chown"):
        os.chown(policy_path, 0, 0)
    _validate_ed25519_public_key(policy_path, openssl_path)
    if not ledger_path.exists():
        ledger_path.write_text(
            json.dumps(_approval_ledger_template(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    _validate_approval_ledger(ledger_path)
    ledger_path.chmod(0o600)
    if ledger_path == PRODUCTION_APPROVAL_LEDGER and hasattr(os, "chown"):
        os.chown(ledger_path, 0, 0)
    policy_attestation_path = policy_path.with_name("approval-policy.json")
    policy_key_sha256 = _sha256(policy_path)
    policy = {
        "schemaVersion": "1.1",
        "algorithm": "Ed25519",
        "audience": APPROVAL_AUDIENCE,
        "approvalDomain": approval_domain,
        "adapterSha256": adapter_sha256,
        "guardSha256": guard_sha256,
        "policyAttestationPath": str(policy_attestation_path),
        "publicKeyPath": str(policy_path),
        "publicKeySha256": policy_key_sha256,
        "policyKeySha256": policy_key_sha256,
        "serverSha256": server_sha256,
        "ledgerPath": str(ledger_path),
        "opensslPath": str(openssl_path),
        "maxApprovalLifetimeSeconds": 900,
        "remainingThreat": (
            "The guard, mcporter entry, and install manifest must be mounted "
            "read-only or protected by the container runtime; a process able to "
            "replace the executable trust chain can bypass an in-process guard."
        ),
    }
    if policy_attestation_path.exists():
        policy_attestation_path.chmod(0o644)
    policy_attestation_path.write_text(
        json.dumps(policy, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    policy_attestation_path.chmod(0o444)
    if policy_attestation_path == PRODUCTION_APPROVAL_POLICY and hasattr(os, "chown"):
        os.chown(policy_attestation_path, 0, 0)
    return policy


def _make_directory_writable(path: Path, mode: int = 0o755) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    if hasattr(os, "chown"):
        os.chown(path, 0, 0)


def _copy_read_only(source: Path, target: Path, mode: int = 0o444) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.chmod(0o644)
    shutil.copy2(source, target)
    target.chmod(mode)
    if hasattr(os, "chown"):
        os.chown(target, 0, 0)


def _ed25519_public_key_digest(public_key: Path, openssl_path: Path) -> str:
    completed = subprocess.run(
        [
            str(openssl_path),
            "pkey",
            "-pubin",
            "-in",
            str(public_key),
            "-outform",
            "DER",
        ],
        capture_output=True,
        check=False,
        timeout=10,
    )
    public_der = completed.stdout
    if (
        completed.returncode != 0
        or len(public_der) != 44
        or not public_der.startswith(ED25519_SPKI_PREFIX)
    ):
        raise ValueError("receipt public key must be a valid Ed25519 public key")
    return hashlib.sha256(public_der).hexdigest()


def _install_github_receipt_policy(
    public_key: Path,
    public_key_path: Path,
    policy_path: Path,
    openssl_path: Path,
) -> dict[str, Any]:
    _validate_ed25519_public_key(public_key, openssl_path)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    _copy_read_only(public_key, public_key_path)
    _validate_ed25519_public_key(public_key_path, openssl_path)
    policy = {
        "schemaVersion": "1.0",
        "algorithm": "Ed25519",
        "audience": GITHUB_RECEIPT_AUDIENCE,
        "signatureDomain": GITHUB_RECEIPT_SIGNATURE_DOMAIN,
        "consumerRuntimeName": GITHUB_RECEIPT_CONSUMER,
        "publicKeyPath": str(public_key_path),
        "publicKeySha256": _ed25519_public_key_digest(
            public_key_path,
            openssl_path,
        ),
        "publicKeyFileSha256": _sha256(public_key_path),
        "policyPath": str(policy_path),
        "opensslPath": str(openssl_path),
    }
    if policy_path.exists():
        policy_path.chmod(0o644)
    policy_path.write_text(
        json.dumps(policy, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    policy_path.chmod(0o444)
    if policy_path == PRODUCTION_GITHUB_RECEIPT_POLICY and hasattr(os, "chown"):
        os.chown(policy_path, 0, 0)
    return policy


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _validate_test_receipt_ledger(path: Path) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or set(value) != {"schemaVersion", "reservations"}
        or value.get("schemaVersion") != TEST_RECEIPT_LEDGER_SCHEMA
        or not isinstance(value.get("reservations"), dict)
        or len(value["reservations"]) > TEST_RECEIPT_LEDGER_MAX_RECORDS
    ):
        raise ValueError("test receipt ledger has an invalid schema")
    for jti, record in value["reservations"].items():
        state = record.get("state") if isinstance(record, dict) else None
        committed_at = record.get("committedAt") if isinstance(record, dict) else None
        authoritative_digest = (
            record.get("authoritativeResultSha256")
            if isinstance(record, dict)
            else None
        )
        upstream_digest = (
            record.get("upstreamResponseSha256")
            if isinstance(record, dict)
            else None
        )
        if (
            not isinstance(jti, str)
            or JTI_RE.fullmatch(jti) is None
            or not isinstance(record, dict)
            or set(record) != TEST_RECEIPT_RESERVATION_FIELDS
            or state not in {"pending", "committed"}
            or isinstance(record.get("exp"), bool)
            or not isinstance(record.get("exp"), int)
            or not isinstance(record.get("receiptSha256"), str)
            or DIGEST_RE.fullmatch(record["receiptSha256"]) is None
            or not isinstance(record.get("runId"), str)
            or SAFE_ID_RE.fullmatch(record["runId"]) is None
            or not isinstance(record.get("taskId"), str)
            or SAFE_ID_RE.fullmatch(record["taskId"]) is None
            or not isinstance(record.get("acceptRequestSha256"), str)
            or DIGEST_RE.fullmatch(record["acceptRequestSha256"]) is None
            or not isinstance(record.get("acceptResultSha256"), str)
            or DIGEST_RE.fullmatch(record["acceptResultSha256"]) is None
            or not isinstance(record.get("ownerId"), str)
            or DIGEST_RE.fullmatch(record["ownerId"]) is None
            or isinstance(record.get("ownerPid"), bool)
            or not isinstance(record.get("ownerPid"), int)
            or record["ownerPid"] < 1
            or not isinstance(record.get("ownerProcessIdentity"), str)
            or DIGEST_RE.fullmatch(record["ownerProcessIdentity"]) is None
            or isinstance(record.get("reservedAt"), bool)
            or not isinstance(record.get("reservedAt"), int)
            or isinstance(record.get("leaseExpiresAt"), bool)
            or not isinstance(record.get("leaseExpiresAt"), int)
            or record["leaseExpiresAt"] < record["reservedAt"]
            or (
                state == "pending"
                and (
                    committed_at is not None
                    or authoritative_digest is not None
                    or upstream_digest is not None
                )
            )
            or (
                state == "committed"
                and (
                    isinstance(committed_at, bool)
                    or not isinstance(committed_at, int)
                    or committed_at < record["reservedAt"]
                    or not isinstance(authoritative_digest, str)
                    or DIGEST_RE.fullmatch(authoritative_digest) is None
                    or not isinstance(upstream_digest, str)
                    or DIGEST_RE.fullmatch(upstream_digest) is None
                )
            )
        ):
            raise ValueError("test receipt ledger contains an invalid record")


def _migrate_test_receipt_ledger_v1(path: Path) -> None:
    """Preserve v1 replay denials as committed, deliberately non-matchable records."""

    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("legacy test receipt ledger is not a stable regular file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return
    if (
        not isinstance(value, dict)
        or set(value) != {"schemaVersion", "usedJtis"}
        or value.get("schemaVersion") != "devflow.test-execution-receipt-ledger/v1"
        or not isinstance(value.get("usedJtis"), dict)
    ):
        return
    reservations: dict[str, Any] = {}
    for jti, old in value["usedJtis"].items():
        if (
            not isinstance(jti, str)
            or JTI_RE.fullmatch(jti) is None
            or not isinstance(old, dict)
            or set(old) != {"exp", "receiptSha256", "runId", "taskId", "consumedAt"}
            or isinstance(old.get("exp"), bool)
            or not isinstance(old.get("exp"), int)
            or isinstance(old.get("consumedAt"), bool)
            or not isinstance(old.get("consumedAt"), int)
            or not isinstance(old.get("receiptSha256"), str)
            or DIGEST_RE.fullmatch(old["receiptSha256"]) is None
            or not isinstance(old.get("runId"), str)
            or SAFE_ID_RE.fullmatch(old["runId"]) is None
            or not isinstance(old.get("taskId"), str)
            or SAFE_ID_RE.fullmatch(old["taskId"]) is None
        ):
            raise ValueError("legacy test receipt ledger contains an invalid record")
        migration_digest = hashlib.sha256(
            _canonical_json({"schema": "legacy-v1-replay-denial", "jti": jti, **old})
        ).hexdigest()
        consumed_at = int(old["consumedAt"])
        reservations[jti] = {
            "state": "committed",
            "exp": int(old["exp"]),
            "receiptSha256": old["receiptSha256"],
            "runId": old["runId"],
            "taskId": old["taskId"],
            "acceptRequestSha256": migration_digest,
            "acceptResultSha256": migration_digest,
            "ownerId": migration_digest,
            "ownerPid": 1,
            "ownerProcessIdentity": migration_digest,
            "reservedAt": consumed_at,
            "leaseExpiresAt": consumed_at,
            "committedAt": consumed_at,
            "authoritativeResultSha256": migration_digest,
            "upstreamResponseSha256": migration_digest,
        }
    migrated = {
        "schemaVersion": TEST_RECEIPT_LEDGER_SCHEMA,
        "reservations": reservations,
    }
    temporary = path.with_name(f".{path.name}.{os.getpid()}.migration.tmp")
    try:
        temporary.write_bytes(_canonical_json(migrated))
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _install_test_receipt_policy(
    public_key: Path,
    policy_source: Path,
    public_key_path: Path,
    policy_path: Path,
    ledger_path: Path,
    openssl_path: Path,
) -> dict[str, Any]:
    """Install only public CI receipt trust plus a root-owned replay ledger."""

    _validate_ed25519_public_key(public_key, openssl_path)
    try:
        source_bytes = policy_source.read_bytes()
        policy = json.loads(source_bytes.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("test receipt policy is unavailable or malformed") from exc
    if (
        policy_source.is_symlink()
        or not isinstance(policy, dict)
        or set(policy) != TEST_RECEIPT_POLICY_FIELDS
        or source_bytes != _canonical_json(policy)
    ):
        raise ValueError("test receipt policy must be canonical exact-schema JSON")
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    if public_key.resolve() != public_key_path.resolve():
        _copy_read_only(public_key, public_key_path)
    else:
        public_key_path.chmod(0o444)
    _validate_ed25519_public_key(public_key_path, openssl_path)
    file_sha256 = _sha256(public_key_path)
    key_sha256 = _ed25519_public_key_digest(public_key_path, openssl_path)
    if (
        policy.get("schemaVersion") != "1.0"
        or policy.get("algorithm") != "Ed25519"
        or policy.get("audience") != TEST_RECEIPT_AUDIENCE
        or policy.get("issuer") != TEST_RECEIPT_ISSUER
        or policy.get("signatureDomain") != TEST_RECEIPT_SCHEMA
        or policy.get("publicKeyPath") != str(public_key_path)
        or policy.get("publicKeyFileSha256") != file_sha256
        or policy.get("publicKeySha256") != key_sha256
        or policy.get("policyAttestationPath") != str(policy_path)
        or policy.get("opensslPath") != str(openssl_path)
        or policy.get("replayLedgerPath") != str(ledger_path)
        or policy.get("replayScope") != TEST_RECEIPT_REPLAY_SCOPE
        or policy.get("replayLedgerPersistentAcrossPodReplacement")
        is not TEST_RECEIPT_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
        or policy.get("receiptLifetimeSeconds")
        != TEST_RECEIPT_LIFETIME_SECONDS
        or policy.get("maxReceiptLifetimeSeconds")
        != TEST_RECEIPT_LIFETIME_SECONDS
        or isinstance(policy.get("maxClockSkewSeconds"), bool)
        or not isinstance(policy.get("maxClockSkewSeconds"), int)
        or not 0 <= policy["maxClockSkewSeconds"] <= 30
        or not isinstance(policy.get("remainingThreat"), str)
        or "root" not in policy["remainingThreat"].lower()
        or "pod replacement" not in policy["remainingThreat"].lower()
        or "120" not in policy["remainingThreat"]
    ):
        raise ValueError("test receipt policy identity or public-key binding is invalid")
    for field in (
        "ciServerSha256",
        "ciPolicySha256",
        "repositoryArchiveSha256",
        "repositoryManifestSha256",
    ):
        if (
            not isinstance(policy.get(field), str)
            or DIGEST_RE.fullmatch(policy[field]) is None
        ):
            raise ValueError("test receipt policy digest binding is invalid")
    if (
        not isinstance(policy.get("repositoryRevision"), str)
        or REVISION_RE.fullmatch(policy["repositoryRevision"]) is None
    ):
        raise ValueError("test receipt policy revision binding is invalid")
    if policy_path.exists():
        policy_path.chmod(0o644)
    policy_path.write_bytes(source_bytes)
    policy_path.chmod(0o444)
    if not ledger_path.exists():
        ledger_path.write_bytes(
            _canonical_json(
                {"schemaVersion": TEST_RECEIPT_LEDGER_SCHEMA, "reservations": {}}
            )
        )
    else:
        _migrate_test_receipt_ledger_v1(ledger_path)
    _validate_test_receipt_ledger(ledger_path)
    ledger_path.chmod(0o600)
    if (
        public_key_path == PRODUCTION_TEST_RECEIPT_PUBLIC_KEY
        and policy_path == PRODUCTION_TEST_RECEIPT_POLICY
        and ledger_path == PRODUCTION_TEST_RECEIPT_LEDGER
        and hasattr(os, "chown")
    ):
        for path in (public_key_path, policy_path, ledger_path):
            os.chown(path, 0, 0)
    return policy


def _install_production_execution(plugin_dir: Path) -> dict[str, Any]:
    if not PRODUCTION_PYTHON.is_file():
        raise ValueError("production Python is missing at /usr/bin/python3")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ValueError("production execution-chain installation requires root")
    _make_directory_writable(PRODUCTION_EXECUTION_ROOT)
    _make_directory_writable(PRODUCTION_PLUGIN_ROOT)
    _make_directory_writable(PRODUCTION_PLUGIN_ROOT / "mcp")
    _copy_read_only(Path(__file__).resolve(), PRODUCTION_ADAPTER)
    _copy_read_only(GUARD, PRODUCTION_GUARD)
    _copy_read_only(plugin_dir / "mcp" / "server.py", PRODUCTION_SERVER)
    for name in ("message_tool.py", "roomflow_tool.py"):
        _copy_read_only(
            plugin_dir / "mcp" / name,
            PRODUCTION_PLUGIN_ROOT / "mcp" / name,
        )
    _copy_read_only(plugin_dir / "plugin.yaml", PRODUCTION_PLUGIN_ROOT / "plugin.yaml")
    for directory in (
        PRODUCTION_PLUGIN_ROOT / "mcp",
        PRODUCTION_PLUGIN_ROOT,
        PRODUCTION_EXECUTION_ROOT,
    ):
        directory.chmod(0o555)
        if hasattr(os, "chown"):
            os.chown(directory, 0, 0)
    return {
        "guardPath": str(PRODUCTION_GUARD),
        "guardSha256": _sha256(PRODUCTION_GUARD),
        "adapterPath": str(PRODUCTION_ADAPTER),
        "adapterSha256": _sha256(PRODUCTION_ADAPTER),
        "serverPath": str(PRODUCTION_SERVER),
        "serverSha256": _sha256(PRODUCTION_SERVER),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _optional_yaml_load(text: str) -> tuple[bool, Any]:
    """Use PyYAML when present without making it a runtime requirement."""

    try:
        import yaml
    except ModuleNotFoundError:
        return False, None
    return True, yaml.safe_load(text)


def _source_hash_policy(
    test_hash_policy: Mapping[str, str] | None,
) -> dict[str, str]:
    policy = dict(UPSTREAM_FILE_SHA256 if test_hash_policy is None else test_hash_policy)
    if set(policy) != set(UPSTREAM_FILE_SHA256):
        raise ValueError("TeamHarness source hash policy must cover exactly four files")
    if any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
        for value in policy.values()
    ):
        raise ValueError("TeamHarness source hash policy contains an invalid SHA-256")
    return policy


def _validate_source_integrity(
    plugin_dir: Path,
    test_hash_policy: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Fail before installation unless every pinned upstream file is exact."""

    policy = _source_hash_policy(test_hash_policy)
    for relative, expected in policy.items():
        path = plugin_dir / relative
        if not path.is_file():
            raise ValueError(f"missing pinned TeamHarness source: {relative}")
        if _sha256(path) != expected:
            raise ValueError(f"TeamHarness source integrity mismatch: {relative}")
    return policy


def _manifest(plugin_dir: Path) -> dict[str, Any]:
    path = plugin_dir / "plugin.yaml"
    if not path.is_file():
        raise ValueError(f"missing TeamHarness manifest: {path}")
    text = path.read_text(encoding="utf-8")
    has_yaml, parsed = _optional_yaml_load(text)
    if has_yaml:
        value = parsed
    elif _sha256(path) == UPSTREAM_FILE_SHA256["plugin.yaml"]:
        value = copy.deepcopy(_AUDITED_PLUGIN_MANIFEST)
    else:
        raise ValueError("PyYAML is unavailable and plugin.yaml is not the audited upstream file")
    if not isinstance(value, dict):
        raise ValueError("plugin.yaml must contain a mapping")
    if value.get("kind") != "AgentTeamPlugin":
        raise ValueError("plugin.yaml kind must be AgentTeamPlugin")
    metadata = value.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("name") != "teamharness":
        raise ValueError("plugin.yaml metadata.name must be teamharness")
    if metadata.get("version") != TEAMHARNESS_VERSION:
        raise ValueError(f"plugin.yaml version must be {TEAMHARNESS_VERSION}")
    return value


def _nested_value(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = data
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _strip_yaml_scalar(tail: str) -> str:
    value = tail.strip()
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    if not value or value[0] in "|>&*!{[":
        raise ValueError("runtime config contains an unsupported YAML scalar")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if value[:1] in {"'", '"'} or value[-1:] in {"'", '"'}:
        raise ValueError("runtime config contains a malformed YAML scalar")
    return value


def _stdlib_runtime_paths(text: str) -> dict[tuple[str, ...], str | None]:
    """Parse the strict mapping subset needed from AgentTeams runtime YAML."""

    if not text or "\x00" in text or "\t" in text or "\r" in text:
        raise ValueError("runtime config has unsafe formatting")
    paths: dict[tuple[str, ...], str | None] = {}
    parents: list[str] = []
    previous_depth = 0
    previous_was_mapping = True
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _SIMPLE_MAPPING.fullmatch(raw_line)
        if match is None:
            raise ValueError("runtime config exceeds the supported YAML mapping subset")
        indentation = len(match.group("indent"))
        if indentation % 2:
            raise ValueError("runtime config indentation must use two-space levels")
        depth = indentation // 2
        if depth > previous_depth and (depth != previous_depth + 1 or not previous_was_mapping):
            raise ValueError("runtime config mapping indentation is inconsistent")
        if depth > len(parents):
            raise ValueError("runtime config mapping indentation is inconsistent")
        parents = parents[:depth]
        key = match.group("key")
        path = (*parents, key)
        if path in paths:
            raise ValueError("runtime config contains a duplicate mapping key")
        tail = match.group("tail")
        if not tail.strip() or tail.lstrip().startswith("#"):
            paths[path] = None
            parents.append(key)
            previous_was_mapping = True
        else:
            paths[path] = _strip_yaml_scalar(tail)
            previous_was_mapping = False
        previous_depth = depth
    return paths


def _one_identity_value(values: list[Any], label: str) -> str:
    present = {value.strip() for value in values if isinstance(value, str) and value.strip()}
    if len(present) != 1:
        raise ValueError(f"runtime config must contain one unambiguous {label}")
    return present.pop()


def _runtime_values(path: Path) -> tuple[dict[str, str], list[str]]:
    text = path.read_text(encoding="utf-8")
    has_yaml, value = _optional_yaml_load(text)
    if has_yaml:
        if not isinstance(value, dict):
            raise ValueError("runtime config must contain a mapping")
        configured_role = _one_identity_value(
            [_nested_value(value, ("member", "role")), value.get("role")],
            "role",
        )
        runtime_name = _one_identity_value(
            [
                _nested_value(value, ("member", "runtimeName")),
                _nested_value(value, ("member", "runtime_name")),
                value.get("runtimeName"),
            ],
            "runtimeName",
        )
        matrix_user_id = _one_identity_value(
            [
                _nested_value(value, ("member", "matrixUserId")),
                _nested_value(value, ("matrix", "userId")),
                value.get("matrixUserId"),
            ],
            "matrixUserId",
        )
        leaked = [
            ".".join(value_path)
            for value_path in FORBIDDEN_RUNTIME_VALUE_PATHS
            if _nested_value(value, value_path)
        ]
        return {
            "role": configured_role,
            "runtimeName": runtime_name,
            "matrixUserId": matrix_user_id,
        }, leaked

    paths = _stdlib_runtime_paths(text)
    configured_role = _one_identity_value(
        [paths.get(("member", "role")), paths.get(("role",))], "role"
    )
    runtime_name = _one_identity_value(
        [
            paths.get(("member", "runtimeName")),
            paths.get(("member", "runtime_name")),
            paths.get(("runtimeName",)),
        ],
        "runtimeName",
    )
    matrix_user_id = _one_identity_value(
        [
            paths.get(("member", "matrixUserId")),
            paths.get(("matrix", "userId")),
            paths.get(("matrixUserId",)),
        ],
        "matrixUserId",
    )
    leaked = [
        ".".join(value_path)
        for value_path in FORBIDDEN_RUNTIME_VALUE_PATHS
        if paths.get(value_path)
    ]
    return {
        "role": configured_role,
        "runtimeName": runtime_name,
        "matrixUserId": matrix_user_id,
    }, leaked


def _load_runtime_binding(path: Path) -> dict[str, str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != RUNTIME_BINDING_FIELDS:
        raise ValueError("runtime binding has an invalid exact schema")
    binding = {key: str(value.get(key) or "").strip() for key in RUNTIME_BINDING_FIELDS}
    if binding["schemaVersion"] != "1.0":
        raise ValueError("runtime binding schemaVersion must be 1.0")
    for key in ("teamName", "memberName", "runtimeName", "podName"):
        if re.fullmatch(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?", binding[key]) is None:
            raise ValueError(f"runtime binding {key} is not a safe DNS label")
    if binding["teamHarnessRole"] not in ROLES:
        raise ValueError("runtime binding role is unsupported")
    return binding


def _validate_runtime_config(
    path: Path, role: str, hostname: str, binding: dict[str, str]
) -> dict[str, str]:
    identity, leaked = _runtime_values(path)
    configured_role = identity["role"]
    if configured_role.replace("_", "-") != role:
        raise ValueError(
            f"runtime config role {configured_role!r} does not match install role {role!r}"
        )
    if leaked:
        raise ValueError(
            "runtime config embeds credentials; use environment references instead: "
            + ", ".join(leaked)
        )
    if binding["teamHarnessRole"] != role:
        raise ValueError("runtime binding role does not match the install role")
    if identity["runtimeName"] != binding["runtimeName"]:
        raise ValueError("runtime config and Team member runtimeName disagree")
    if binding["podName"] != hostname:
        raise ValueError("runtime binding podName does not match /etc/hostname")
    match = re.fullmatch(r"@([^:]+):([^:]+)", identity["matrixUserId"])
    if match is None or match.group(1) != identity["runtimeName"]:
        raise ValueError("matrixUserId must identify runtimeName on one Matrix domain")
    return {
        **identity,
        "role": role,
        "hostname": hostname,
        "teamName": binding["teamName"],
        "memberName": binding["memberName"],
        "podName": binding["podName"],
    }


def _role_skill_entries(manifest: dict[str, Any], role: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    groups = manifest.get("skills")
    if not isinstance(groups, dict):
        return entries
    for group in ("agent", "team"):
        values = groups.get(group)
        if not isinstance(values, list):
            continue
        for value in values:
            if not isinstance(value, dict):
                continue
            roles = value.get("roles")
            if isinstance(roles, list) and role in roles:
                entries.append(value)
    return entries


def _prompt_paths(manifest: dict[str, Any], role: str) -> list[str]:
    prompts = manifest.get("prompts")
    if not isinstance(prompts, dict):
        return []
    paths = [str(prompts.get("team") or "")]
    if role == "manager":
        manager = prompts.get("manager")
        if isinstance(manager, dict):
            paths.extend(str(value) for value in manager.values())
    else:
        agents = prompts.get("agent")
        key = "remoteMember" if role == "remote-member" else role
        if isinstance(agents, dict):
            paths.append(str(agents.get(key) or ""))
    return [path for path in paths if path]


def _copy_role_assets(
    plugin_dir: Path,
    workspace: Path,
    role: str,
    manifest: dict[str, Any],
) -> list[Path]:
    installed: list[Path] = []
    mcp_target = workspace / ".teamharness" / "mcp"
    mcp_target.mkdir(parents=True, exist_ok=True)
    for name in REQUIRED_MCP_FILES:
        source = plugin_dir / "mcp" / name
        if not source.is_file():
            raise ValueError(f"missing TeamHarness MCP source: {source}")
        target = mcp_target / name
        shutil.copy2(source, target)
        installed.append(target)
    shutil.copy2(GUARD, mcp_target / GUARD.name)
    installed.append(mcp_target / GUARD.name)

    for entry in _role_skill_entries(manifest, role):
        skill_id = str(entry.get("id") or "").strip()
        relative = str(entry.get("path") or "").strip()
        if not skill_id or not relative:
            continue
        source = plugin_dir / relative
        target_name = (
            skill_id if skill_id in {"mcporter", "find-skills"} else f"teamharness-{skill_id}"
        )
        target = workspace / "skills" / target_name
        if target.exists() and skill_id in {"mcporter", "find-skills"}:
            installed.extend(path for path in target.rglob("*") if path.is_file())
            continue
        shutil.copytree(source, target, dirs_exist_ok=True)
        installed.extend(path for path in target.rglob("*") if path.is_file())

    prompt_target = workspace / ".teamharness" / "prompts"
    for relative in _prompt_paths(manifest, role):
        source = plugin_dir / relative
        if not source.is_file():
            raise ValueError(f"missing TeamHarness prompt: {source}")
        target = prompt_target / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        installed.append(target)
    return installed


def _default_shared_dir(workspace: Path) -> Path:
    if workspace.parent.name == "agents":
        return workspace.parent.parent / "shared"
    return workspace / "shared"


def _mcporter_entry(
    shared_dir: Path,
    command: Path,
    guard_path: Path,
) -> dict[str, Any]:
    return {
        "command": str(command),
        "args": [str(guard_path)],
        "transport": "stdio",
        "env": {
            "TEAMHARNESS_SHARED_DIR": str(shared_dir.resolve()),
        },
    }


def _configure_mcporter(
    workspace: Path,
    shared_dir: Path,
    command: Path,
    guard_path: Path,
    *,
    replace: bool,
) -> Path:
    path = workspace / "config" / "mcporter.json"
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    if not isinstance(data, dict):
        raise ValueError("mcporter.json must contain an object")
    servers = data.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError("mcporter.json mcpServers must contain an object")
    if "teamharness" in servers and not replace:
        raise ValueError("teamharness already exists in mcporter.json; pass --replace")
    servers["teamharness"] = _mcporter_entry(
        shared_dir,
        command,
        guard_path,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _collaboration_block(role: str) -> str:
    heading = f"### DevFlow TeamHarness collaboration contract — {role}"
    identity = f"- Installed TeamHarness role: `{role}`. Do not infer or claim another role."
    if role == "leader":
        body = """- Start with `projectflow.create_project` (or `create_quick_project`) and record the complete plan with `plan_dag` or `plan_loop` before delegation.
- Every project creation must include one explicit immutable `riskTier` from T1 through T5; never infer, omit, or downgrade it later.
- T4/T5 `resume_project`, `accept_task_result`, and `complete_project` require exact-scope, unexpired externally signed Ed25519 approval evidence. `pause_project` never requires approval. Never invent approval evidence.
- Approval is `{evidence, signature}` only. Schema 1.1 evidence binds the fixed audience, deployment approvalDomain, policyKeySha256, guard-generated projectBindingDigest, full approvalRequestDigest, action, projectId, taskId when accepting, riskTier, targetDigest, approvedBy, issuedAt, expiresAt, and nonce. The operator confirmation must name approvalRequestDigest, not targetDigest alone.
- Before `taskflow.delegate_task`, create or reuse one bounded task room with `roomflow.create_task_room` and invite/include the assignee in that room.
- For repository evidence, delegate only to `devflow-locator` and set `spec` to canonical JSON with exactly `schema=devflow.github-assignment-request/v1`, `run_id`, positive `issue_id`, the same `task_id` as the task payload, `trace_id=<run_id>:<task_id>`, `idempotency_key=<run_id>:<task_id>:devflow-locator:github-evidence`, exact `{owner,repo}` repository, a 40-character lowercase commit SHA, and 1..32 sorted unique relative `paths`. Never supply a capability, token path, or issuer URL; the guard obtains a short-lived scope-bound capability and constructs the complete HandoffEnvelope.
- Delegate one bounded task, then send exactly one complete Matrix assignment mention with `message.send`; wait for an ACK for a bounded interval and do not split the effective instruction across messages.
- On ACK timeout, re-send only the same assignmentId with the byte-identical assignment digest. Never create a replacement task or a new assignmentId for that retry.
- Use `taskflow.check_task`, then `projectflow.accept_task_result` only for one submitted, effective result with no validation errors.
- After every planned node is closed, call `projectflow.complete_project`, then `mark_requester_report_sent`, then `filesync.push`; read the file-sync state back and finish only when `pending=false`.
- Do not perform Worker `ack_task`/`submit_task` actions or domain implementation work. Pause rather than bypass any human approval gate."""
    elif role in {"worker", "remote-member"}:
        body = """- On one bounded assignment, use idempotent `taskflow.ack_task` before doing the work; retry only the same task ID and never ACK a terminal task.
- If the acknowledged spec is a `github-evidence` HandoffEnvelope, accept it only when producer is `devflow-lead`, consumer is `devflow-locator`, the envelope task ID matches the assigned task, and the inline digest is valid; never reconstruct, broaden, or copy its capability into messages or errors.
- Produce the assigned canonical artifact first and return it only through the assigned task result; this role cannot call `artifact` or `filesync` directly.
- Use idempotent `taskflow.submit_task` only after the artifact is complete and evidence-backed; never resubmit a terminal task, then stop until a new instruction arrives.
- Never call Leader actions: no project create/plan/accept/complete, room create/archive, delegation/check/cancel, requester-report sync, or team assignment messages.
- If the assignment, artifact path, or acceptance criteria are missing or conflicting, do not improvise control-plane state; return a bounded failure to the Leader."""
    else:
        body = """- This Manager role may route requester context but must not operate the TeamHarness project/task lifecycle.
- Do not create or plan projects, manage task rooms, delegate/check/accept/complete tasks, perform Worker ack/submit actions, or call artifact/filesync directly.
- Send only bounded requester context to the designated Leader and leave acceptance and completion to that Leader."""
    return f"{AGENTS_BEGIN}\n{heading}\n\n{identity}\n{body}\n{AGENTS_END}"


def _agents_section(text: str) -> str | None:
    begin_count = text.count(AGENTS_BEGIN)
    end_count = text.count(AGENTS_END)
    if begin_count == 0 and end_count == 0:
        return None
    if begin_count != 1 or end_count != 1:
        raise ValueError("AGENTS.md contains duplicate or unbalanced DevFlow markers")
    begin = text.index(AGENTS_BEGIN)
    end = text.index(AGENTS_END, begin) + len(AGENTS_END)
    return text[begin:end]


def _configure_agents(workspace: Path, role: str, *, replace: bool) -> Path:
    path = workspace / "AGENTS.md"
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    existing = _agents_section(current)
    desired = _collaboration_block(role)
    if existing is not None:
        if not replace:
            raise ValueError("DevFlow TeamHarness AGENTS section exists; pass --replace")
        updated = current.replace(existing, desired, 1)
    else:
        separator = (
            ""
            if not current or current.endswith("\n\n")
            else ("\n" if current.endswith("\n") else "\n\n")
        )
        updated = f"{current}{separator}{desired}\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if updated != current:
        path.write_text(updated, encoding="utf-8")
    return path


def install(
    plugin_dir: Path,
    workspace: Path,
    role: str,
    runtime_config: Path,
    *,
    runtime_binding: Path | None = None,
    approval_public_key: Path | None = None,
    approval_domain: str | None = None,
    github_receipt_public_key: Path | None = None,
    test_receipt_public_key: Path | None = None,
    test_receipt_policy: Path | None = None,
    shared_dir: Path | None = None,
    replace: bool = False,
    _test_hash_policy: Mapping[str, str] | None = None,
    _test_hostname: str | None = None,
    _test_policy_path: Path | None = None,
    _test_ledger_path: Path | None = None,
    _test_openssl_path: Path | None = None,
    _test_runtime_binding_path: Path | None = None,
    _test_github_receipt_public_key_path: Path | None = None,
    _test_github_receipt_policy_path: Path | None = None,
    _test_github_receipt_openssl_path: Path | None = None,
    _test_test_receipt_public_key_path: Path | None = None,
    _test_test_receipt_policy_path: Path | None = None,
    _test_test_receipt_ledger_path: Path | None = None,
    _test_test_receipt_openssl_path: Path | None = None,
) -> dict[str, Any]:
    """Install an OpenClaw overlay without copying any credentials."""
    if role not in ROLES:
        raise ValueError(f"unsupported role: {role}")
    if not runtime_config.is_file():
        raise ValueError(f"runtime config does not exist: {runtime_config}")
    source_hashes = _validate_source_integrity(plugin_dir, _test_hash_policy)
    production_install = _test_hash_policy is None
    if _test_hostname is not None and _test_hash_policy is None:
        raise ValueError("test hostname fixtures require a test-only source policy")
    if runtime_binding is None:
        raise ValueError("installation requires --runtime-binding")
    if _test_runtime_binding_path is not None and _test_hash_policy is None:
        raise ValueError("test runtime binding paths require a test-only source policy")
    test_policy_values = (
        _test_policy_path,
        _test_ledger_path,
        _test_openssl_path,
    )
    if any(value is not None for value in test_policy_values) and (
        _test_hash_policy is None or not all(value is not None for value in test_policy_values)
    ):
        raise ValueError("test approval paths require one complete test-only fixture")
    test_receipt_values = (
        _test_github_receipt_public_key_path,
        _test_github_receipt_policy_path,
        _test_github_receipt_openssl_path,
    )
    if any(value is not None for value in test_receipt_values) and (
        _test_hash_policy is None or not all(value is not None for value in test_receipt_values)
    ):
        raise ValueError("test receipt paths require one complete test-only fixture")
    test_execution_receipt_values = (
        _test_test_receipt_public_key_path,
        _test_test_receipt_policy_path,
        _test_test_receipt_ledger_path,
        _test_test_receipt_openssl_path,
    )
    if any(value is not None for value in test_execution_receipt_values) and (
        _test_hash_policy is None
        or not all(value is not None for value in test_execution_receipt_values)
    ):
        raise ValueError(
            "test execution receipt paths require one complete test-only fixture"
        )
    if (test_receipt_public_key is None) != (test_receipt_policy is None):
        raise ValueError("test execution receipt trust requires both public files")
    if production_install and test_receipt_public_key is None:
        raise ValueError(
            "production installation requires --test-receipt-public-key and policy"
        )
    hostname = (
        _test_hostname.strip()
        if _test_hostname is not None
        else Path("/etc/hostname").read_text(encoding="utf-8").strip()
    )
    if not hostname:
        raise ValueError("container hostname is empty")
    execution_evidence: dict[str, Any] = {}
    if production_install:
        _make_directory_writable(PRODUCTION_RUNTIME_BINDING.parent)
        _make_directory_writable(PRODUCTION_APPROVAL_LEDGER.parent, 0o700)
        execution_evidence = _install_production_execution(plugin_dir)
    source_binding = _load_runtime_binding(runtime_binding)
    runtime_binding_path = _test_runtime_binding_path or PRODUCTION_RUNTIME_BINDING
    runtime_binding_path.parent.mkdir(parents=True, exist_ok=True)
    if runtime_binding.resolve() != runtime_binding_path.resolve():
        if runtime_binding_path.exists():
            runtime_binding_path.chmod(0o644)
        shutil.copy2(runtime_binding, runtime_binding_path)
    runtime_binding_path.chmod(0o444)
    if production_install and hasattr(os, "chown"):
        os.chown(runtime_binding_path, 0, 0)
    installed_binding = _load_runtime_binding(runtime_binding_path)
    if installed_binding != source_binding:
        raise ValueError("installed runtime binding differs from its source")
    runtime_identity = _validate_runtime_config(runtime_config, role, hostname, installed_binding)
    approval_policy: dict[str, Any] | None = None
    if role == "leader":
        if approval_public_key is None:
            raise ValueError("Leader installation requires --approval-public-key")
        if approval_domain is None:
            raise ValueError("Leader installation requires --approval-domain")
        policy_path = _test_policy_path or PRODUCTION_APPROVAL_PUBLIC_KEY
        ledger_path = _test_ledger_path or PRODUCTION_APPROVAL_LEDGER
        openssl_path = _test_openssl_path or PRODUCTION_OPENSSL
        approval_policy = _install_approval_policy(
            approval_public_key,
            approval_domain,
            policy_path,
            ledger_path,
            openssl_path,
            str(execution_evidence.get("guardSha256") or _sha256(GUARD)),
            str(execution_evidence.get("adapterSha256") or _sha256(Path(__file__).resolve())),
            str(execution_evidence.get("serverSha256") or source_hashes["mcp/server.py"]),
        )
    elif approval_public_key is not None or approval_domain is not None:
        raise ValueError("approval policy inputs are installed only for the Leader")
    github_receipt_policy: dict[str, Any] | None = None
    is_locator = runtime_identity.get("runtimeName") == GITHUB_RECEIPT_CONSUMER
    if is_locator:
        if github_receipt_public_key is None:
            raise ValueError(
                "Locator installation requires --github-receipt-public-key"
            )
        github_receipt_public_key_path = (
            _test_github_receipt_public_key_path
            or PRODUCTION_GITHUB_RECEIPT_PUBLIC_KEY
        )
        github_receipt_policy_path = (
            _test_github_receipt_policy_path or PRODUCTION_GITHUB_RECEIPT_POLICY
        )
        github_receipt_openssl_path = (
            _test_github_receipt_openssl_path or PRODUCTION_OPENSSL
        )
        github_receipt_policy = _install_github_receipt_policy(
            github_receipt_public_key,
            github_receipt_public_key_path,
            github_receipt_policy_path,
            github_receipt_openssl_path,
        )
    elif github_receipt_public_key is not None:
        raise ValueError("receipt trust input is installed only for Locator")
    test_execution_receipt_policy: dict[str, Any] | None = None
    if test_receipt_public_key is not None and test_receipt_policy is not None:
        test_execution_receipt_policy = _install_test_receipt_policy(
            test_receipt_public_key,
            test_receipt_policy,
            _test_test_receipt_public_key_path
            or PRODUCTION_TEST_RECEIPT_PUBLIC_KEY,
            _test_test_receipt_policy_path or PRODUCTION_TEST_RECEIPT_POLICY,
            _test_test_receipt_ledger_path or PRODUCTION_TEST_RECEIPT_LEDGER,
            _test_test_receipt_openssl_path or PRODUCTION_OPENSSL,
        )
    manifest = _manifest(plugin_dir)
    shared_dir = shared_dir or _default_shared_dir(workspace)
    shared_dir.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(parents=True, exist_ok=True)
    runtime_identity_path = workspace / "runtime" / "runtime.json"
    runtime_identity_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_identity_path.write_text(
        json.dumps(runtime_identity, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    installed = _copy_role_assets(plugin_dir, workspace, role, manifest)
    installed.append(runtime_identity_path)
    mcp_target = workspace / ".teamharness" / "mcp"
    if any(
        _sha256(mcp_target / name) != source_hashes[f"mcp/{name}"] for name in REQUIRED_MCP_FILES
    ):
        raise ValueError("installed TeamHarness MCP source failed integrity recheck")
    installed.append(_configure_agents(workspace, role, replace=replace))
    installed.append(
        _configure_mcporter(
            workspace,
            shared_dir,
            PRODUCTION_PYTHON if production_install else Path("python3"),
            (
                PRODUCTION_GUARD
                if production_install
                else (workspace / ".teamharness" / "mcp" / GUARD.name).resolve()
            ),
            replace=replace,
        )
    )
    record = {
        "schemaVersion": "1.0",
        "pluginVersion": str(manifest.get("metadata", {}).get("version") or ""),
        "upstreamCommit": UPSTREAM_AGENTTEAMS_COMMIT,
        "sourcePolicy": "test-only" if _test_hash_policy is not None else "production-pinned",
        "sourceFiles": source_hashes,
        "role": role,
        "workspacePath": str(workspace.resolve()),
        "runtimeIdentity": runtime_identity,
        "runtimeBinding": installed_binding,
        "runtimeBindingPath": str(runtime_binding_path),
        "runtimeBindingSha256": _sha256(runtime_binding_path),
        **execution_evidence,
        "files": {
            path.resolve().relative_to(workspace.resolve()).as_posix(): _sha256(path)
            for path in sorted(set(installed))
        },
        "secretsEmbedded": False,
    }
    if approval_policy is not None:
        record["approvalPolicy"] = approval_policy
        record.update(
            {
                "approvalPolicyPath": str(PRODUCTION_APPROVAL_POLICY)
                if production_install
                else str(Path(str(approval_policy["policyAttestationPath"]))),
                "approvalPolicySha256": _sha256(
                    Path(str(approval_policy["policyAttestationPath"]))
                ),
                "approvalPublicKeyPath": str(approval_policy["publicKeyPath"]),
                "approvalPublicKeySha256": str(approval_policy["publicKeySha256"]),
            }
        )
    if github_receipt_policy is not None:
        record["githubReceiptPolicy"] = github_receipt_policy
        record.update(
            {
                "githubReceiptPolicyPath": str(
                    github_receipt_policy["policyPath"]
                ),
                "githubReceiptPolicySha256": _sha256(
                    Path(str(github_receipt_policy["policyPath"]))
                ),
                "githubReceiptPublicKeyPath": str(
                    github_receipt_policy["publicKeyPath"]
                ),
                "githubReceiptPublicKeySha256": str(
                    github_receipt_policy["publicKeyFileSha256"]
                ),
                "githubReceiptKeyIdSha256": str(
                    github_receipt_policy["publicKeySha256"]
                ),
            }
        )
    if test_execution_receipt_policy is not None:
        record["testExecutionReceiptPolicy"] = test_execution_receipt_policy
        record.update(
            {
                "testExecutionReceiptPolicyPath": str(
                    test_execution_receipt_policy["policyAttestationPath"]
                ),
                "testExecutionReceiptPolicySha256": _sha256(
                    Path(
                        str(
                            test_execution_receipt_policy[
                                "policyAttestationPath"
                            ]
                        )
                    )
                ),
                "testExecutionReceiptPublicKeyPath": str(
                    test_execution_receipt_policy["publicKeyPath"]
                ),
                "testExecutionReceiptPublicKeyFileSha256": str(
                    test_execution_receipt_policy["publicKeyFileSha256"]
                ),
                "testExecutionReceiptReplayScope": TEST_RECEIPT_REPLAY_SCOPE,
                "testExecutionReceiptReplayLedgerPersistentAcrossPodReplacement": (
                    TEST_RECEIPT_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
                ),
                "testExecutionReceiptLifetimeSeconds": (
                    TEST_RECEIPT_LIFETIME_SECONDS
                ),
                "testExecutionReceiptLedgerSchema": TEST_RECEIPT_LEDGER_SCHEMA,
                "testExecutionReceiptConsumptionProtocol": (
                    TEST_RECEIPT_CONSUMPTION_PROTOCOL
                ),
                "testExecutionReceiptReservationLeaseSeconds": (
                    TEST_RECEIPT_RESERVATION_LEASE_SECONDS
                ),
                "testExecutionReceiptAuthoritativeReadback": (
                    TEST_RECEIPT_AUTHORITATIVE_READBACK
                ),
            }
        )
    if _test_hostname is not None:
        record["testHostnameFixture"] = hostname
        record["testRuntimeBindingFixture"] = True
    record_path = workspace / ".teamharness" / "install-manifest.json"
    record_path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if production_install:
        if PRODUCTION_INSTALL_MANIFEST.exists():
            PRODUCTION_INSTALL_MANIFEST.chmod(0o644)
        PRODUCTION_INSTALL_MANIFEST.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        PRODUCTION_INSTALL_MANIFEST.chmod(0o444)
        if hasattr(os, "chown"):
            os.chown(PRODUCTION_INSTALL_MANIFEST, 0, 0)
        for directory in (
            PRODUCTION_RUNTIME_BINDING.parent,
            *(
                (PRODUCTION_GITHUB_RECEIPT_PUBLIC_KEY.parent,)
                if is_locator
                else ()
            ),
            PRODUCTION_RUNTIME_BINDING.parent.parent,
        ):
            directory.chmod(0o555)
    return record


def _verify_manifest(
    workspace: Path,
    role: str,
    test_hash_policy: Mapping[str, str] | None,
) -> list[Check]:
    checks: list[Check] = []
    path = (
        PRODUCTION_INSTALL_MANIFEST
        if test_hash_policy is None
        else workspace / ".teamharness" / "install-manifest.json"
    )
    if not path.is_file():
        return [Check("install-manifest", False, f"missing {path}")]
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return [Check("install-manifest", False, f"invalid manifest: {exc}")]
    if not isinstance(record, dict):
        return [Check("install-manifest", False, "manifest must be an object")]

    expected_policy = _source_hash_policy(test_hash_policy)
    expected_source_policy = "test-only" if test_hash_policy is not None else "production-pinned"
    runtime_identity = record.get("runtimeIdentity")
    runtime_binding = record.get("runtimeBinding")
    identity_fields_ok = (
        isinstance(runtime_identity, dict)
        and isinstance(runtime_binding, dict)
        and runtime_identity.get("role") == role
        and isinstance(runtime_identity.get("runtimeName"), str)
        and isinstance(runtime_identity.get("matrixUserId"), str)
        and runtime_identity.get("runtimeName") == runtime_binding.get("runtimeName")
        and runtime_identity.get("hostname") == runtime_binding.get("podName")
        and runtime_identity.get("teamName") == runtime_binding.get("teamName")
        and runtime_identity.get("memberName") == runtime_binding.get("memberName")
        and runtime_binding.get("teamHarnessRole") == role
        and re.fullmatch(
            rf"@{re.escape(str(runtime_identity.get('runtimeName') or ''))}:[^:]+",
            str(runtime_identity.get("matrixUserId") or ""),
        )
        is not None
    )
    fixture_policy_ok = (
        (
            expected_source_policy == "test-only"
            and record.get("testHostnameFixture") == runtime_identity.get("hostname")
            and record.get("testRuntimeBindingFixture") is True
        )
        if isinstance(runtime_identity, dict) and "testHostnameFixture" in record
        else "testHostnameFixture" not in record and "testRuntimeBindingFixture" not in record
    )
    runtime_binding_path = Path(str(record.get("runtimeBindingPath") or ""))
    runtime_binding_ok = False
    try:
        runtime_binding_ok = (
            runtime_binding_path.is_file()
            and _load_runtime_binding(runtime_binding_path) == runtime_binding
            and record.get("runtimeBindingSha256") == _sha256(runtime_binding_path)
            and (
                expected_source_policy == "test-only"
                or runtime_binding_path == PRODUCTION_RUNTIME_BINDING
            )
        )
    except (json.JSONDecodeError, OSError, UnicodeError, ValueError):
        runtime_binding_ok = False
    external_execution_ok = True
    if expected_source_policy == "production-pinned":
        try:
            external_execution_ok = all(
                (
                    record.get("guardPath") == str(PRODUCTION_GUARD),
                    record.get("guardSha256") == _sha256(PRODUCTION_GUARD),
                    record.get("adapterPath") == str(PRODUCTION_ADAPTER),
                    record.get("adapterSha256") == _sha256(PRODUCTION_ADAPTER),
                    record.get("serverPath") == str(PRODUCTION_SERVER),
                    record.get("serverSha256") == _sha256(PRODUCTION_SERVER),
                )
            )
        except OSError:
            external_execution_ok = False
    identity_ok = (
        record.get("schemaVersion") == "1.0"
        and record.get("pluginVersion") == TEAMHARNESS_VERSION
        and record.get("upstreamCommit") == UPSTREAM_AGENTTEAMS_COMMIT
        and record.get("sourcePolicy") == expected_source_policy
        and record.get("sourceFiles") == expected_policy
        and record.get("role") == role
        and identity_fields_ok
        and fixture_policy_ok
        and runtime_binding_ok
        and external_execution_ok
        and record.get("secretsEmbedded") is False
    )
    checks.append(
        Check(
            "install-manifest",
            identity_ok,
            "pinned source and role match" if identity_ok else "identity or source policy mismatch",
        )
    )

    files = record.get("files")
    if not isinstance(files, dict):
        checks.append(Check("manifest-hashes", False, "files must be an object"))
        return checks
    required = {
        "AGENTS.md",
        "config/mcporter.json",
        "runtime/runtime.json",
        f".teamharness/mcp/{GUARD.name}",
        *(f".teamharness/mcp/{name}" for name in REQUIRED_MCP_FILES),
    }
    coverage_ok = required <= set(files)
    hashes_ok = True
    workspace_root = workspace.resolve()
    for relative, expected_hash in files.items():
        if not isinstance(relative, str) or not isinstance(expected_hash, str):
            hashes_ok = False
            continue
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            hashes_ok = False
            continue
        installed_path = workspace.joinpath(*pure.parts)
        try:
            installed_path.resolve().relative_to(workspace_root)
        except ValueError:
            hashes_ok = False
            continue
        if (
            not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
            or not installed_path.is_file()
            or _sha256(installed_path) != expected_hash
        ):
            hashes_ok = False
    checks.append(
        Check(
            "manifest-hashes",
            coverage_ok and hashes_ok,
            "required files covered and exact"
            if coverage_ok and hashes_ok
            else "coverage is missing or a recorded file changed",
        )
    )
    return checks


def _verify_approval_policy(
    workspace: Path,
    role: str,
    test_hash_policy: Mapping[str, str] | None,
) -> Check:
    manifest_path = (
        PRODUCTION_INSTALL_MANIFEST
        if test_hash_policy is None
        else workspace / ".teamharness" / "install-manifest.json"
    )
    try:
        record = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            raise ValueError("install manifest must contain an object")
        policy = record.get("approvalPolicy")
        if role != "leader":
            if policy is not None:
                raise ValueError("non-Leader manifest contains an approval policy")
            return Check("approval-policy", True, "not applicable to this role")
        if not isinstance(policy, dict):
            raise ValueError("Leader approval policy is missing")
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
        if set(policy) != required:
            raise ValueError("Leader approval policy schema mismatch")
        production_policy = record.get("sourcePolicy") == "production-pinned"
        expected_guard = (
            PRODUCTION_GUARD
            if production_policy
            else workspace / ".teamharness/mcp/guarded_server.py"
        )
        expected_server = (
            PRODUCTION_SERVER if production_policy else workspace / ".teamharness/mcp/server.py"
        )
        if (
            policy.get("schemaVersion") != "1.1"
            or policy.get("algorithm") != "Ed25519"
            or policy.get("audience") != APPROVAL_AUDIENCE
            or not isinstance(policy.get("approvalDomain"), str)
            or APPROVAL_DOMAIN_RE.fullmatch(str(policy.get("approvalDomain"))) is None
            or policy.get("maxApprovalLifetimeSeconds") != 900
            or policy.get("guardSha256") != _sha256(expected_guard)
            or not isinstance(policy.get("adapterSha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(policy.get("adapterSha256")))
            or policy.get("serverSha256") != _sha256(expected_server)
        ):
            raise ValueError("Leader approval policy constants mismatch")
        expected_adapter = PRODUCTION_ADAPTER if production_policy else Path(__file__).resolve()
        if policy.get("adapterSha256") != _sha256(expected_adapter):
            raise ValueError("Leader approval policy adapter hash mismatch")
        if production_policy and (
            policy.get("publicKeyPath") != str(PRODUCTION_APPROVAL_PUBLIC_KEY)
            or policy.get("policyAttestationPath") != str(PRODUCTION_APPROVAL_POLICY)
            or policy.get("ledgerPath") != str(PRODUCTION_APPROVAL_LEDGER)
            or policy.get("opensslPath") != str(PRODUCTION_OPENSSL)
        ):
            raise ValueError("production approval policy paths are not fixed")
        public_key = Path(str(policy.get("publicKeyPath") or ""))
        policy_attestation = Path(str(policy.get("policyAttestationPath") or ""))
        ledger = Path(str(policy.get("ledgerPath") or ""))
        openssl_path = Path(str(policy.get("opensslPath") or ""))
        expected_hash = policy.get("publicKeySha256")
        if (
            not isinstance(expected_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
            or policy.get("policyKeySha256") != expected_hash
            or not public_key.is_file()
            or _sha256(public_key) != expected_hash
        ):
            raise ValueError("approval public key hash mismatch")
        _validate_ed25519_public_key(public_key, openssl_path)
        attested_policy = json.loads(policy_attestation.read_text(encoding="utf-8"))
        if attested_policy != policy:
            raise ValueError("external policy attestation and manifest disagree")
        _validate_approval_ledger(ledger)
    except (
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
        ValueError,
    ) as exc:
        return Check("approval-policy", False, str(exc))
    return Check("approval-policy", True, "Ed25519 policy and ledger verified")


def _verify_github_receipt_policy(
    workspace: Path,
    test_hash_policy: Mapping[str, str] | None,
) -> Check:
    manifest_path = (
        PRODUCTION_INSTALL_MANIFEST
        if test_hash_policy is None
        else workspace / ".teamharness" / "install-manifest.json"
    )
    try:
        record = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            raise ValueError("install manifest must contain an object")
        runtime_identity = record.get("runtimeIdentity")
        is_locator = (
            isinstance(runtime_identity, dict)
            and runtime_identity.get("runtimeName") == GITHUB_RECEIPT_CONSUMER
        )
        policy = record.get("githubReceiptPolicy")
        if not is_locator:
            if policy is not None:
                raise ValueError("non-Locator manifest contains receipt trust")
            return Check("github-receipt-policy", True, "not applicable to this role")
        if not isinstance(policy, dict) or set(policy) != {
            "schemaVersion",
            "algorithm",
            "audience",
            "signatureDomain",
            "consumerRuntimeName",
            "publicKeyPath",
            "publicKeySha256",
            "publicKeyFileSha256",
            "policyPath",
            "opensslPath",
        }:
            raise ValueError("Locator receipt policy schema mismatch")
        production_policy = record.get("sourcePolicy") == "production-pinned"
        if (
            policy.get("schemaVersion") != "1.0"
            or policy.get("algorithm") != "Ed25519"
            or policy.get("audience") != GITHUB_RECEIPT_AUDIENCE
            or policy.get("signatureDomain") != GITHUB_RECEIPT_SIGNATURE_DOMAIN
            or policy.get("consumerRuntimeName") != GITHUB_RECEIPT_CONSUMER
            or production_policy
            and (
                policy.get("publicKeyPath")
                != str(PRODUCTION_GITHUB_RECEIPT_PUBLIC_KEY)
                or policy.get("policyPath")
                != str(PRODUCTION_GITHUB_RECEIPT_POLICY)
                or policy.get("opensslPath") != str(PRODUCTION_OPENSSL)
            )
        ):
            raise ValueError("Locator receipt policy constants mismatch")
        public_key = Path(str(policy.get("publicKeyPath") or ""))
        policy_path = Path(str(policy.get("policyPath") or ""))
        openssl_path = Path(str(policy.get("opensslPath") or ""))
        if (
            not public_key.is_file()
            or policy.get("publicKeyFileSha256") != _sha256(public_key)
            or policy.get("publicKeySha256")
            != _ed25519_public_key_digest(public_key, openssl_path)
            or record.get("githubReceiptPolicyPath") != str(policy_path)
            or record.get("githubReceiptPolicySha256") != _sha256(policy_path)
            or record.get("githubReceiptPublicKeyPath") != str(public_key)
            or record.get("githubReceiptPublicKeySha256")
            != policy.get("publicKeyFileSha256")
            or record.get("githubReceiptKeyIdSha256")
            != policy.get("publicKeySha256")
        ):
            raise ValueError("Locator receipt public-key binding mismatch")
        attested = json.loads(policy_path.read_text(encoding="utf-8"))
        if attested != policy:
            raise ValueError("external receipt policy and manifest disagree")
    except (
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
        ValueError,
    ) as exc:
        return Check("github-receipt-policy", False, str(exc))
    return Check(
        "github-receipt-policy",
        True,
        "fixed Ed25519 receipt trust verified",
    )


def _verify_test_execution_receipt_policy(
    workspace: Path,
    test_hash_policy: Mapping[str, str] | None,
) -> Check:
    manifest_path = (
        PRODUCTION_INSTALL_MANIFEST
        if test_hash_policy is None
        else workspace / ".teamharness" / "install-manifest.json"
    )
    try:
        record = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            raise ValueError("install manifest must contain an object")
        policy = record.get("testExecutionReceiptPolicy")
        if policy is None and record.get("sourcePolicy") == "test-only":
            return Check(
                "test-execution-receipt-policy",
                True,
                "not configured in this legacy test-only fixture",
            )
        if not isinstance(policy, dict) or set(policy) != TEST_RECEIPT_POLICY_FIELDS:
            raise ValueError("test execution receipt policy is missing")
        public_key = Path(str(policy.get("publicKeyPath") or ""))
        policy_path = Path(str(policy.get("policyAttestationPath") or ""))
        ledger_path = Path(str(policy.get("replayLedgerPath") or ""))
        openssl_path = Path(str(policy.get("opensslPath") or ""))
        if record.get("sourcePolicy") == "production-pinned" and (
            public_key != PRODUCTION_TEST_RECEIPT_PUBLIC_KEY
            or policy_path != PRODUCTION_TEST_RECEIPT_POLICY
            or ledger_path != PRODUCTION_TEST_RECEIPT_LEDGER
            or openssl_path != PRODUCTION_OPENSSL
        ):
            raise ValueError("production test receipt paths are not fixed")
        if (
            record.get("testExecutionReceiptPolicyPath") != str(policy_path)
            or record.get("testExecutionReceiptPolicySha256")
            != _sha256(policy_path)
            or record.get("testExecutionReceiptPublicKeyPath")
            != str(public_key)
            or record.get("testExecutionReceiptPublicKeyFileSha256")
            != policy.get("publicKeyFileSha256")
            or record.get("testExecutionReceiptReplayScope")
            != TEST_RECEIPT_REPLAY_SCOPE
            or record.get(
                "testExecutionReceiptReplayLedgerPersistentAcrossPodReplacement"
            )
            is not TEST_RECEIPT_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
            or record.get("testExecutionReceiptLifetimeSeconds")
            != TEST_RECEIPT_LIFETIME_SECONDS
            or record.get("testExecutionReceiptLedgerSchema")
            != TEST_RECEIPT_LEDGER_SCHEMA
            or record.get("testExecutionReceiptConsumptionProtocol")
            != TEST_RECEIPT_CONSUMPTION_PROTOCOL
            or record.get("testExecutionReceiptReservationLeaseSeconds")
            != TEST_RECEIPT_RESERVATION_LEASE_SECONDS
            or record.get("testExecutionReceiptAuthoritativeReadback")
            != TEST_RECEIPT_AUTHORITATIVE_READBACK
            or policy.get("schemaVersion") != "1.0"
            or policy.get("algorithm") != "Ed25519"
            or policy.get("audience") != TEST_RECEIPT_AUDIENCE
            or policy.get("issuer") != TEST_RECEIPT_ISSUER
            or policy.get("signatureDomain") != TEST_RECEIPT_SCHEMA
            or policy.get("maxReceiptLifetimeSeconds")
            != TEST_RECEIPT_LIFETIME_SECONDS
            or policy.get("replayScope") != TEST_RECEIPT_REPLAY_SCOPE
            or policy.get("replayLedgerPersistentAcrossPodReplacement")
            is not TEST_RECEIPT_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
            or policy.get("receiptLifetimeSeconds")
            != TEST_RECEIPT_LIFETIME_SECONDS
            or not isinstance(policy.get("remainingThreat"), str)
            or "pod replacement" not in policy["remainingThreat"].lower()
            or "120" not in policy["remainingThreat"]
            or policy.get("publicKeyFileSha256") != _sha256(public_key)
            or policy.get("publicKeySha256")
            != _ed25519_public_key_digest(public_key, openssl_path)
            or json.loads(policy_path.read_text(encoding="utf-8")) != policy
        ):
            raise ValueError("test receipt manifest or public-key digest mismatch")
        _validate_test_receipt_ledger(ledger_path)
        if record.get("sourcePolicy") == "production-pinned":
            key_metadata = public_key.stat()
            policy_metadata = policy_path.stat()
            ledger_metadata = ledger_path.stat()
            if (
                key_metadata.st_uid != 0
                or key_metadata.st_gid != 0
                or stat.S_IMODE(key_metadata.st_mode) & 0o022
                or policy_metadata.st_uid != 0
                or policy_metadata.st_gid != 0
                or stat.S_IMODE(policy_metadata.st_mode) & 0o022
                or ledger_metadata.st_uid != 0
                or ledger_metadata.st_gid != 0
                or stat.S_IMODE(ledger_metadata.st_mode) != 0o600
            ):
                raise ValueError("test receipt file ownership or mode is invalid")
    except (
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
        ValueError,
    ) as exc:
        return Check("test-execution-receipt-policy", False, str(exc))
    return Check(
        "test-execution-receipt-policy",
        True,
        "public verifier policy and 0600 replay ledger verified",
    )


def verify(
    workspace: Path,
    role: str,
    *,
    _test_hash_policy: Mapping[str, str] | None = None,
) -> list[Check]:
    """Verify installation structure and credential-free mcporter wiring."""
    if role not in ROLES:
        raise ValueError(f"unsupported role: {role}")
    checks = _verify_manifest(workspace, role, _test_hash_policy)
    checks.append(_verify_approval_policy(workspace, role, _test_hash_policy))
    checks.append(_verify_github_receipt_policy(workspace, _test_hash_policy))
    checks.append(
        _verify_test_execution_receipt_policy(workspace, _test_hash_policy)
    )
    agents_path = workspace / "AGENTS.md"
    agents_error = ""
    try:
        agents_text = agents_path.read_text(encoding="utf-8")
        section = _agents_section(agents_text)
    except (OSError, UnicodeError, ValueError) as exc:
        agents_error = str(exc)
        section = None
    expected_section = _collaboration_block(role)
    checks.append(
        Check(
            "agents-section",
            section == expected_section,
            "exact DevFlow contract exists"
            if section == expected_section
            else agents_error or "missing or drifted DevFlow contract",
        )
    )
    role_marker = f"- Installed TeamHarness role: `{role}`."
    checks.append(
        Check(
            "agents-role",
            section is not None and role_marker in section,
            role if section is not None and role_marker in section else "role mismatch",
        )
    )
    mcp_dir = workspace / ".teamharness" / "mcp"
    source_policy = _source_hash_policy(_test_hash_policy)
    source_targets_ok = all(
        (mcp_dir / name).is_file() and _sha256(mcp_dir / name) == source_policy[f"mcp/{name}"]
        for name in REQUIRED_MCP_FILES
    )
    checks.append(
        Check(
            "pinned-mcp-sources",
            source_targets_ok,
            "installed MCP files match source policy"
            if source_targets_ok
            else "installed MCP source mismatch",
        )
    )
    for name in (*REQUIRED_MCP_FILES, GUARD.name):
        path = mcp_dir / name
        checks.append(Check(f"mcp:{name}", path.is_file(), str(path)))
        if path.is_file() and path.suffix == ".py":
            try:
                compile(path.read_text(encoding="utf-8"), str(path), "exec")
            except SyntaxError as exc:
                checks.append(Check(f"compile:{name}", False, str(exc)))
            else:
                checks.append(Check(f"compile:{name}", True, "valid Python"))

    config_path = workspace / "config" / "mcporter.json"
    if not config_path.is_file():
        checks.append(Check("mcporter", False, f"missing {config_path}"))
        return checks
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        entry = config["mcpServers"]["teamharness"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        checks.append(Check("mcporter", False, f"invalid TeamHarness entry: {exc}"))
        return checks
    if not isinstance(entry, dict):
        checks.append(Check("mcporter", False, "TeamHarness entry must be an object"))
        return checks
    checks.append(Check("mcporter", True, "teamharness entry exists"))
    expected_command = str(PRODUCTION_PYTHON) if _test_hash_policy is None else "python3"
    checks.append(
        Check(
            "command",
            entry.get("command") == expected_command,
            str(entry.get("command")),
        )
    )
    checks.append(
        Check("transport", entry.get("transport") == "stdio", str(entry.get("transport")))
    )
    args = entry.get("args")
    guard_path = Path(str(args[0])) if isinstance(args, list) and args else Path()
    expected_guard = PRODUCTION_GUARD if _test_hash_policy is None else mcp_dir / GUARD.name
    checks.append(Check("guard-entrypoint", guard_path == expected_guard, str(guard_path)))
    env = entry.get("env")
    env = env if isinstance(env, dict) else {}
    embedded = sorted(
        key for key in env if any(part in key.upper() for part in SENSITIVE_ENV_PARTS)
    )
    checks.append(
        Check(
            "credential-free",
            not embedded,
            "no sensitive env names" if not embedded else f"embedded keys: {embedded}",
        )
    )
    checks.append(
        Check(
            "identity-env-free",
            "AGENTTEAMS_AGENT_ROLE" not in env
            and "AGENTTEAMS_WORKER_ROLE" not in env
            and "TEAMHARNESS_RUNTIME_CONFIG" not in env,
            "identity is not supplied by environment",
        )
    )
    shared_path = Path(str(env.get("TEAMHARNESS_SHARED_DIR") or ""))
    checks.append(Check("shared-dir", shared_path.is_dir(), str(shared_path)))
    runtime_path = workspace / "runtime" / "runtime.json"
    try:
        if not runtime_path.is_file():
            raise ValueError("runtime identity is missing")
        runtime_identity = json.loads(runtime_path.read_text(encoding="utf-8"))
        manifest_path = (
            PRODUCTION_INSTALL_MANIFEST
            if _test_hash_policy is None
            else workspace / ".teamharness" / "install-manifest.json"
        )
        manifest_record = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(runtime_identity, dict) or not isinstance(manifest_record, dict):
            raise ValueError("identity evidence must contain objects")
        if runtime_identity != manifest_record.get("runtimeIdentity"):
            raise ValueError("runtime identity and install manifest disagree")
        binding_path = Path(str(manifest_record.get("runtimeBindingPath") or ""))
        binding = _load_runtime_binding(binding_path)
        if (
            binding != manifest_record.get("runtimeBinding")
            or manifest_record.get("runtimeBindingSha256") != _sha256(binding_path)
            or runtime_identity.get("runtimeName") != binding.get("runtimeName")
            or runtime_identity.get("hostname") != binding.get("podName")
        ):
            raise ValueError("external runtime binding disagrees")
        expected_hostname = (
            manifest_record.get("testHostnameFixture")
            if manifest_record.get("sourcePolicy") == "test-only"
            else Path("/etc/hostname").read_text(encoding="utf-8").strip()
        )
        if runtime_identity.get("hostname") != expected_hostname:
            raise ValueError("runtime identity hostname mismatch")
    except (OSError, UnicodeError, ValueError) as exc:
        checks.append(Check("runtime-identity", False, str(exc)))
    else:
        checks.append(Check("runtime-identity", True, "fixed-path evidence agrees"))
    return checks


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--plugin-dir", type=Path, required=True)
    install_parser.add_argument("--workspace", type=Path, required=True)
    install_parser.add_argument("--role", choices=sorted(ROLES), required=True)
    install_parser.add_argument("--runtime-config", type=Path, required=True)
    install_parser.add_argument("--runtime-binding", type=Path, required=True)
    install_parser.add_argument("--approval-public-key", type=Path)
    install_parser.add_argument("--approval-domain")
    install_parser.add_argument("--github-receipt-public-key", type=Path)
    install_parser.add_argument("--test-receipt-public-key", type=Path)
    install_parser.add_argument("--test-receipt-policy", type=Path)
    install_parser.add_argument("--shared-dir", type=Path)
    install_parser.add_argument("--replace", action="store_true")
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--workspace", type=Path, required=True)
    verify_parser.add_argument("--role", choices=sorted(ROLES), required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "install":
        result = install(
            args.plugin_dir.resolve(),
            args.workspace.resolve(),
            args.role,
            args.runtime_config.resolve(),
            runtime_binding=args.runtime_binding.resolve(),
            approval_public_key=(
                args.approval_public_key.resolve() if args.approval_public_key else None
            ),
            approval_domain=args.approval_domain,
            github_receipt_public_key=(
                args.github_receipt_public_key.resolve()
                if args.github_receipt_public_key
                else None
            ),
            test_receipt_public_key=(
                args.test_receipt_public_key.resolve()
                if args.test_receipt_public_key
                else None
            ),
            test_receipt_policy=(
                args.test_receipt_policy.resolve()
                if args.test_receipt_policy
                else None
            ),
            shared_dir=args.shared_dir.resolve() if args.shared_dir else None,
            replace=args.replace,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    checks = verify(args.workspace.resolve(), args.role)
    print(json.dumps([asdict(check) for check in checks], indent=2, sort_keys=True))
    return 0 if all(check.ok for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
