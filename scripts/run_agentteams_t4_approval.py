#!/usr/bin/env python3
"""Prepare and verify one externally approved AgentTeams T4 resume.

The prepare phase creates a fresh T4 project, pauses it, proves that an
unsigned resume is denied, and prints only a digest-bound approval request.
The resume phase accepts an approval produced outside the cluster, verifies
its exact scope locally, resumes once, proves replay denial, and prints a
sanitized evidence summary.  This module never creates or reads a private key.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import re
import stat
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

try:
    from scripts.reconcile_teamharness_openclaw import (
        TEAM_NAME,
        ReconcileError,
        discover_targets,
    )
    from scripts.run_agentteams_github_success_path import (
        EXPECTED_MCP_SCHEMA_CANONICAL_BYTES,
        EXPECTED_MCP_SCHEMA_CANONICAL_SHA256,
        EXPECTED_MCPORTER_SHA256,
        EXPECTED_MCPORTER_VERSION,
        HOST_PREFLIGHT_TIMEOUT_SECONDS,
        LOCATOR_ROLE,
        MCP_SCHEMA_CANONICALIZATION_ID,
        REMOTE_PREFLIGHT_HELPER,
        TEAMHARNESS_SERVER,
        DriverError,
        KubernetesBackend,
        RuntimeContext,
        _assert_public_safe,
        _canonical_bytes,
        _canonical_text,
        _expect_absent,
        _expect_identity,
        _expect_ok,
        _normalized_mcporter_config,
        _sha256,
        _strict_loads,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from reconcile_teamharness_openclaw import (  # type: ignore[no-redef]
        TEAM_NAME,
        ReconcileError,
        discover_targets,
    )
    from run_agentteams_github_success_path import (  # type: ignore[no-redef]
        EXPECTED_MCP_SCHEMA_CANONICAL_BYTES,
        EXPECTED_MCP_SCHEMA_CANONICAL_SHA256,
        EXPECTED_MCPORTER_SHA256,
        EXPECTED_MCPORTER_VERSION,
        HOST_PREFLIGHT_TIMEOUT_SECONDS,
        LOCATOR_ROLE,
        MCP_SCHEMA_CANONICALIZATION_ID,
        REMOTE_PREFLIGHT_HELPER,
        TEAMHARNESS_SERVER,
        DriverError,
        KubernetesBackend,
        RuntimeContext,
        _assert_public_safe,
        _canonical_bytes,
        _canonical_text,
        _expect_absent,
        _expect_identity,
        _expect_ok,
        _normalized_mcporter_config,
        _sha256,
        _strict_loads,
    )


PREPARE_CONFIRMATION = "EXECUTE_FRESH_T4_APPROVAL_PREPARE"
RESUME_CONFIRMATION_PREFIX = "APPROVE_T4_RESUME:"
APPROVAL_AUDIENCE = "devflow.agentteams.projectflow.approval/v1"
APPROVAL_REQUEST_SCHEMA = "devflow.agentteams.projectflow.approval-request/v1"
PROJECT_PREFIX = "devflow-live-t4-"
RISK_TIER = "T4"
SOURCE = "operator-driven"
LEADER_ROLE = "devflow-lead"
SAFE_PROJECT = re.compile(
    r"^devflow-live-t4-[a-z0-9](?:[a-z0-9-]{0,29}[a-z0-9])?$"
)
DIGEST = re.compile(r"^[0-9a-f]{64}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
APPROVER = re.compile(r"^[A-Za-z0-9@._:/+\-]{3,128}$")
RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class ApprovalBackend(Protocol):
    def preflight(self) -> RuntimeContext: ...

    def leader_call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


class T4KubernetesBackend(KubernetesBackend):
    """Attest only the runtime surface required by the T4 Leader transition.

    T4 pause/resume is a Leader-only TeamHarness operation.  Reusing the
    GitHub success-path preflight would incorrectly make this approval path
    depend on the Locator's unrelated GitHub MCP endpoint.  Discovery still
    proves the fixed six-role Team exists, while executable/config/schema
    attestation is deliberately limited to the Leader surface used below.
    """

    def preflight(self) -> RuntimeContext:
        self.runner.run(
            [self.kubectl, "version", "--request-timeout=10s"], timeout=20
        )
        try:
            team = _strict_loads(
                self.runner.run(
                    self._kubectl("get", "team", TEAM_NAME, "--output", "json"),
                    timeout=30,
                )
            )
            pods = _strict_loads(
                self.runner.run(
                    self._kubectl(
                        "get",
                        "pods",
                        "--selector",
                        f"agentteams.io/team={TEAM_NAME}",
                        "--output",
                        "json",
                    ),
                    timeout=30,
                )
            )
            if not isinstance(team, dict) or not isinstance(pods, dict):
                raise ReconcileError("discovery document is malformed")
            targets = discover_targets(
                team, pods, require_github_issuer_token=False
            )
        except (ReconcileError, TypeError, ValueError) as exc:
            raise DriverError(
                "runtime_discovery_failed", "runtime-preflight"
            ) from exc

        by_role = {target.role_name: target for target in targets}
        if set(by_role) != {
            "devflow-lead",
            "devflow-triage",
            "devflow-locator",
            "devflow-coder",
            "devflow-tester",
            "devflow-reviewer",
        }:
            raise DriverError("runtime_set_invalid", "runtime-preflight")

        leader = by_role[LEADER_ROLE]
        locator = by_role[LOCATOR_ROLE]
        expected_servers = [TEAMHARNESS_SERVER]
        report = self._json_object(
            self._exec(
                leader,
                REMOTE_PREFLIGHT_HELPER,
                [leader.role_name, leader.workspace],
                timeout_seconds=HOST_PREFLIGHT_TIMEOUT_SECONDS,
            ),
            "runtime-preflight",
        )
        expected = {
            "ok": True,
            "role": LEADER_ROLE,
            "serverNames": expected_servers,
            "skillAttested": False,
            "mcporterSha256": EXPECTED_MCPORTER_SHA256,
            "mcporterVersion": EXPECTED_MCPORTER_VERSION,
            "configSha256": _sha256(
                _canonical_bytes(_normalized_mcporter_config(LEADER_ROLE))
            ),
            "schemaCanonicalization": MCP_SCHEMA_CANONICALIZATION_ID,
            "schemaCanonicalSha256": {
                server: EXPECTED_MCP_SCHEMA_CANONICAL_SHA256[LEADER_ROLE][server]
                for server in expected_servers
            },
            "schemaCanonicalBytes": {
                server: EXPECTED_MCP_SCHEMA_CANONICAL_BYTES[LEADER_ROLE][server]
                for server in expected_servers
            },
        }
        if report != expected:
            raise DriverError("runtime_attestation_failed", "runtime-preflight")
        self._leader = leader
        self._locator = None
        return RuntimeContext(
            leader_matrix_user_id=leader.matrix_user_id,
            locator_matrix_user_id=locator.matrix_user_id,
        )


def _validate_project_id(project_id: str) -> None:
    if (
        not isinstance(project_id, str)
        or len(project_id) > 48
        or SAFE_PROJECT.fullmatch(project_id) is None
    ):
        raise DriverError("project_id_invalid", "input")


PROJECT_BINDING_FIELDS = {
    "schema",
    "audience",
    "approvalDomain",
    "policyKeySha256",
    "riskTierAuthority",
    "sourceAuthority",
    "incarnationAuthority",
    "projectBindingDigest",
}


def _expect_binding(value: Any, stage: str) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != PROJECT_BINDING_FIELDS
        or value.get("schema") != "devflow.project-binding/v2"
        or value.get("audience") != APPROVAL_AUDIENCE
        or not isinstance(value.get("approvalDomain"), str)
        or DIGEST.fullmatch(value["approvalDomain"]) is None
        or not isinstance(value.get("policyKeySha256"), str)
        or DIGEST.fullmatch(value["policyKeySha256"]) is None
        or value.get("riskTierAuthority") != "root-only-approval-ledger"
        or value.get("sourceAuthority") != "persistent-project-state"
        or value.get("incarnationAuthority")
        != "guard-generated-root-only-approval-ledger"
        or not isinstance(value.get("projectBindingDigest"), str)
        or DIGEST.fullmatch(value["projectBindingDigest"]) is None
    ):
        raise DriverError("project_binding_invalid", stage)
    return {key: str(value[key]) for key in PROJECT_BINDING_FIELDS}


def _expect_project(
    project: Any,
    project_id: str,
    *,
    status: str,
    stage: str,
    expected_binding: dict[str, str] | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(project, dict)
        or project.get("project_id") != project_id
        or project.get("risk_tier") != RISK_TIER
        or project.get("source") != SOURCE
        or project.get("status") != status
    ):
        raise DriverError("project_state_invalid", stage)
    binding = _expect_binding(project.get("binding"), stage)
    if expected_binding is not None and binding != expected_binding:
        raise DriverError("project_binding_changed", stage)
    return dict(project)


def _resume_arguments(project_id: str) -> dict[str, Any]:
    return {
        "action": "resume_project",
        "riskTier": RISK_TIER,
        "payload": {"projectId": project_id, "source": SOURCE},
    }


def approval_target_digest(arguments: dict[str, Any]) -> str:
    """Match the guard's canonical projectflow target digest."""

    target = _strict_loads(_canonical_text(arguments))
    if not isinstance(target, dict):
        raise DriverError("approval_target_invalid", "input")
    target.pop("approval", None)
    target.pop("role", None)
    target.pop("workspaceDir", None)
    if isinstance(target.get("payload"), str):
        payload = _strict_loads(target["payload"])
        if not isinstance(payload, dict):
            raise DriverError("approval_target_invalid", "input")
        target["payload"] = payload
    return _sha256(
        _canonical_bytes({"tool": "projectflow", "arguments": target})
    )


def approval_request_digest(
    *,
    project_id: str,
    arguments: dict[str, Any],
    binding: dict[str, str],
) -> str:
    """Bind operator intent to this policy, deployment, and project incarnation."""

    checked = _expect_binding(binding, "approval-request")
    request = {
        "schema": APPROVAL_REQUEST_SCHEMA,
        "audience": checked["audience"],
        "approvalDomain": checked["approvalDomain"],
        "policyKeySha256": checked["policyKeySha256"],
        "projectBindingDigest": checked["projectBindingDigest"],
        "action": "resume_project",
        "projectId": project_id,
        "riskTier": RISK_TIER,
        "targetDigest": approval_target_digest(arguments),
    }
    return _sha256(_canonical_bytes(request))


def _parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or RFC3339_UTC.fullmatch(value) is None:
        raise DriverError("approval_schema_invalid", field)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise DriverError("approval_schema_invalid", field) from exc


def validate_approval(
    approval: Any,
    *,
    project_id: str,
    arguments: dict[str, Any],
    binding: dict[str, str],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate public approval shape against guard-attested local policy facts."""

    if not isinstance(approval, dict) or set(approval) != {"evidence", "signature"}:
        raise DriverError("approval_schema_invalid", "approval-input")
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
    if not isinstance(evidence, dict) or set(evidence) != expected_fields:
        raise DriverError("approval_schema_invalid", "approval-input")
    checked_binding = _expect_binding(binding, "approval-input")
    target_digest = approval_target_digest(arguments)
    request_digest = approval_request_digest(
        project_id=project_id,
        arguments=arguments,
        binding=checked_binding,
    )
    if (
        evidence.get("schemaVersion") != "1.1"
        or evidence.get("audience") != checked_binding["audience"]
        or evidence.get("approvalDomain") != checked_binding["approvalDomain"]
        or evidence.get("policyKeySha256") != checked_binding["policyKeySha256"]
        or evidence.get("projectBindingDigest")
        != checked_binding["projectBindingDigest"]
        or evidence.get("approvalRequestDigest") != request_digest
        or evidence.get("action") != "resume_project"
        or evidence.get("projectId") != project_id
        or evidence.get("riskTier") != RISK_TIER
        or evidence.get("targetDigest") != target_digest
        or not isinstance(evidence.get("approvedBy"), str)
        or APPROVER.fullmatch(evidence["approvedBy"]) is None
        or not isinstance(evidence.get("nonce"), str)
        or NONCE.fullmatch(evidence["nonce"]) is None
    ):
        raise DriverError("approval_scope_invalid", "approval-input")
    issued_at = _parse_utc(evidence.get("issuedAt"), "approval-input")
    expires_at = _parse_utc(evidence.get("expiresAt"), "approval-input")
    current = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    if (
        issued_at > current
        or expires_at <= current
        or expires_at <= issued_at
        or (expires_at - issued_at).total_seconds() > 900
    ):
        raise DriverError("approval_time_invalid", "approval-input")
    signature = approval.get("signature")
    if not isinstance(signature, str):
        raise DriverError("approval_signature_invalid", "approval-input")
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DriverError("approval_signature_invalid", "approval-input") from exc
    if len(signature_bytes) != 64:
        raise DriverError("approval_signature_invalid", "approval-input")
    return {
        "evidence": dict(evidence),
        "signature": signature,
    }


def _expect_leader(context: RuntimeContext) -> None:
    prefix = f"@{LEADER_ROLE}:"
    if not context.leader_matrix_user_id.startswith(prefix):
        raise DriverError("leader_identity_invalid", "runtime-preflight")


def _expect_denied(
    response: Any,
    *,
    action: str,
    error: str,
    stage: str,
) -> None:
    checked = _expect_identity(
        response,
        tool="projectflow",
        action=action,
        stage=stage,
    )
    if checked.get("ok") is not False or checked.get("error") != error:
        raise DriverError("denial_not_proven", stage)


def plan_report() -> dict[str, Any]:
    report = {
        "ok": True,
        "mode": "plan",
        "executionMode": "operator-driven",
        "writes": False,
        "riskTier": RISK_TIER,
        "privateKeyLocation": "external-operator-only",
        "prepareConfirmation": PREPARE_CONFIRMATION,
        "approvalAudience": APPROVAL_AUDIENCE,
        "resumeConfirmationFormat": (
            f"{RESUME_CONFIRMATION_PREFIX}<approvalRequestDigest>"
        ),
        "stages": [
            "attest-runtime",
            "prove-fresh-project",
            "create-t4-project",
            "pause-project",
            "prove-unsigned-resume-denial",
            "publish-domain-key-project-bound-approval-request-digest",
            "accept-external-signature",
            "resume-paused-project-once",
            "prove-replay-denial",
            "read-back-active-state",
        ],
    }
    _assert_public_safe(report)
    return report


def prepare_approval(
    backend: ApprovalBackend,
    *,
    project_id: str,
    confirmation: str,
) -> dict[str, Any]:
    if confirmation != PREPARE_CONFIRMATION:
        raise DriverError("confirmation_required", "input")
    _validate_project_id(project_id)
    _expect_leader(backend.preflight())

    _expect_absent(
        backend.leader_call(
            "projectflow",
            {"action": "resolve_project", "payload": {"projectId": project_id}},
        ),
        tool="projectflow",
        action="resolve_project",
        error="project not found",
        stage="fresh-project",
    )
    created = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "create_project",
                "riskTier": RISK_TIER,
                "payload": {
                    "projectId": project_id,
                    "title": "One-time externally approved T4 resume",
                    "source": SOURCE,
                },
            },
        ),
        tool="projectflow",
        action="create_project",
        stage="create-project",
    )
    created_project = _expect_project(
        created.get("project"), project_id, status="active", stage="create-project"
    )
    binding = _expect_binding(created_project["binding"], "create-project")
    paused = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "pause_project",
                "riskTier": RISK_TIER,
                "payload": {"projectId": project_id, "source": SOURCE},
            },
        ),
        tool="projectflow",
        action="pause_project",
        stage="pause-project",
    )
    _expect_project(
        paused.get("project"),
        project_id,
        status="paused",
        stage="pause-project",
        expected_binding=binding,
    )
    resume_arguments = _resume_arguments(project_id)
    _expect_denied(
        backend.leader_call("projectflow", resume_arguments),
        action="resume_project",
        error="approval_denied:approval must contain exactly evidence and signature",
        stage="unsigned-resume",
    )
    resolved = _expect_ok(
        backend.leader_call(
            "projectflow",
            {"action": "resolve_project", "payload": {"projectId": project_id}},
        ),
        tool="projectflow",
        action="resolve_project",
        stage="paused-readback",
    )
    _expect_project(
        resolved.get("project"),
        project_id,
        status="paused",
        stage="paused-readback",
        expected_binding=binding,
    )
    target_digest = approval_target_digest(resume_arguments)
    request_digest = approval_request_digest(
        project_id=project_id,
        arguments=resume_arguments,
        binding=binding,
    )
    report = {
        "ok": True,
        "mode": "prepare",
        "executionMode": "operator-driven",
        "riskTier": RISK_TIER,
        "projectIdSha256": _sha256(project_id.encode("utf-8")),
        "audience": binding["audience"],
        "approvalDomain": binding["approvalDomain"],
        "policyKeySha256": binding["policyKeySha256"],
        "projectBindingDigest": binding["projectBindingDigest"],
        "targetDigest": target_digest,
        "paused": True,
        "unsignedResumeDenied": True,
        "approvalRequestDigest": request_digest,
        "approvalConfirmation": f"{RESUME_CONFIRMATION_PREFIX}{request_digest}",
    }
    _assert_public_safe(report)
    return report


def resume_with_approval(
    backend: ApprovalBackend,
    *,
    project_id: str,
    approval: Any,
    confirmation: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    _validate_project_id(project_id)
    arguments = _resume_arguments(project_id)
    target_digest = approval_target_digest(arguments)
    _expect_leader(backend.preflight())
    before = _expect_ok(
        backend.leader_call(
            "projectflow",
            {"action": "resolve_project", "payload": {"projectId": project_id}},
        ),
        tool="projectflow",
        action="resolve_project",
        stage="pre-resume-readback",
    )
    before_project = _expect_project(
        before.get("project"),
        project_id,
        status="paused",
        stage="pre-resume-readback",
    )
    binding = _expect_binding(before_project["binding"], "pre-resume-readback")
    request_digest = approval_request_digest(
        project_id=project_id,
        arguments=arguments,
        binding=binding,
    )
    if confirmation != f"{RESUME_CONFIRMATION_PREFIX}{request_digest}":
        raise DriverError("confirmation_required", "input")
    checked_approval = validate_approval(
        approval,
        project_id=project_id,
        arguments=arguments,
        binding=binding,
        now=now,
    )

    approved_arguments = {**arguments, "approval": checked_approval}
    resumed = _expect_ok(
        backend.leader_call("projectflow", approved_arguments),
        tool="projectflow",
        action="resume_project",
        stage="signed-resume",
    )
    _expect_project(
        resumed.get("project"),
        project_id,
        status="active",
        stage="signed-resume",
        expected_binding=binding,
    )
    _expect_denied(
        backend.leader_call("projectflow", approved_arguments),
        action="resume_project",
        error="approval_denied:approval nonce was already used",
        stage="replay-denial",
    )
    after = _expect_ok(
        backend.leader_call(
            "projectflow",
            {"action": "resolve_project", "payload": {"projectId": project_id}},
        ),
        tool="projectflow",
        action="resolve_project",
        stage="post-resume-readback",
    )
    _expect_project(
        after.get("project"),
        project_id,
        status="active",
        stage="post-resume-readback",
        expected_binding=binding,
    )
    evidence = checked_approval["evidence"]
    signature_bytes = base64.b64decode(checked_approval["signature"], validate=True)
    report = {
        "ok": True,
        "mode": "resume",
        "executionMode": "human-approved",
        "riskTier": RISK_TIER,
        "projectIdSha256": _sha256(project_id.encode("utf-8")),
        "audience": binding["audience"],
        "approvalDomain": binding["approvalDomain"],
        "policyKeySha256": binding["policyKeySha256"],
        "projectBindingDigest": binding["projectBindingDigest"],
        "targetDigest": target_digest,
        "approvalRequestDigest": request_digest,
        "approvalEvidenceSha256": _sha256(_canonical_bytes(evidence)),
        "approvalSignatureSha256": hashlib.sha256(signature_bytes).hexdigest(),
        "approverIdSha256": _sha256(str(evidence["approvedBy"]).encode("utf-8")),
        "nonceSha256": _sha256(str(evidence["nonce"]).encode("utf-8")),
        "signedResumeVerified": True,
        "replayDenied": True,
        "postResumeStatus": "active",
    }
    _assert_public_safe(report)
    return report


def _load_approval(path: Path) -> Any:
    descriptor: int | None = None
    try:
        geteuid = getattr(os, "geteuid", None)
        if os.name == "posix":
            parent = path.parent
            parent_metadata = parent.lstat()
            if (
                geteuid is None
                or not path.is_absolute()
                or parent.is_symlink()
                or parent.resolve(strict=True) != parent
                or not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != geteuid()
                or stat.S_IMODE(parent_metadata.st_mode) & 0o077
            ):
                raise OSError
        before = path.lstat()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= 16_384
            or (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino)
            or (
                os.name == "posix"
                and (
                    geteuid is None
                    or metadata.st_uid != geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                )
            )
        ):
            raise OSError
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(16_384, remaining))
            if not chunk:
                raise OSError
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size:
            raise OSError
        return _strict_loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise DriverError("approval_file_invalid", "approval-input") from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare or verify one external T4 approval on AgentTeams."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--resume", action="store_true")
    parser.add_argument("--project-id")
    parser.add_argument("--approval-file", type=Path)
    parser.add_argument("--confirm")
    parser.add_argument("--kubectl", default="kubectl")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not args.prepare and not args.resume:
            if any(
                value is not None
                for value in (args.project_id, args.approval_file, args.confirm)
            ):
                raise DriverError("execute_flag_required", "input")
            result = plan_report()
        elif args.prepare:
            if (
                args.project_id is None
                or args.confirm is None
                or args.approval_file is not None
            ):
                raise DriverError("execution_arguments_invalid", "input")
            result = prepare_approval(
                T4KubernetesBackend(args.kubectl),
                project_id=args.project_id,
                confirmation=args.confirm,
            )
        else:
            if (
                args.project_id is None
                or args.confirm is None
                or args.approval_file is None
            ):
                raise DriverError("execution_arguments_invalid", "input")
            result = resume_with_approval(
                T4KubernetesBackend(args.kubectl),
                project_id=args.project_id,
                approval=_load_approval(args.approval_file),
                confirmation=args.confirm,
            )
        _assert_public_safe(result)
        print(_canonical_text(result))
        return 0
    except DriverError as exc:
        failure = {"ok": False, "code": exc.code, "stage": exc.stage}
        _assert_public_safe(failure)
        print(_canonical_text(failure))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
