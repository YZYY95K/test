"""Deterministic tests for the live T4 approval driver."""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts.run_agentteams_github_success_path import (
    REMOTE_CONTROL_HELPER,
    DriverError,
    RuntimeContext,
    _canonical_text,
)
from scripts.run_agentteams_t4_approval import (
    APPROVAL_AUDIENCE,
    PREPARE_CONFIRMATION,
    RESUME_CONFIRMATION_PREFIX,
    _resume_arguments,
    approval_request_digest,
    approval_target_digest,
    prepare_approval,
    resume_with_approval,
    validate_approval,
)
from scripts.sign_agentteams_t4_approval import (
    KEY_CONFIRMATION,
    generate_keypair,
    sign_approval,
)

PROJECT_ID = "devflow-live-t4-driver-test"
TEST_APPROVAL_DOMAIN = "a" * 64
TEST_POLICY_KEY_SHA256 = "b" * 64
TEST_PROJECT_BINDING_DIGEST = "c" * 64


def _binding(
    *,
    policy_key_sha256: str = TEST_POLICY_KEY_SHA256,
) -> dict[str, str]:
    return {
        "schema": "devflow.project-binding/v2",
        "audience": APPROVAL_AUDIENCE,
        "approvalDomain": TEST_APPROVAL_DOMAIN,
        "policyKeySha256": policy_key_sha256,
        "riskTierAuthority": "root-only-approval-ledger",
        "sourceAuthority": "persistent-project-state",
        "incarnationAuthority": "guard-generated-root-only-approval-ledger",
        "projectBindingDigest": TEST_PROJECT_BINDING_DIGEST,
    }


class FakeBackend:
    def __init__(self) -> None:
        self.project: dict[str, Any] | None = None
        self.resume_seen = False

    def preflight(self) -> RuntimeContext:
        return RuntimeContext(
            leader_matrix_user_id="@devflow-lead:matrix.test",
            locator_matrix_user_id="@devflow-locator:matrix.test",
        )

    def _bound_project(self) -> dict[str, Any]:
        assert self.project is not None
        return {
            **self.project,
            "risk_tier": "T4",
            "binding": _binding(),
        }

    def leader_call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        assert tool == "projectflow"
        action = str(arguments["action"])
        payload = arguments.get("payload", {})
        project_id = payload.get("projectId")
        assert project_id == PROJECT_ID
        if action == "resolve_project" and self.project is None:
            return {
                "ok": False,
                "tool": tool,
                "action": action,
                "error": "project not found",
            }
        if action == "create_project":
            self.project = {
                "project_id": PROJECT_ID,
                "source": "operator-driven",
                "status": "active",
                "tasks": [],
            }
            return {
                "ok": True,
                "tool": tool,
                "action": action,
                "project": self._bound_project(),
            }
        assert self.project is not None
        if action == "pause_project":
            self.project["status"] = "paused"
        elif action == "resume_project":
            if "approval" not in arguments:
                return {
                    "ok": False,
                    "tool": tool,
                    "action": action,
                    "error": (
                        "approval_denied:approval must contain exactly evidence and signature"
                    ),
                }
            if self.resume_seen:
                return {
                    "ok": False,
                    "tool": tool,
                    "action": action,
                    "error": "approval_denied:approval nonce was already used",
                }
            self.resume_seen = True
            self.project["status"] = "active"
        return {
            "ok": True,
            "tool": tool,
            "action": action,
            "project": self._bound_project(),
        }


def _approval(
    now: datetime,
    *,
    binding: dict[str, str] | None = None,
) -> dict[str, Any]:
    arguments = _resume_arguments(PROJECT_ID)
    binding = binding or _binding()
    evidence = {
        "schemaVersion": "1.1",
        "audience": binding["audience"],
        "approvalDomain": binding["approvalDomain"],
        "policyKeySha256": binding["policyKeySha256"],
        "projectBindingDigest": binding["projectBindingDigest"],
        "approvalRequestDigest": approval_request_digest(
            project_id=PROJECT_ID,
            arguments=arguments,
            binding=binding,
        ),
        "action": "resume_project",
        "projectId": PROJECT_ID,
        "riskTier": "T4",
        "targetDigest": approval_target_digest(arguments),
        "approvedBy": "human-operator",
        "issuedAt": (now - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": "nonce_driver_fixture_123456",
    }
    return {
        "evidence": evidence,
        "signature": base64.b64encode(b"s" * 64).decode("ascii"),
    }


def test_prepare_proves_pause_and_unsigned_denial_without_public_project_id() -> None:
    report = prepare_approval(
        FakeBackend(),
        project_id=PROJECT_ID,
        confirmation=PREPARE_CONFIRMATION,
    )

    assert report["paused"] is True
    assert report["unsignedResumeDenied"] is True
    assert report["approvalConfirmation"] == (
        RESUME_CONFIRMATION_PREFIX + report["approvalRequestDigest"]
    )
    assert PROJECT_ID not in _canonical_text(report)


def test_resume_accepts_exact_public_shape_and_proves_replay_denial() -> None:
    now = datetime(2026, 7, 28, 8, 0, tzinfo=timezone.utc)
    backend = FakeBackend()
    prepare = prepare_approval(
        backend,
        project_id=PROJECT_ID,
        confirmation=PREPARE_CONFIRMATION,
    )
    report = resume_with_approval(
        backend,
        project_id=PROJECT_ID,
        approval=_approval(now),
        confirmation=prepare["approvalConfirmation"],
        now=now,
    )

    assert report["signedResumeVerified"] is True
    assert report["replayDenied"] is True
    assert report["postResumeStatus"] == "active"
    assert PROJECT_ID not in _canonical_text(report)


def test_approval_validation_rejects_scope_time_and_signature_changes() -> None:
    now = datetime(2026, 7, 28, 8, 0, tzinfo=timezone.utc)
    arguments = _resume_arguments(PROJECT_ID)
    valid = _approval(now)
    assert (
        validate_approval(
            valid,
            project_id=PROJECT_ID,
            arguments=arguments,
            binding=_binding(),
            now=now,
        )
        == valid
    )

    wrong_scope = _approval(now)
    wrong_scope["evidence"]["targetDigest"] = "0" * 64
    with pytest.raises(DriverError, match="approval_scope_invalid"):
        validate_approval(
            wrong_scope,
            project_id=PROJECT_ID,
            arguments=arguments,
            binding=_binding(),
            now=now,
        )

    expired = _approval(now)
    expired["evidence"]["expiresAt"] = (now - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with pytest.raises(DriverError, match="approval_time_invalid"):
        validate_approval(
            expired,
            project_id=PROJECT_ID,
            arguments=arguments,
            binding=_binding(),
            now=now,
        )

    short_signature = _approval(now)
    short_signature["signature"] = base64.b64encode(b"x" * 63).decode("ascii")
    with pytest.raises(DriverError, match="approval_signature_invalid"):
        validate_approval(
            short_signature,
            project_id=PROJECT_ID,
            arguments=arguments,
            binding=_binding(),
            now=now,
        )

    for field, replacement in (
        ("approvalDomain", "0" * 64),
        ("policyKeySha256", "1" * 64),
        ("projectBindingDigest", "2" * 64),
        ("approvalRequestDigest", "3" * 64),
    ):
        tampered = _approval(now)
        tampered["evidence"][field] = replacement
        with pytest.raises(DriverError, match="approval_scope_invalid"):
            validate_approval(
                tampered,
                project_id=PROJECT_ID,
                arguments=arguments,
                binding=_binding(),
                now=now,
            )


def test_resume_rejects_legacy_target_only_confirmation_before_transition() -> None:
    now = datetime(2026, 7, 28, 8, 0, tzinfo=timezone.utc)
    backend = FakeBackend()
    prepare_approval(
        backend,
        project_id=PROJECT_ID,
        confirmation=PREPARE_CONFIRMATION,
    )

    with pytest.raises(DriverError, match="confirmation_required"):
        resume_with_approval(
            backend,
            project_id=PROJECT_ID,
            approval=_approval(now),
            confirmation=(
                RESUME_CONFIRMATION_PREFIX + approval_target_digest(_resume_arguments(PROJECT_ID))
            ),
            now=now,
        )

    assert backend.project is not None
    assert backend.project["status"] == "paused"
    assert backend.resume_seen is False


def test_remote_control_surface_is_still_leader_only_and_allows_t4_transitions() -> None:
    assert 'role != "devflow-lead"' in REMOTE_CONTROL_HELPER
    assert '"pause_project"' in REMOTE_CONTROL_HELPER
    assert '"resume_project"' in REMOTE_CONTROL_HELPER
    assert '"worker":' not in REMOTE_CONTROL_HELPER


def test_external_signer_keeps_key_local_and_signs_only_exact_confirmation(
    tmp_path: Path,
) -> None:
    private_key = tmp_path / "operator-private.pem"
    public_key = tmp_path / "operator-public.pem"
    approval_path = tmp_path / "approval.json"
    generated = generate_keypair(
        private_key_path=private_key,
        public_key_path=public_key,
        confirmation=KEY_CONFIRMATION,
    )
    assert generated["privateKeyExported"] is False
    assert private_key.is_file() and public_key.is_file()
    with pytest.raises(DriverError, match="key_path_exists"):
        generate_keypair(
            private_key_path=private_key,
            public_key_path=public_key,
            confirmation=KEY_CONFIRMATION,
        )

    now = datetime(2026, 7, 28, 8, 0, tzinfo=timezone.utc)
    signing_binding = _binding(policy_key_sha256=generated["publicKeySha256"])
    request_digest = approval_request_digest(
        project_id=PROJECT_ID,
        arguments=_resume_arguments(PROJECT_ID),
        binding=signing_binding,
    )
    signed = sign_approval(
        private_key_path=private_key,
        output_path=approval_path,
        project_id=PROJECT_ID,
        approved_by="human-operator",
        approval_domain=TEST_APPROVAL_DOMAIN,
        policy_key_sha256=generated["publicKeySha256"],
        project_binding_digest=TEST_PROJECT_BINDING_DIGEST,
        confirmation=RESUME_CONFIRMATION_PREFIX + request_digest,
        now=now,
    )
    assert signed["privateKeyExported"] is False
    assert PROJECT_ID not in _canonical_text(signed)
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    validate_approval(
        approval,
        project_id=PROJECT_ID,
        arguments=_resume_arguments(PROJECT_ID),
        binding=signing_binding,
        now=now,
    )
    loaded = serialization.load_pem_public_key(public_key.read_bytes())
    assert isinstance(loaded, Ed25519PublicKey)
    loaded.verify(
        base64.b64decode(approval["signature"]),
        _canonical_text(approval["evidence"]).encode("utf-8"),
    )


@pytest.mark.parametrize("collision", ["private", "public"])
def test_generate_keypair_race_never_removes_competing_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    collision: str,
) -> None:
    private_key = tmp_path / "operator-private.pem"
    public_key = tmp_path / "operator-public.pem"
    collision_path = private_key if collision == "private" else public_key
    competing_payload = b"created-by-competing-process"
    real_open = os.open
    injected = False

    def racing_open(
        path: str | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
    ) -> int:
        nonlocal injected
        if not injected and Path(path) == collision_path and flags & os.O_EXCL:
            injected = True
            descriptor = real_open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            try:
                os.write(descriptor, competing_payload)
            finally:
                os.close(descriptor)
        return real_open(path, flags, mode)

    monkeypatch.setattr(os, "open", racing_open)

    with pytest.raises(DriverError, match="key_path_exists"):
        generate_keypair(
            private_key_path=private_key,
            public_key_path=public_key,
            confirmation=KEY_CONFIRMATION,
        )

    assert collision_path.read_bytes() == competing_payload
    other_path = public_key if collision == "private" else private_key
    assert not other_path.exists()


def test_external_signer_refuses_wrong_human_confirmation_without_output(
    tmp_path: Path,
) -> None:
    private_key = tmp_path / "operator-private.pem"
    public_key = tmp_path / "operator-public.pem"
    output = tmp_path / "approval.json"
    generated = generate_keypair(
        private_key_path=private_key,
        public_key_path=public_key,
        confirmation=KEY_CONFIRMATION,
    )

    with pytest.raises(DriverError, match="confirmation_required"):
        sign_approval(
            private_key_path=private_key,
            output_path=output,
            project_id=PROJECT_ID,
            approved_by="human-operator",
            approval_domain=TEST_APPROVAL_DOMAIN,
            policy_key_sha256=generated["publicKeySha256"],
            project_binding_digest=TEST_PROJECT_BINDING_DIGEST,
            confirmation="APPROVE_SOMETHING_ELSE",
        )
    assert not output.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits are not portable")
def test_external_signer_refuses_group_or_world_readable_private_key(
    tmp_path: Path,
) -> None:
    private_key = tmp_path / "operator-private.pem"
    public_key = tmp_path / "operator-public.pem"
    generated = generate_keypair(
        private_key_path=private_key,
        public_key_path=public_key,
        confirmation=KEY_CONFIRMATION,
    )
    private_key.chmod(0o644)

    with pytest.raises(DriverError, match="private_key_invalid"):
        sign_approval(
            private_key_path=private_key,
            output_path=tmp_path / "approval.json",
            project_id=PROJECT_ID,
            approved_by="human-operator",
            approval_domain=TEST_APPROVAL_DOMAIN,
            policy_key_sha256=generated["publicKeySha256"],
            project_binding_digest=TEST_PROJECT_BINDING_DIGEST,
            confirmation=RESUME_CONFIRMATION_PREFIX + "0" * 64,
        )
