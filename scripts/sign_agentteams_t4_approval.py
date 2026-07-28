#!/usr/bin/env python3
"""Generate an external Ed25519 key or sign one exact T4 resume request.

This utility is intentionally cluster-blind.  The private key stays on the
operator workstation; only its public key is installed in AgentTeams.  Signing
requires the exact deployment-, key-, and project-bound approval request
digest in the confirmation phrase emitted by the prepare driver.
"""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

try:
    from scripts.run_agentteams_github_success_path import (
        DriverError,
        _assert_public_safe,
        _canonical_bytes,
        _canonical_text,
        _sha256,
    )
    from scripts.run_agentteams_t4_approval import (
        APPROVAL_AUDIENCE,
        APPROVER,
        DIGEST,
        RESUME_CONFIRMATION_PREFIX,
        _expect_binding,
        _resume_arguments,
        _validate_project_id,
        approval_request_digest,
        approval_target_digest,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from run_agentteams_github_success_path import (  # type: ignore[no-redef]
        DriverError,
        _assert_public_safe,
        _canonical_bytes,
        _canonical_text,
        _sha256,
    )
    from run_agentteams_t4_approval import (  # type: ignore[no-redef]
        APPROVAL_AUDIENCE,
        APPROVER,
        DIGEST,
        RESUME_CONFIRMATION_PREFIX,
        _expect_binding,
        _resume_arguments,
        _validate_project_id,
        approval_request_digest,
        approval_target_digest,
    )


KEY_CONFIRMATION = "GENERATE_EXTERNAL_T4_APPROVAL_KEY"


@dataclass(frozen=True)
class _CreatedFile:
    path: Path
    device: int
    inode: int


def _unlink_created_file(created: _CreatedFile) -> None:
    """Remove a file only while it is still the inode created by this process."""

    try:
        metadata = created.path.lstat()
    except OSError:
        return
    if (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and (metadata.st_dev, metadata.st_ino) == (created.device, created.inode)
    ):
        with suppress(OSError):
            created.path.unlink()


def _write_new(path: Path, payload: bytes, mode: int) -> _CreatedFile:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    metadata = os.fstat(descriptor)
    created = _CreatedFile(path=path, device=metadata.st_dev, inode=metadata.st_ino)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        _unlink_created_file(created)
        raise
    with suppress(OSError):
        path.chmod(mode)
    return created


def generate_keypair(
    *,
    private_key_path: Path,
    public_key_path: Path,
    confirmation: str,
) -> dict[str, Any]:
    if confirmation != KEY_CONFIRMATION:
        raise DriverError("confirmation_required", "input")
    if private_key_path == public_key_path:
        raise DriverError("key_paths_invalid", "input")
    if private_key_path.exists() or public_key_path.exists():
        raise DriverError("key_path_exists", "input")
    signer = Ed25519PrivateKey.generate()
    private_pem = signer.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = signer.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    created: list[_CreatedFile] = []
    try:
        created.append(_write_new(private_key_path, private_pem, 0o600))
        created.append(_write_new(public_key_path, public_pem, 0o444))
    except FileExistsError as exc:
        for item in reversed(created):
            _unlink_created_file(item)
        raise DriverError("key_path_exists", "input") from exc
    except Exception:
        for item in reversed(created):
            _unlink_created_file(item)
        raise
    report = {
        "ok": True,
        "mode": "generate-key",
        "algorithm": "Ed25519",
        "privateKeyExported": False,
        "publicKeySha256": _sha256(public_pem),
    }
    _assert_public_safe(report)
    return report


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    descriptor: int | None = None
    try:
        before = path.lstat()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= 4_096
            or (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise OSError
        if os.name == "posix":
            if metadata.st_mode & 0o077:
                raise OSError
            getuid = getattr(os, "getuid", None)
            if getuid is not None and metadata.st_uid != getuid():
                raise OSError
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            payload = handle.read(4_097)
        if len(payload) != metadata.st_size:
            raise OSError
        value = serialization.load_pem_private_key(
            payload,
            password=None,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise DriverError("private_key_invalid", "signing") from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
    if not isinstance(value, Ed25519PrivateKey):
        raise DriverError("private_key_invalid", "signing")
    return value


def _public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sign_approval(
    *,
    private_key_path: Path,
    output_path: Path,
    project_id: str,
    approved_by: str,
    approval_domain: str,
    policy_key_sha256: str,
    project_binding_digest: str,
    confirmation: str,
    now: datetime | None = None,
    lifetime_seconds: int = 300,
) -> dict[str, Any]:
    _validate_project_id(project_id)
    if APPROVER.fullmatch(approved_by) is None:
        raise DriverError("approver_invalid", "input")
    if not 30 <= lifetime_seconds <= 900:
        raise DriverError("approval_lifetime_invalid", "input")
    if (
        DIGEST.fullmatch(approval_domain) is None
        or DIGEST.fullmatch(policy_key_sha256) is None
        or DIGEST.fullmatch(project_binding_digest) is None
    ):
        raise DriverError("approval_binding_invalid", "input")
    key = _load_private_key(private_key_path)
    public_pem = _public_key_bytes(key.public_key())
    actual_policy_key_sha256 = _sha256(public_pem)
    if actual_policy_key_sha256 != policy_key_sha256:
        raise DriverError("policy_key_mismatch", "input")
    arguments = _resume_arguments(project_id)
    target_digest = approval_target_digest(arguments)
    binding = _expect_binding(
        {
            "schema": "devflow.project-binding/v2",
            "audience": APPROVAL_AUDIENCE,
            "approvalDomain": approval_domain,
            "policyKeySha256": policy_key_sha256,
            "riskTierAuthority": "root-only-approval-ledger",
            "sourceAuthority": "persistent-project-state",
            "incarnationAuthority": "guard-generated-root-only-approval-ledger",
            "projectBindingDigest": project_binding_digest,
        },
        "input",
    )
    request_digest = approval_request_digest(
        project_id=project_id,
        arguments=arguments,
        binding=binding,
    )
    if confirmation != f"{RESUME_CONFIRMATION_PREFIX}{request_digest}":
        raise DriverError("confirmation_required", "input")
    if output_path.exists():
        raise DriverError("approval_path_exists", "input")
    current = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    evidence = {
        "schemaVersion": "1.1",
        "audience": APPROVAL_AUDIENCE,
        "approvalDomain": approval_domain,
        "policyKeySha256": policy_key_sha256,
        "projectBindingDigest": project_binding_digest,
        "approvalRequestDigest": request_digest,
        "action": "resume_project",
        "projectId": project_id,
        "riskTier": "T4",
        "targetDigest": target_digest,
        "approvedBy": approved_by,
        "issuedAt": current.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expiresAt": (current + timedelta(seconds=lifetime_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": base64.urlsafe_b64encode(secrets.token_bytes(24)).decode("ascii").rstrip("="),
    }
    signature = key.sign(_canonical_bytes(evidence))
    approval = {
        "evidence": evidence,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    _write_new(output_path, _canonical_bytes(approval) + b"\n", 0o600)
    report = {
        "ok": True,
        "mode": "sign",
        "algorithm": "Ed25519",
        "projectIdSha256": _sha256(project_id.encode("utf-8")),
        "audience": APPROVAL_AUDIENCE,
        "approvalDomain": approval_domain,
        "policyKeySha256": policy_key_sha256,
        "projectBindingDigest": project_binding_digest,
        "targetDigest": target_digest,
        "approvalRequestDigest": request_digest,
        "approvalEvidenceSha256": _sha256(_canonical_bytes(evidence)),
        "approvalSignatureSha256": _sha256(signature),
        "approvalWritten": True,
        "privateKeyExported": False,
    }
    _assert_public_safe(report)
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate or use an external T4 Ed25519 approval key."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--generate-key", action="store_true")
    mode.add_argument("--sign", action="store_true")
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--project-id")
    parser.add_argument("--approved-by")
    parser.add_argument("--approval-domain")
    parser.add_argument("--policy-key-sha256")
    parser.add_argument("--project-binding-digest")
    parser.add_argument("--lifetime-seconds", type=int, default=300)
    parser.add_argument("--confirm", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.generate_key:
            if (
                args.public_key is None
                or args.output is not None
                or args.project_id is not None
                or args.approved_by is not None
                or args.approval_domain is not None
                or args.policy_key_sha256 is not None
                or args.project_binding_digest is not None
            ):
                raise DriverError("arguments_invalid", "input")
            result = generate_keypair(
                private_key_path=args.private_key,
                public_key_path=args.public_key,
                confirmation=args.confirm,
            )
        else:
            if (
                args.public_key is not None
                or args.output is None
                or args.project_id is None
                or args.approved_by is None
                or args.approval_domain is None
                or args.policy_key_sha256 is None
                or args.project_binding_digest is None
            ):
                raise DriverError("arguments_invalid", "input")
            result = sign_approval(
                private_key_path=args.private_key,
                output_path=args.output,
                project_id=args.project_id,
                approved_by=args.approved_by,
                approval_domain=args.approval_domain,
                policy_key_sha256=args.policy_key_sha256,
                project_binding_digest=args.project_binding_digest,
                confirmation=args.confirm,
                lifetime_seconds=args.lifetime_seconds,
            )
        print(_canonical_text(result))
        return 0
    except (DriverError, OSError) as exc:
        if isinstance(exc, DriverError):
            failure = {"ok": False, "code": exc.code, "stage": exc.stage}
        else:
            failure = {"ok": False, "code": "filesystem_failed", "stage": "write"}
        _assert_public_safe(failure)
        print(_canonical_text(failure))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
