"""Strictly validate GitHub Evidence Skill input and output artifacts."""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from _contract import load_contract

SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,}|"
    r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9_-])?$")
BROKER_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
CAPABILITY = re.compile(r"^[A-Za-z0-9_-]{16,4096}\.[A-Za-z0-9_-]{43}$")
CONTENT_SCHEMA = "devflow.github-content-response/v2"
RECEIPT_SIGNATURE_DOMAIN = b"devflow.github-content-receipt/v2\0"
RECEIPT_SIGNATURE_DOMAIN_NAME = "devflow.github-content-receipt/v2"
PRODUCTION_RECEIPT_PUBLIC_KEY = Path(
    "/etc/devflow/github-evidence/receipt-ed25519.pub"
)
PRODUCTION_RECEIPT_POLICY = Path(
    "/etc/devflow/github-evidence/receipt-policy.json"
)
PRODUCTION_TRUST_ROOT = Path("/etc/devflow/github-evidence")
PRODUCTION_OPENSSL = Path("/usr/bin/openssl")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ED25519_SPKI_BYTES = 44
ED25519_SIGNATURE_BYTES = 64
OPENSSL_TIMEOUT_SECONDS = 10
MAX_CONTENT_BYTES = 1_000_000
ROOT_OUTPUT_FIELDS = frozenset(
    {
        "run_id",
        "task_id",
        "repository",
        "revision",
        "operations",
        "evidence",
        "trace_id",
        "digest",
        "status",
    }
)
RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "assignment",
        "authorization",
        "github",
        "receipt_key_sha256",
        "response_digest",
        "receipt_signature",
    }
)
ASSIGNMENT_FIELDS = frozenset(
    {
        "run_id",
        "task_id",
        "trace_id",
        "repository",
        "revision",
        "paths",
        "scope_digest",
    }
)
AUTHORIZATION_FIELDS = frozenset(
    {"decision", "task_id", "scope_digest", "capability_digest", "authorized_at"}
)
GITHUB_FIELDS = frozenset(
    {"repository", "revision", "path", "object_sha", "content_base64", "encoding"}
)
EVIDENCE_FIELDS = frozenset({"path", "object_sha", "content_sha256", "response_digest"})
RECEIPT_POLICY_FIELDS = frozenset(
    {
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
    }
)


@dataclass(frozen=True)
class ReceiptTrust:
    public_key: Path
    openssl: Path
    public_key_sha256: str


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("artifact contains a duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ValueError("artifact contains a non-standard JSON scalar")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _run_openssl(
    args: list[str],
    *,
    input_data: bytes | None = None,
    maximum: int,
) -> bytes:
    try:
        completed = subprocess.run(
            args,
            input=input_data,
            capture_output=True,
            check=False,
            timeout=OPENSSL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("receipt signature verifier is unavailable") from exc
    if completed.returncode != 0 or len(completed.stdout) > maximum:
        raise ValueError("operation receipt signature is invalid")
    return completed.stdout


def _trusted_regular_file(path: Path, *, maximum: int, mode: int | None) -> bytes:
    try:
        metadata = path.lstat()
        parent_metadata = path.parent.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise ValueError("receipt trust policy is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or len(payload) < 1
        or len(payload) > maximum
        or path.parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
    ):
        raise ValueError("receipt trust policy metadata is invalid")
    production_metadata = path.is_relative_to(PRODUCTION_TRUST_ROOT)
    if os.name == "posix" and production_metadata and (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or mode is not None
        and stat.S_IMODE(metadata.st_mode) != mode
        or parent_metadata.st_uid != 0
        or parent_metadata.st_gid != 0
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise ValueError("receipt trust policy metadata is invalid")
    return payload


def _load_receipt_trust() -> ReceiptTrust:
    policy_bytes = _trusted_regular_file(
        PRODUCTION_RECEIPT_POLICY,
        maximum=4096,
        mode=0o444,
    )
    public_key_bytes = _trusted_regular_file(
        PRODUCTION_RECEIPT_PUBLIC_KEY,
        maximum=1024,
        mode=0o444,
    )
    try:
        policy = json.loads(
            policy_bytes.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("receipt trust policy is malformed") from exc
    if not isinstance(policy, dict) or set(policy) != RECEIPT_POLICY_FIELDS:
        raise ValueError("receipt trust policy schema is invalid")
    if (
        policy.get("schemaVersion") != "1.0"
        or policy.get("algorithm") != "Ed25519"
        or policy.get("audience") != CONTENT_SCHEMA
        or policy.get("signatureDomain") != RECEIPT_SIGNATURE_DOMAIN_NAME
        or policy.get("consumerRuntimeName") != "devflow-locator"
        or policy.get("publicKeyPath") != str(PRODUCTION_RECEIPT_PUBLIC_KEY)
        or policy.get("policyPath") != str(PRODUCTION_RECEIPT_POLICY)
        or policy.get("opensslPath") != str(PRODUCTION_OPENSSL)
        or not isinstance(policy.get("publicKeySha256"), str)
        or DIGEST.fullmatch(policy["publicKeySha256"]) is None
        or not isinstance(policy.get("publicKeyFileSha256"), str)
        or DIGEST.fullmatch(policy["publicKeyFileSha256"]) is None
        or hashlib.sha256(public_key_bytes).hexdigest()
        != policy["publicKeyFileSha256"]
    ):
        raise ValueError("receipt trust policy binding is invalid")
    try:
        openssl_metadata = PRODUCTION_OPENSSL.lstat()
    except OSError as exc:
        raise ValueError("receipt signature verifier is unavailable") from exc
    if (
        PRODUCTION_OPENSSL.is_symlink()
        or not stat.S_ISREG(openssl_metadata.st_mode)
        or not os.access(PRODUCTION_OPENSSL, os.X_OK)
        or os.name == "posix"
        and (
            openssl_metadata.st_uid != 0
            or openssl_metadata.st_gid != 0
            or stat.S_IMODE(openssl_metadata.st_mode) & 0o022
        )
    ):
        raise ValueError("receipt signature verifier metadata is invalid")
    public_der = _run_openssl(
        [
            str(PRODUCTION_OPENSSL),
            "pkey",
            "-pubin",
            "-in",
            str(PRODUCTION_RECEIPT_PUBLIC_KEY),
            "-outform",
            "DER",
        ],
        maximum=ED25519_SPKI_BYTES,
    )
    public_key_sha256 = hashlib.sha256(public_der).hexdigest()
    if (
        len(public_der) != ED25519_SPKI_BYTES
        or not public_der.startswith(ED25519_SPKI_PREFIX)
        or public_key_sha256 != policy["publicKeySha256"]
    ):
        raise ValueError("receipt trust public key is invalid")
    return ReceiptTrust(
        public_key=PRODUCTION_RECEIPT_PUBLIC_KEY,
        openssl=PRODUCTION_OPENSSL,
        public_key_sha256=public_key_sha256,
    )


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{86}", value) is None:
        raise ValueError("operation receipt signature is invalid")
    try:
        signature = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError("operation receipt signature is invalid") from exc
    canonical = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    if len(signature) != ED25519_SIGNATURE_BYTES or canonical != value:
        raise ValueError("operation receipt signature is invalid")
    return signature


def _verify_receipt_signature(
    trust: ReceiptTrust,
    value: dict[str, Any],
    signature_text: Any,
) -> None:
    signature = _decode_signature(signature_text)
    signature_path: Path | None = None
    message_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="devflow-github-receipt-",
            suffix=".sig",
            delete=False,
        ) as stream:
            signature_path = Path(stream.name)
            stream.write(signature)
            stream.flush()
        signature_path.chmod(0o600)
        message = RECEIPT_SIGNATURE_DOMAIN + _canonical_json(value)
        with tempfile.NamedTemporaryFile(
            prefix="devflow-github-receipt-",
            suffix=".msg",
            delete=False,
        ) as stream:
            message_path = Path(stream.name)
            stream.write(message)
            stream.flush()
        message_path.chmod(0o600)
        _run_openssl(
            [
                str(trust.openssl),
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(trust.public_key),
                "-rawin",
                "-sigfile",
                str(signature_path),
                "-in",
                str(message_path),
            ],
            maximum=128,
        )
    finally:
        for path in (signature_path, message_path):
            if path is not None:
                with contextlib.suppress(OSError):
                    path.unlink()


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _strings(child)]
    return []


def _text(value: Any, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or CONTROL.search(value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _repository(value: Any) -> tuple[str, str]:
    if not isinstance(value, dict) or set(value) != {"owner", "repo"}:
        raise ValueError("repository schema is invalid")
    owner = _text(value["owner"], "repository owner", maximum=100)
    repo = _text(value["repo"], "repository name", maximum=100)
    if (
        OWNER.fullmatch(owner) is None
        or "--" in owner
        or REPOSITORY.fullmatch(repo) is None
        or repo in {".", ".."}
    ):
        raise ValueError("repository identity is invalid")
    return owner, repo


def _path(value: Any) -> str:
    text = _text(value, "repository path", maximum=512)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or BROKER_PATH.fullmatch(text) is None
        or path.as_posix() != text
        or text.endswith("/")
        or "//" in text
        or "\\" in text
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("repository path is unsafe")
    return text


def _canonical_base64(value: Any) -> tuple[str, bytes]:
    text = _text(value, "content_base64", maximum=1_400_000)
    if re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", text) is None:
        raise ValueError("content_base64 is malformed")
    try:
        content = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("content_base64 is malformed") from exc
    if len(content) > MAX_CONTENT_BYTES or base64.b64encode(content).decode("ascii") != text:
        raise ValueError("content_base64 is non-canonical or too large")
    return text, content


def _validate_input(artifact: dict[str, Any]) -> None:
    has_path = "path" in artifact
    has_paths = "paths" in artifact
    if has_path == has_paths:
        raise ValueError("input requires exactly one of path or paths")
    expected = {"repository", "revision", "capability", "path" if has_path else "paths"}
    if set(artifact) != expected:
        raise ValueError("input schema is invalid")
    _repository(artifact["repository"])
    revision = artifact["revision"]
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        raise ValueError("revision must be a lowercase immutable commit SHA")
    capability = artifact["capability"]
    if not isinstance(capability, str) or CAPABILITY.fullmatch(capability) is None:
        raise ValueError("capability is missing or malformed")
    raw_paths = [artifact["path"]] if has_path else artifact["paths"]
    if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= 32:
        raise ValueError("input paths are invalid")
    paths = [_path(item) for item in raw_paths]
    if len(paths) != len(set(paths)) or (has_paths and paths != sorted(paths)):
        raise ValueError("input paths are not sorted and unique")


def _validate_receipt(
    value: Any,
    *,
    trust: ReceiptTrust,
    run_id: str,
    task_id: str,
    trace_id: str,
    repository: str,
    revision: str,
) -> tuple[dict[str, str], str, str, tuple[str, ...]]:
    if not isinstance(value, dict) or set(value) != RECEIPT_FIELDS:
        raise ValueError("operation receipt schema is invalid")
    if value["schema_version"] != CONTENT_SCHEMA:
        raise ValueError("operation receipt version is unsupported")
    assignment = value["assignment"]
    authorization = value["authorization"]
    github = value["github"]
    if not isinstance(assignment, dict) or set(assignment) != ASSIGNMENT_FIELDS:
        raise ValueError("operation assignment schema is invalid")
    if not isinstance(authorization, dict) or set(authorization) != AUTHORIZATION_FIELDS:
        raise ValueError("operation authorization schema is invalid")
    if not isinstance(github, dict) or set(github) != GITHUB_FIELDS:
        raise ValueError("operation GitHub schema is invalid")
    assignment_paths = assignment["paths"]
    if (
        assignment["run_id"] != run_id
        or assignment["task_id"] != task_id
        or assignment["trace_id"] != trace_id
        or assignment["repository"] != repository
        or assignment["revision"] != revision
        or not isinstance(assignment_paths, list)
        or not 1 <= len(assignment_paths) <= 32
    ):
        raise ValueError("operation assignment does not match the result")
    paths = tuple(_path(item) for item in assignment_paths)
    if list(paths) != sorted(set(paths)):
        raise ValueError("operation assignment paths are invalid")
    owner, repo = repository.split("/", 1)
    scope_document = {
        "run_id": run_id,
        "task_id": task_id,
        "trace_id": trace_id,
        "owner": owner,
        "repo": repo,
        "revision": revision,
        "paths": list(paths),
    }
    scope_digest = hashlib.sha256(_canonical_json(scope_document)).hexdigest()
    if assignment["scope_digest"] != scope_digest:
        raise ValueError("operation assignment scope digest mismatch")
    if authorization["decision"] != "allow" or authorization["task_id"] != task_id:
        raise ValueError("operation authorization does not match the task")
    for field in ("scope_digest", "capability_digest"):
        if (
            not isinstance(authorization[field], str)
            or DIGEST.fullmatch(authorization[field]) is None
        ):
            raise ValueError(f"operation {field} is invalid")
    authorized_at = authorization["authorized_at"]
    if isinstance(authorized_at, bool) or not isinstance(authorized_at, int) or authorized_at < 1:
        raise ValueError("operation authorization time is invalid")
    if github["repository"] != repository or github["revision"] != revision:
        raise ValueError("operation repository scope does not match the result")
    path = _path(github["path"])
    if path not in paths:
        raise ValueError("operation path is outside the signed assignment")
    object_sha = github["object_sha"]
    if not isinstance(object_sha, str) or REVISION.fullmatch(object_sha) is None:
        raise ValueError("GitHub object SHA is invalid")
    if github["encoding"] != "base64":
        raise ValueError("GitHub content encoding is unsupported")
    _, content = _canonical_base64(github["content_base64"])
    response_digest = value["response_digest"]
    receipt_signature = value["receipt_signature"]
    receipt_key_sha256 = value["receipt_key_sha256"]
    if not isinstance(response_digest, str) or DIGEST.fullmatch(response_digest) is None:
        raise ValueError("operation response digest is invalid")
    if receipt_key_sha256 != trust.public_key_sha256:
        raise ValueError("operation receipt key is not deployment-trusted")
    unsigned = {
        key: item
        for key, item in value.items()
        if key not in {"response_digest", "receipt_signature"}
    }
    if hashlib.sha256(_canonical_json(unsigned)).hexdigest() != response_digest:
        raise ValueError("operation response digest mismatch")
    signed = {key: item for key, item in value.items() if key != "receipt_signature"}
    _verify_receipt_signature(trust, signed, receipt_signature)
    evidence = {
        "path": path,
        "object_sha": object_sha,
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "response_digest": response_digest,
    }
    return (
        evidence,
        authorization["scope_digest"],
        authorization["capability_digest"],
        paths,
    )


def _validate_output(artifact: dict[str, Any]) -> None:
    if set(artifact) != ROOT_OUTPUT_FIELDS:
        raise ValueError("output schema is invalid")
    run_id = _text(artifact["run_id"], "run_id")
    task_id = _text(artifact["task_id"], "task_id")
    trace_id = _text(artifact["trace_id"], "trace_id")
    if trace_id != f"{run_id}:{task_id}":
        raise ValueError("output trace_id does not bind run_id and task_id")
    owner, repo = _repository(artifact["repository"])
    revision = artifact["revision"]
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        raise ValueError("output revision is invalid")
    if artifact["status"] != "success":
        raise ValueError("GitHubEvidence output status must be success")
    operations = artifact["operations"]
    evidence = artifact["evidence"]
    if (
        not isinstance(operations, list)
        or not 1 <= len(operations) <= 32
        or not isinstance(evidence, list)
        or len(evidence) != len(operations)
    ):
        raise ValueError("operations and evidence must be equal non-empty lists")
    expected_evidence: list[dict[str, str]] = []
    scope_digests: set[str] = set()
    capability_digests: set[str] = set()
    assignment_paths: set[tuple[str, ...]] = set()
    trust = _load_receipt_trust()
    for operation in operations:
        summary, scope_digest, capability_digest, signed_paths = _validate_receipt(
            operation,
            trust=trust,
            run_id=run_id,
            task_id=task_id,
            trace_id=trace_id,
            repository=f"{owner}/{repo}",
            revision=revision,
        )
        expected_evidence.append(summary)
        scope_digests.add(scope_digest)
        capability_digests.add(capability_digest)
        assignment_paths.add(signed_paths)
    if len(scope_digests) != 1 or len(capability_digests) != 1:
        raise ValueError("operations do not share one assigned capability scope")
    if evidence != expected_evidence or len({item["path"] for item in expected_evidence}) != len(
        expected_evidence
    ):
        raise ValueError("evidence summaries do not exactly match operation receipts")
    if (
        len(assignment_paths) != 1
        or tuple(sorted(item["path"] for item in expected_evidence))
        != next(iter(assignment_paths))
    ):
        raise ValueError("evidence paths do not exactly close the signed assignment")
    digest = artifact["digest"]
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        raise ValueError("output digest is invalid")
    unsigned = {key: value for key, value in artifact.items() if key != "digest"}
    if hashlib.sha256(_canonical_json(unsigned)).hexdigest() != digest:
        raise ValueError("output digest mismatch")


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"input", "output"}:
        print("usage: validate.py <input|output> <artifact.json>", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    contract = load_contract(root / "references" / "contract.yaml")
    try:
        artifact_path = Path(sys.argv[2])
        if artifact_path.stat().st_size > 3_000_000:
            raise ValueError("artifact is too large")
        artifact = json.loads(
            artifact_path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("artifact cannot be loaded as strict JSON") from exc
    if not isinstance(artifact, dict):
        raise ValueError("artifact root must be an object")
    if any(SECRET.search(text) for text in _strings(artifact)):
        raise ValueError("artifact contains secret-shaped content")
    if sys.argv[1] == "input":
        _validate_input(artifact)
    else:
        _validate_output(artifact)
    print(json.dumps({"valid": True, "skill": contract["name"], "mode": sys.argv[1]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
