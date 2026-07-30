from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from base64 import urlsafe_b64encode
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from scripts.github_scope_broker import (
    CapabilityCodec,
    ContentRequest,
    GitHubContent,
    OpenSSLEd25519ReceiptSigner,
    Scope,
    content_receipt,
)

ROOT = Path(__file__).parents[1]
AUTHORIZER = ROOT / "skills" / "github-evidence" / "scripts" / "authorize_tool.py"
VALIDATOR = ROOT / "skills" / "github-evidence" / "scripts" / "validate.py"
REVISION = "a" * 40
NOW = datetime(2026, 7, 27, 10, 5, tzinfo=timezone.utc)
CAPABILITY = (
    urlsafe_b64encode(b'{"grant":"test"}').rstrip(b"=").decode("ascii")
    + "."
    + urlsafe_b64encode(b"s" * 32).rstrip(b"=").decode("ascii")
)
OPENSSL = next(
    path
    for path in (
        Path(r"C:\Program Files\Git\usr\bin\openssl.exe"),
        Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe"),
        Path("/usr/bin/openssl"),
    )
    if path.is_file()
)


@dataclass(frozen=True)
class ReceiptFixture:
    signer: OpenSSLEd25519ReceiptSigner
    validator: Path
    private_key: Path
    public_key: Path


@pytest.fixture
def receipt_fixture(tmp_path: Path) -> ReceiptFixture:
    trust_root = tmp_path / "test-only-receipt-trust"
    trust_root.mkdir()
    private_key = trust_root / "test-only-receipt-ed25519.pem"
    public_key = trust_root / "test-only-receipt-ed25519.pub"
    policy_path = trust_root / "receipt-policy.json"
    subprocess.run(
        [
            str(OPENSSL),
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            str(OPENSSL),
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
        check=True,
        capture_output=True,
    )
    private_key.chmod(0o400)
    public_der = subprocess.run(
        [
            str(OPENSSL),
            "pkey",
            "-pubin",
            "-in",
            str(public_key),
            "-outform",
            "DER",
        ],
        check=True,
        capture_output=True,
    ).stdout
    policy = {
        "schemaVersion": "1.0",
        "algorithm": "Ed25519",
        "audience": "devflow.github-content-response/v2",
        "signatureDomain": "devflow.github-content-receipt/v2",
        "consumerRuntimeName": "devflow-locator",
        "publicKeyPath": str(public_key),
        "publicKeySha256": hashlib.sha256(public_der).hexdigest(),
        "publicKeyFileSha256": hashlib.sha256(public_key.read_bytes()).hexdigest(),
        "policyPath": str(policy_path),
        "opensslPath": str(OPENSSL),
    }
    policy_path.write_text(
        json.dumps(policy, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    public_key.chmod(0o444)
    policy_path.chmod(0o444)

    skill_copy = tmp_path / "github-evidence"
    shutil.copytree(ROOT / "skills" / "github-evidence", skill_copy)
    validator = skill_copy / "scripts" / "validate.py"
    source = validator.read_text(encoding="utf-8")
    source = source.replace(
        'PRODUCTION_RECEIPT_PUBLIC_KEY = Path(\n'
        '    "/etc/devflow/github-evidence/receipt-ed25519.pub"\n'
        ")",
        f"PRODUCTION_RECEIPT_PUBLIC_KEY = Path({str(public_key)!r})",
    )
    source = source.replace(
        'PRODUCTION_RECEIPT_POLICY = Path(\n'
        '    "/etc/devflow/github-evidence/receipt-policy.json"\n'
        ")",
        f"PRODUCTION_RECEIPT_POLICY = Path({str(policy_path)!r})",
    )
    source = source.replace(
        'PRODUCTION_OPENSSL = Path("/usr/bin/openssl")',
        f"PRODUCTION_OPENSSL = Path({str(OPENSSL)!r})",
    )
    validator.write_text(source, encoding="utf-8")
    return ReceiptFixture(
        signer=OpenSSLEd25519ReceiptSigner(private_key, openssl_path=OPENSSL),
        validator=validator,
        private_key=private_key,
        public_key=public_key,
    )


def _policy_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("github_evidence_policy", AUTHORIZER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _digest(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _envelope(
    *,
    owner: str = "example",
    repo: str = "repo",
    revision: str = REVISION,
    path: str | None = "src/app.py",
    paths: list[str] | None = None,
    capability: str = CAPABILITY,
    producer: str = "TeamLeader",
    created_at: str = "2026-07-27T10:00:00Z",
) -> dict[str, Any]:
    inline: dict[str, Any] = {
        "repository": {"owner": owner, "repo": repo},
        "revision": revision,
        "capability": capability,
    }
    if paths is not None:
        inline["paths"] = paths
    elif path is not None:
        inline["path"] = path
    artifact = {
        "type": "SkillInvocation",
        "schema_version": "1.0",
        "inline": inline,
        "sha256": _digest(inline),
    }
    return {
        "envelope_version": "1.0",
        "run_id": "run-1",
        "issue_id": 7,
        "task_id": "7-1-locator",
        "producer": producer,
        "consumer": "LocatorAgent",
        "skill": "github-evidence",
        "trace_id": "trace-1",
        "idempotency_key": "run-1:7-1-locator:github-evidence",
        "created_at": created_at,
        "status": "ready",
        "artifact": artifact,
    }


def _authorize(
    *,
    envelope: dict[str, Any] | None = None,
    tool: str = "devflow-github-readonly.get_file_contents",
    owner: str = "example",
    repo: str = "repo",
    path: str = "src/app.py",
    revision: str = REVISION,
    task_id: str = "7-1-locator",
    capability: str = CAPABILITY,
) -> Any:
    return _policy_module().authorize(
        "locator",
        tool,
        envelope=_envelope() if envelope is None else envelope,
        owner=owner,
        repo=repo,
        path=path,
        revision=revision,
        task_id=task_id,
        capability=capability,
        now=NOW,
    )


def test_locator_allows_only_the_envelope_bound_read() -> None:
    decision = _authorize()

    assert decision.allowed
    assert decision.code == "ALLOW_READ"
    assert decision.risk == "read_only"
    assert len(decision.scope_digest) == 64


def test_wrong_repository_and_path_cannot_override_assignment() -> None:
    wrong_repo = _authorize(repo="other")
    wrong_path = _authorize(path="src/other.py")
    multi_path = _authorize(
        envelope=_envelope(path=None, paths=["README.md", "src/app.py"]),
        path="README.md",
    )

    assert not wrong_repo.allowed and wrong_repo.code == "MCP_SCOPE_MISMATCH"
    assert not wrong_path.allowed and wrong_path.code == "MCP_SCOPE_MISMATCH"
    assert multi_path.allowed


def test_task_and_capability_are_part_of_the_exact_scope() -> None:
    wrong_task = _authorize(task_id="different-task")
    wrong_capability = _authorize(capability=CAPABILITY[:-1] + "A")

    assert not wrong_task.allowed and wrong_task.code == "MCP_SCOPE_MISMATCH"
    assert not wrong_capability.allowed and wrong_capability.code == "MCP_SCOPE_MISMATCH"


def test_tampered_inline_digest_is_rejected_before_scope_use() -> None:
    envelope = _envelope()
    envelope["artifact"]["inline"]["repository"]["repo"] = "other"

    decision = _authorize(envelope=envelope)

    assert not decision.allowed
    assert decision.code == "HANDOFF_DIGEST_MISMATCH"
    assert decision.scope_digest == ""


def test_wrong_consumer_skill_and_status_have_stable_codes() -> None:
    for field, value, code in (
        ("consumer", "CoderAgent", "HANDOFF_CONSUMER_MISMATCH"),
        ("skill", "code-root-cause", "HANDOFF_SKILL_MISMATCH"),
        ("status", "blocked", "HANDOFF_STATUS_INVALID"),
    ):
        envelope = _envelope()
        envelope[field] = value
        decision = _authorize(envelope=envelope)
        assert not decision.allowed
        assert decision.code == code


def test_producer_and_freshness_are_not_self_asserted_ambient_authority() -> None:
    attacker = _authorize(envelope=_envelope(producer="attacker"))
    stale = _authorize(envelope=_envelope(created_at=(NOW - timedelta(hours=1)).isoformat()))
    future = _authorize(envelope=_envelope(created_at=(NOW + timedelta(minutes=2)).isoformat()))

    assert not attacker.allowed and attacker.code == "HANDOFF_PRODUCER_MISMATCH"
    assert not stale.allowed and stale.code == "HANDOFF_EXPIRED"
    assert not future.allowed and future.code == "HANDOFF_EXPIRED"


def test_missing_or_malformed_envelope_fails_closed() -> None:
    policy = _policy_module()
    missing = policy.authorize(
        "locator",
        "devflow-github-readonly.get_file_contents",
        envelope=None,
        owner="example",
        repo="repo",
        path="src/app.py",
        revision=REVISION,
        task_id="7-1-locator",
        capability=CAPABILITY,
    )
    malformed = _envelope()
    del malformed["trace_id"]

    assert not missing.allowed and missing.code == "HANDOFF_REQUIRED"
    rejected = _authorize(envelope=malformed)
    assert not rejected.allowed and rejected.code == "HANDOFF_INVALID"


def test_mutable_revision_is_rejected_in_assignment_and_call() -> None:
    mutable_assignment = _envelope(revision="main")
    mutable_call = _authorize(revision="main")

    assigned = _authorize(envelope=mutable_assignment, revision="main")
    assert not assigned.allowed and assigned.code == "REVISION_REQUIRED"
    assert not mutable_call.allowed and mutable_call.code == "REVISION_REQUIRED"


def test_mutation_is_denied_even_with_a_valid_envelope() -> None:
    decision = _authorize(tool="github:push_files")

    assert not decision.allowed
    assert decision.code == "MCP_TOOL_DENIED"


def test_unknown_profile_and_lookalike_read_tool_are_denied() -> None:
    policy = _policy_module()
    reviewer = policy.authorize(
        "reviewer",
        "devflow-github-readonly.get_file_contents",
        envelope=_envelope(),
    )
    lookalike = _authorize(tool="untrusted-gateway.get_file_contents")

    assert not reviewer.allowed and reviewer.code == "UNKNOWN_PROFILE"
    assert not lookalike.allowed and lookalike.code == "MCP_TOOL_DENIED"


def test_invalid_assignment_and_call_paths_fail_closed() -> None:
    for path in (
        "../secret",
        "/etc/passwd",
        ".",
        "src/",
        "src//app.py",
        "src\\app.py",
        "src/%2e%2e/secret",
        "src/app.py?ref=main",
        "src/app.py#fragment",
        "src/app file.py",
        "文件.py",
        "src/app.py\n--repo=other",
    ):
        assignment = _authorize(envelope=_envelope(path=path), path=path)
        call = _authorize(path=path)
        assert not assignment.allowed and assignment.code == "MCP_SCOPE_INVALID"
        assert not call.allowed and call.code == "MCP_SCOPE_INVALID"


def test_assignment_scope_uses_the_same_canonical_surface_as_the_broker() -> None:
    uppercase_revision = _authorize(envelope=_envelope(revision="A" * 40), revision="A" * 40)
    unsorted_paths = _authorize(
        envelope=_envelope(path=None, paths=["src/app.py", "README.md"]),
        path="README.md",
    )
    invalid_owner = _authorize(envelope=_envelope(owner="bad_owner"))

    assert not uppercase_revision.allowed and uppercase_revision.code == "REVISION_REQUIRED"
    assert not unsorted_paths.allowed and unsorted_paths.code == "MCP_SCOPE_INVALID"
    assert not invalid_owner.allowed and invalid_owner.code == "MCP_SCOPE_INVALID"


def test_scope_digest_binds_envelope_trace_and_idempotency() -> None:
    first = _authorize()
    changed_trace = _envelope()
    changed_trace["trace_id"] = "trace-2"
    changed_idempotency = _envelope()
    changed_idempotency["idempotency_key"] = "different-key"

    second = _authorize(envelope=changed_trace)
    third = _authorize(envelope=changed_idempotency)

    assert first.allowed and second.allowed and third.allowed
    assert len({first.scope_digest, second.scope_digest, third.scope_digest}) == 3


def test_authorizer_cli_runs_without_site_packages_and_requires_envelope(
    tmp_path: Path,
) -> None:
    envelope_path = tmp_path / "envelope.json"
    envelope = _envelope(created_at=datetime.now(timezone.utc).isoformat())
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
    base = [
        sys.executable,
        "-S",
        str(AUTHORIZER),
        "--profile",
        "locator",
        "--tool",
        "devflow-github-readonly.get_file_contents",
        "--owner",
        "example",
        "--repo",
        "repo",
        "--path",
        "src/app.py",
        "--revision",
        REVISION,
        "--task-id",
        "7-1-locator",
        "--capability",
        CAPABILITY,
    ]
    allowed = subprocess.run(
        [*base, "--envelope", str(envelope_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    missing = subprocess.run(
        base,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert allowed.returncode == 0
    assert json.loads(allowed.stdout)["code"] == "ALLOW_READ"
    assert missing.returncode == 3
    assert json.loads(missing.stdout)["code"] == "HANDOFF_REQUIRED"
    assert "approval-ref" not in allowed.stdout + allowed.stderr


def test_authorizer_cli_rejects_malformed_and_duplicate_json(tmp_path: Path) -> None:
    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text("{", encoding="utf-8")
    valid = json.dumps(_envelope(), separators=(",", ":"))
    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text(
        valid.replace(
            '"consumer":"LocatorAgent"',
            '"consumer":"LocatorAgent","consumer":"LocatorAgent"',
        ),
        encoding="utf-8",
    )
    base = [
        sys.executable,
        "-S",
        str(AUTHORIZER),
        "--profile",
        "locator",
        "--tool",
        "devflow-github-readonly.get_file_contents",
        "--owner",
        "example",
        "--repo",
        "repo",
        "--path",
        "src/app.py",
        "--revision",
        REVISION,
        "--task-id",
        "7-1-locator",
        "--capability",
        CAPABILITY,
    ]

    for path in (malformed_path, duplicate_path):
        result = subprocess.run(
            [*base, "--envelope", str(path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 3
        assert json.loads(result.stdout)["code"] == "HANDOFF_INVALID"


def test_envelope_surface_is_strict_and_inline_only() -> None:
    unknown = _envelope()
    unknown["extra"] = True
    referenced = _envelope()
    referenced["artifact"] = {
        "type": "SkillInvocation",
        "schema_version": "1.0",
        "ref": "shared://assignment",
        "sha256": "0" * 64,
    }
    both_path_forms = _envelope()
    both_path_forms["artifact"]["inline"]["paths"] = ["src/app.py"]
    both_path_forms["artifact"]["sha256"] = _digest(both_path_forms["artifact"]["inline"])

    for envelope in (unknown, referenced, both_path_forms):
        decision = _authorize(envelope=envelope)
        assert not decision.allowed
        assert decision.code == "HANDOFF_INVALID"


def test_scope_digest_is_stable_for_equivalent_tool_qualifiers() -> None:
    first = _authorize(tool="devflow-github-readonly.get_file_contents")
    second = _authorize(tool="github:get_file_contents")

    assert first.allowed and second.allowed
    assert first.scope_digest == second.scope_digest


def test_recomputed_digest_does_not_authorize_a_different_repository() -> None:
    envelope = deepcopy(_envelope())
    inline = envelope["artifact"]["inline"]
    inline["repository"]["repo"] = "other"
    envelope["artifact"]["sha256"] = _digest(inline)

    decision = _authorize(envelope=envelope)

    assert not decision.allowed
    assert decision.code == "MCP_SCOPE_MISMATCH"


def _broker_receipt(
    fixture: ReceiptFixture,
    *,
    run_id: str = "run-1",
    task_id: str = "7-1-locator",
    path: str = "src/app.py",
) -> dict[str, Any]:
    trace_id = f"{run_id}:{task_id}"
    codec = CapabilityCodec(b"test-only-capability-hmac-key-32-bytes")
    capability, claims = codec.issue(
        Scope.from_issuer_document(
            {
                "run_id": run_id,
                "task_id": task_id,
                "trace_id": trace_id,
                "owner": "example",
                "repo": "repo",
                "revision": REVISION,
                "paths": [path],
            }
        ),
        now=1_722_074_390,
        jti="0" * 32,
    )
    return content_receipt(
        signer=fixture.signer,
        capability=capability,
        claims=claims,
        request=ContentRequest(
            task_id=task_id,
            owner="example",
            repo="repo",
            path=path,
            revision=REVISION,
        ),
        content=GitHubContent(
            object_sha="c" * 40,
            content_base64="cHJpbnQoJ29rJykK",
        ),
        authorized_at=1_722_074_400,
    )


def _github_output(
    fixture: ReceiptFixture,
    *,
    receipt_run_id: str = "run-1",
    receipt_task_id: str = "7-1-locator",
    receipt_path: str = "src/app.py",
) -> dict[str, Any]:
    receipt = _broker_receipt(
        fixture,
        run_id=receipt_run_id,
        task_id=receipt_task_id,
        path=receipt_path,
    )
    artifact: dict[str, Any] = {
        "run_id": "run-1",
        "task_id": "7-1-locator",
        "repository": {"owner": "example", "repo": "repo"},
        "revision": REVISION,
        "operations": [receipt],
        "evidence": [
            {
                "path": "src/app.py",
                "object_sha": "c" * 40,
                "content_sha256": hashlib.sha256(b"print('ok')\n").hexdigest(),
                "response_digest": receipt["response_digest"],
            }
        ],
        "trace_id": "run-1:7-1-locator",
        "status": "success",
    }
    artifact["digest"] = _digest(artifact)
    return artifact


def _run_validator(
    tmp_path: Path,
    artifact: dict[str, Any],
    mode: str,
    *,
    validator: Path = VALIDATOR,
) -> subprocess.CompletedProcess[str]:
    artifact_path = tmp_path / f"{mode}.json"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-S", str(validator), mode, str(artifact_path)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_validator_accepts_exact_input_and_broker_receipt_output(
    tmp_path: Path,
    receipt_fixture: ReceiptFixture,
) -> None:
    input_artifact = _envelope()["artifact"]["inline"]
    accepted_input = _run_validator(tmp_path, input_artifact, "input")
    accepted_output = _run_validator(
        tmp_path,
        _github_output(receipt_fixture),
        "output",
        validator=receipt_fixture.validator,
    )

    assert accepted_input.returncode == 0, accepted_input.stderr
    assert accepted_output.returncode == 0, accepted_output.stderr


def test_validator_recomputes_every_evidence_digest(
    tmp_path: Path,
    receipt_fixture: ReceiptFixture,
) -> None:
    mutations: tuple[Callable[[dict[str, Any]], object], ...] = (
        lambda value: value["operations"][0].__setitem__("response_digest", "0" * 64),
        lambda value: value["evidence"][0].__setitem__("object_sha", "e" * 40),
        lambda value: value.__setitem__("digest", "0" * 64),
        lambda value: value["operations"][0]["authorization"].__setitem__(
            "task_id", "another-task"
        ),
    )
    for mutate in mutations:
        artifact = _github_output(receipt_fixture)
        mutate(artifact)
        completed = _run_validator(
            tmp_path,
            artifact,
            "output",
            validator=receipt_fixture.validator,
        )
        assert completed.returncode != 0


def test_validator_rejects_capability_or_secret_leak_in_output(
    tmp_path: Path,
    receipt_fixture: ReceiptFixture,
) -> None:
    artifact = _github_output(receipt_fixture)
    artifact["unexpected_capability"] = CAPABILITY
    rejected_capability = _run_validator(
        tmp_path,
        artifact,
        "output",
        validator=receipt_fixture.validator,
    )
    artifact = _github_output(receipt_fixture)
    artifact["evidence"][0]["path"] = "ghp_" + "A" * 36
    rejected_secret = _run_validator(
        tmp_path,
        artifact,
        "output",
        validator=receipt_fixture.validator,
    )

    assert rejected_capability.returncode != 0
    assert rejected_secret.returncode != 0


def test_validator_rejects_forged_cross_task_and_cross_path_receipts(
    tmp_path: Path,
    receipt_fixture: ReceiptFixture,
) -> None:
    forged = _github_output(receipt_fixture)
    forged["operations"][0]["receipt_signature"] = "A" * 86
    forged["digest"] = _digest(
        {key: value for key, value in forged.items() if key != "digest"}
    )
    cross_task = _github_output(
        receipt_fixture,
        receipt_task_id="8-1-locator",
    )
    cross_path = _github_output(
        receipt_fixture,
        receipt_path="src/other.py",
    )
    for artifact in (forged, cross_task, cross_path):
        completed = _run_validator(
            tmp_path,
            artifact,
            "output",
            validator=receipt_fixture.validator,
        )
        assert completed.returncode != 0


def test_validator_does_not_accept_a_caller_selected_public_key(
    tmp_path: Path,
    receipt_fixture: ReceiptFixture,
) -> None:
    attacker_private = tmp_path / "attacker.pem"
    subprocess.run(
        [
            str(OPENSSL),
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(attacker_private),
        ],
        check=True,
        capture_output=True,
    )
    attacker = ReceiptFixture(
        signer=OpenSSLEd25519ReceiptSigner(attacker_private, openssl_path=OPENSSL),
        validator=receipt_fixture.validator,
        private_key=attacker_private,
        public_key=receipt_fixture.public_key,
    )
    completed = _run_validator(
        tmp_path,
        _github_output(attacker),
        "output",
        validator=receipt_fixture.validator,
    )
    assert completed.returncode != 0
