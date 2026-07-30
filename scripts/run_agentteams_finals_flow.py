#!/usr/bin/env python3
"""Run one fail-closed AgentTeams/TeamHarness conformance fixture.

The default mode only prints a deterministic plan and never contacts
Kubernetes.  Execute mode requires a fixed confirmation phrase and a fresh
project identifier.

This driver deliberately distinguishes two claims:

* AgentTeams, TeamHarness, role-scoped packaged validators, FileSync and the
  task/project state machines are exercised for real.
* The stage artifacts are pre-generated deterministic fixtures carrying
  revision metadata.  The driver performs no model call and no repository
  checkout, GitHub MCP call, live Broker-receipt verification, or repository
  mutation, and its result is not a repository benchmark.

The deterministic Locator source contains a digest-valid GitHubEvidence
fixture inside the exact TeamLeader SkillInvocation required by
``code-root-cause``.  It proves source/schema binding only; it is not evidence
of a live GitHub Broker call.  The Reviewer is candidate-only and always emits
``pr_url=null``.  A red test remains typed ``TestEvidence`` with ``retry``
status, while execution failures use the unified ``SkillFailure`` contract and
route only to TeamLeader.

The fixed upstream TeamHarness release cannot accept ``FAILED`` as a completed
project node.  Therefore the first red Tester result is checked as effective,
recorded as a Loop ``replan`` decision, and retained as a ``revision`` node.
The same project then routes a second Coder candidate and a green Tester run.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from devflow.security.secrets import contains_secret

try:
    from scripts.reconcile_teamharness_openclaw import (
        CONTAINER_NAME,
        NAMESPACE,
        TEAM_NAME,
        ReconcileError,
        Target,
        discover_targets,
    )
    from scripts.run_agentteams_github_success_path import (
        MAX_KUBECTL_ARGUMENT_BYTES,
        MAX_KUBECTL_ARGV_BYTES,
        REMOTE_STDIN_BOOTSTRAP,
        _CommandRunner,
        _remote_frame,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from reconcile_teamharness_openclaw import (  # type: ignore[no-redef]
        CONTAINER_NAME,
        NAMESPACE,
        TEAM_NAME,
        ReconcileError,
        Target,
        discover_targets,
    )
    from run_agentteams_github_success_path import (  # type: ignore[no-redef]
        MAX_KUBECTL_ARGUMENT_BYTES,
        MAX_KUBECTL_ARGV_BYTES,
        REMOTE_STDIN_BOOTSTRAP,
        _CommandRunner,
        _remote_frame,
    )

ROOT = Path(__file__).resolve().parents[1]
CONFIRMATION = "EXECUTE_FRESH_FINALS_SIX_STAGE_FLOW"
PROJECT_PREFIX = "devflow-finals-"
RISK_TIER = "T2"
SOURCE = "operator-driven"
ISSUE_ID = 7
MAX_FIXTURE_GENERATION_ATTEMPTS = 3
PROJECT_TITLE = "DevFlow AgentTeams conformance recovery fixture"
REPOSITORY_OWNER = "YZYY95K"
REPOSITORY_NAME = "test"
REPOSITORY_REVISION = "cc6a79d6b633be640a78eadf081469d0038f2dd5"
SOURCE_PATH = "examples/calculator_bug/calculator.py"
TEST_PATH = "examples/calculator_bug/tests/test_calculator.py"

SKILL_FAILURE_PROBE_POLICIES: dict[str, dict[str, Any]] = {
    "issue-classifier": {
        "code": "EXPERIENCE_UNAVAILABLE",
        "retryable": True,
        "retry_count": 0,
        "max_attempts": 1,
        "event": "triage.degraded",
    },
    "code-root-cause": {
        "code": "FILE_UNAVAILABLE",
        "retryable": True,
        "retry_count": 0,
        "max_attempts": 1,
        "event": "locator.degraded",
    },
    "patch-generator": {
        "code": "BOUNDARY_VIOLATION",
        "retryable": False,
        "retry_count": 0,
        "max_attempts": 0,
        "event": "boundary.violation",
    },
    "test-runner": {
        "code": "ISOLATION_UNAVAILABLE",
        "retryable": False,
        "retry_count": 0,
        "max_attempts": 0,
        "event": "test.error",
    },
    "pr-reviewer": {
        "code": "EVIDENCE_INVALID",
        "retryable": False,
        "retry_count": 0,
        "max_attempts": 0,
        "event": "review.failed",
    },
    "experience-distiller": {
        "code": "STORE_UNAVAILABLE",
        "retryable": True,
        "retry_count": 0,
        "max_attempts": 2,
        "event": "experience.degraded",
    },
}
SOURCE_BOUND_FAILURE_PROBE_SKILLS = (
    "issue-classifier",
    "code-root-cause",
    "pr-reviewer",
    "experience-distiller",
)

LEADER_ROLE = "devflow-lead"
TRIAGE_ROLE = "devflow-triage"
LOCATOR_ROLE = "devflow-locator"
CODER_ROLE = "devflow-coder"
TESTER_ROLE = "devflow-tester"
REVIEWER_ROLE = "devflow-reviewer"
WORKER_ROLES = (
    TRIAGE_ROLE,
    LOCATOR_ROLE,
    CODER_ROLE,
    TESTER_ROLE,
    REVIEWER_ROLE,
)
ALL_ROLES = (LEADER_ROLE, *WORKER_ROLES)
ROLE_TO_AGENT = {
    TRIAGE_ROLE: "TriageAgent",
    LOCATOR_ROLE: "LocatorAgent",
    CODER_ROLE: "CoderAgent",
    TESTER_ROLE: "TesterAgent",
    REVIEWER_ROLE: "ReviewerAgent",
}

STAGE_ORDER = (
    "triage",
    "locator",
    "coder-1",
    "tester-1",
    "coder-2",
    "tester-2",
    "reviewer",
    "experience",
)
STAGE_ROLE = {
    "triage": TRIAGE_ROLE,
    "locator": LOCATOR_ROLE,
    "coder-1": CODER_ROLE,
    "tester-1": TESTER_ROLE,
    "coder-2": CODER_ROLE,
    "tester-2": TESTER_ROLE,
    "reviewer": REVIEWER_ROLE,
    "experience": REVIEWER_ROLE,
}
STAGE_SKILL = {
    "triage": "issue-classifier",
    "locator": "code-root-cause",
    "coder-1": "patch-generator",
    "tester-1": "test-runner",
    "coder-2": "patch-generator",
    "tester-2": "test-runner",
    "reviewer": "pr-reviewer",
    "experience": "experience-distiller",
}
STAGE_TITLE = {
    "triage": "Classify the fixed calculator issue",
    "locator": "Locate the revision-pinned root cause",
    "coder-1": "Generate candidate one",
    "tester-1": "Test candidate one in isolation",
    "coder-2": "Generate candidate two from bounded failure evidence",
    "tester-2": "Test candidate two in isolation",
    "reviewer": "Review the green candidate",
    "experience": "Distill verified terminal experience",
}
INITIAL_STAGES = ("triage", "locator", "coder-1", "tester-1")
RECOVERY_STAGES = ("coder-2", "tester-2", "reviewer", "experience")
SUCCESS_STAGES = (
    "triage",
    "locator",
    "coder-1",
    "coder-2",
    "tester-2",
    "reviewer",
    "experience",
)

PLAN_STAGES = (
    "attest-six-fixed-runtimes-and-role-scoped-skills",
    "prove-project-and-eight-task-identifiers-are-fresh",
    "create-one-t2-loop-project",
    "plan-triage-locator-coder1-tester1",
    "create-one-private-five-worker-task-room",
    "delegate-digest-bound-ed25519-attested-handoffs",
    "ack-each-assignment-idempotently",
    "validate-each-result-against-its-exact-source-with-the-packaged-skill",
    "submit-each-result-and-prove-idempotent-replay",
    "reject-one-conflicting-replay-per-task",
    "leader-check-and-accept-triage-locator-coder1",
    "run-candidate-one-in-a-disposable-python-workspace",
    "leader-check-effective-failed-tester1",
    "record-loop-iteration-one-as-replan",
    "replan-same-project-with-tester1-revision-and-recovery-branch",
    "enforce-one-three-attempt-fixture-generation-budget",
    "route-tester1-failure-through-leader-to-coder2",
    "run-candidate-two-in-a-disposable-python-workspace",
    "leader-check-and-accept-green-tester2",
    "review-only-the-digest-matched-green-candidate",
    "distill-only-a-digest-valid-terminal-receipt",
    "record-loop-iteration-two-as-stop-success",
    "complete-project-send-final-room-report-then-mark-requester-report-sent",
    "push-project-state-and-stat-all-result-signatures",
    "read-back-completed-project-loop-and-terminal-node-states",
)

SAFE_PROJECT = re.compile(r"^devflow-finals-[a-z0-9](?:[a-z0-9-]{0,25}[a-z0-9])?$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
MATRIX_USER = re.compile(r"^@([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?):([^:\s]+)$")
MATRIX_ROOM = re.compile(r"^![^\s:]{1,255}:[^\s]{1,255}$")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[^\s]+)",
    re.IGNORECASE,
)
PUBLIC_FORBIDDEN_KEYS = frozenset(
    {
        "authorization",
        "capability",
        "content",
        "privateKey",
        "private_key",
        "roomId",
        "room_id",
        "signature",
        "spec",
    }
)

INTEGRITY_POLICY = "agentteams-bwrap-tests/v1"
POLICY_DIGEST = "e1527ec714370ab983443b14559953d1a0d6a0a4d838930a120c3559f095fe13"
ISOLATION_BOUNDARY = (
    "linux-bubblewrap-unshare-all-cap-drop-process-boundary-not-node-root-or-kernel"
)
PORTABLE_POLICY_DIGEST = (
    "e30d5b49b5bbde322301604354d21f604687483b54d1b4dd0f2e86473462516c"
)
PORTABLE_ISOLATION_BOUNDARY = (
    "stdlib-temporary-directory-process-only-not-os-sandbox"
)
TEST_RECEIPT_SCHEMA = "devflow.test-execution-receipt/v1"
TEST_RECEIPT_DOMAIN = b"devflow.test-execution-receipt/v1\0"
TEST_RECEIPT_ISSUER = "devflow-tester-cicd"
TEST_RECEIPT_AUDIENCE = "devflow-teamharness"
TEST_RECEIPT_TTL_SECONDS = 120
TEST_REPOSITORY_ARCHIVE_SHA256 = hashlib.sha256(
    b"devflow-finals-conformance-repository-archive/v1"
).hexdigest()
TEST_REPOSITORY_MANIFEST_SHA256 = hashlib.sha256(
    b"devflow-finals-conformance-repository-manifest/v1"
).hexdigest()
TEST_CI_SERVER_SHA256 = hashlib.sha256(
    b"devflow-finals-conformance-ci-server/v1"
).hexdigest()
TEST_CI_POLICY_SHA256 = hashlib.sha256(
    b"devflow-finals-conformance-ci-policy/v1"
).hexdigest()
TEST_COMMAND = ("python3", "-m", "unittest", "discover", "-s", "tests")
ORIGINAL_SOURCE = '''"""Tiny calculator used by the reproducible DevFlow demo."""


def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a - b
'''
CANDIDATE_ONE_SOURCE = '''"""Tiny calculator used by the reproducible DevFlow demo."""


def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a + b + 1
'''
CANDIDATE_TWO_SOURCE = '''"""Tiny calculator used by the reproducible DevFlow demo."""


def add(a: int, b: int) -> int:
    """Return the sum of two integers."""
    return a + b
'''
TEST_SOURCE = '''"""Regression test for the bundled calculator issue."""

import unittest

from calculator import add


class CalculatorTests(unittest.TestCase):
    def test_add(self) -> None:
        self.assertEqual(add(2, 3), 5)


if __name__ == "__main__":
    unittest.main()
'''


class DriverError(RuntimeError):
    """A stable, non-sensitive driver failure."""

    def __init__(self, code: str, stage: str) -> None:
        super().__init__(f"{stage}:{code}")
        self.code = code
        self.stage = stage


def _reject_constant(_value: str) -> None:
    raise ValueError("non-standard JSON constant")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = child
    return value


def _strict_loads(value: str) -> Any:
    return json.loads(
        value,
        object_pairs_hook=_strict_object,
        parse_constant=_reject_constant,
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_text(value: Any) -> str:
    return _canonical_bytes(value).decode("utf-8")


def _digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else _canonical_bytes(value)
    return hashlib.sha256(payload).hexdigest()


def _walk(value: Any) -> list[Any]:
    values = [value]
    if isinstance(value, dict):
        for child in value.values():
            values.extend(_walk(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(_walk(child))
    return values


def _assert_public_safe(value: Any) -> None:
    for item in _walk(value):
        if isinstance(item, dict) and PUBLIC_FORBIDDEN_KEYS.intersection(item):
            raise DriverError("unsafe_public_key", "public-output")
        if isinstance(item, str) and (
            SECRET.search(item) is not None or MATRIX_ROOM.fullmatch(item) is not None
        ):
            raise DriverError("unsafe_public_value", "public-output")


def plan_report() -> dict[str, Any]:
    """Return the deterministic, no-contact plan."""

    report = {
        "ok": True,
        "mode": "plan",
        "writes": False,
        "executionMode": "operator-driven-deterministic-conformance-fixture",
        "framework": "AgentTeams v1.2.0-beta.1 TeamHarness",
        "riskTier": RISK_TIER,
        "fixtureSourceMetadata": {
            "repository": f"{REPOSITORY_OWNER}/{REPOSITORY_NAME}",
            "revision": REPOSITORY_REVISION,
            "sourcePath": SOURCE_PATH,
            "testPath": TEST_PATH,
            "embeddedSourceAndTests": True,
            "runtimeRepositoryCheckout": False,
            "embeddedGitHubEvidence": True,
            "actualGitHubMcpCalls": 0,
            "liveBrokerReceiptVerification": False,
        },
        "roles": [LEADER_ROLE, *WORKER_ROLES],
        "logicalStages": [
            "Triage",
            "Locator",
            "Coder",
            "Tester",
            "Reviewer",
            "Experience",
        ],
        "recovery": {
            "firstTesterResult": "FAILED",
            "firstTesterArtifact": "TestEvidence",
            "firstTesterEnvelopeStatus": "retry",
            "projectNode": "revision",
            "route": "Tester -> TeamLeader -> Coder candidate 2 -> Tester",
            "maxFixtureGenerationAttempts": MAX_FIXTURE_GENERATION_ATTEMPTS,
        },
        "failureContract": {
            "executionFailureArtifact": "SkillFailure",
            "executionFailureEnvelopeStatus": "failed",
            "routeTo": "TeamLeader",
            "workerDirectHumanEscalation": False,
            "stageSkillPoliciesModeled": len(SKILL_FAILURE_PROBE_POLICIES),
            "localSourceBoundContractProbes": len(SOURCE_BOUND_FAILURE_PROBE_SKILLS),
            "submittedInSuccessFixture": False,
        },
        "reviewBoundary": {
            "candidateOnly": True,
            "pullRequestUrl": None,
            "repositoryMutation": False,
        },
        "signatureTrustBoundary": (
            "the ephemeral Ed25519 key proves byte integrity within one run; "
            "it is not a persistent human or release identity"
        ),
        "executeRequires": {
            "projectIdPrefix": PROJECT_PREFIX,
            "confirmation": CONFIRMATION,
        },
        "stages": list(PLAN_STAGES),
        "claims": {
            "autonomousInference": False,
            "actualModelCalls": 0,
            "runtimeRepositoryCheckout": False,
            "actualGitHubMcpCalls": 0,
            "liveBrokerReceiptVerification": False,
            "reviewerRepositoryMutation": False,
            "realRepositoryBenchmark": False,
            "fixtureArtifactsPreGeneratedByOperator": True,
        },
        "skillContractCompatibility": {
            "schemaFieldNames": ["model_call_attempt", "max_model_calls"],
            "interpretation": (
                "deterministic fixture-generation ordinals only; "
                "they do not attest model invocation"
            ),
        },
        "claimBoundary": (
            "real TeamHarness transitions and a real disposable unittest process; "
            "pre-generated deterministic fixture artifacts, zero model calls, "
            "no repository checkout, no GitHub MCP or live Broker receipt, "
            "no repository mutation, and no repository benchmark claim"
        ),
    }
    _assert_public_safe(report)
    return report


@dataclass(frozen=True)
class RuntimeContext:
    """Public role identities discovered from the fixed AgentTeams Team."""

    leader_matrix_user_id: str
    worker_matrix_user_ids: tuple[tuple[str, str], ...]

    def worker_id(self, role: str) -> str:
        values = dict(self.worker_matrix_user_ids)
        try:
            return values[role]
        except KeyError as exc:
            raise DriverError("worker_identity_missing", "runtime-preflight") from exc


@dataclass(frozen=True)
class DetachedSignature:
    signature_b64: str
    signature_sha256: str


@dataclass(frozen=True)
class ExecutionFixture:
    source_path: str
    test_path: str
    original_source: str
    test_source: str
    expected_candidate_passed: bool
    command: tuple[str, ...]

    def public_binding(self) -> dict[str, Any]:
        return {
            "sourcePath": self.source_path,
            "testPath": self.test_path,
            "originalSourceSha256": _digest(self.original_source.encode("utf-8")),
            "testSourceSha256": _digest(self.test_source.encode("utf-8")),
            "expectedCandidatePassed": self.expected_candidate_passed,
            "commandSha256": _digest(list(self.command)),
        }


@dataclass(frozen=True)
class StageMaterial:
    stage: str
    role: str
    skill: str
    task_id: str
    title: str
    source_envelope: dict[str, Any]
    result_envelope: dict[str, Any]
    source_signature: DetachedSignature
    result_signature: DetachedSignature
    signer_public_key_pem: str
    signer_public_key_sha256: str
    result_status: str
    summary: str
    execution_fixture: ExecutionFixture | None = None

    @property
    def source_route_sha256(self) -> str:
        return _digest(self.source_envelope)

    @property
    def result_handoff_sha256(self) -> str:
        return _digest(self.result_envelope)

    @property
    def artifact_sha256(self) -> str:
        artifact = self.result_envelope["artifact"]
        return str(artifact["sha256"])

    @property
    def deliverables(self) -> list[str]:
        root = f"shared/tasks/{self.task_id}"
        return [
            f"{root}/assignment.sig.json",
            f"{root}/result.handoff.json",
            f"{root}/result.handoff.sig.json",
            f"{root}/result.md",
        ]


class Backend(Protocol):
    def preflight(self) -> RuntimeContext: ...

    def leader_call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]: ...

    def worker_execute(self, material: StageMaterial) -> dict[str, Any]: ...


class EnvelopeSigner:
    """Per-execution ephemeral Ed25519 signer; no private bytes are persisted."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._private_key = private_key or Ed25519PrivateKey.generate()
        public_key = self._private_key.public_key()
        self.public_key_pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_pem = self.public_key_pem_bytes.decode("ascii")
        self.public_key_sha256 = _digest(self.public_key_pem_bytes)

    def sign(self, envelope: dict[str, Any]) -> DetachedSignature:
        signature = self._private_key.sign(_canonical_bytes(envelope))
        return DetachedSignature(
            signature_b64=base64.b64encode(signature).decode("ascii"),
            signature_sha256=_digest(signature),
        )

    def verify(self, envelope: dict[str, Any], signature: DetachedSignature) -> None:
        try:
            raw = base64.b64decode(signature.signature_b64, validate=True)
            public_key = serialization.load_pem_public_key(self.public_key_pem_bytes)
            if not isinstance(public_key, Ed25519PublicKey):
                raise ValueError("not Ed25519")
            public_key.verify(raw, _canonical_bytes(envelope))
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise DriverError("envelope_signature_invalid", "local-contract") from exc
        if _digest(raw) != signature.signature_sha256:
            raise DriverError("signature_digest_invalid", "local-contract")


class TestReceiptSigner:
    """Ephemeral real Ed25519 issuer for the local CI conformance fixture.

    This signer is deliberately separate from the envelope signer and never
    persists private bytes. Its public key is installed only in a temporary
    test-only TeamHarness policy by the conformance test; it is not a live CI,
    model, repository benchmark, or production trust root.
    """

    __test__ = False

    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._private_key = private_key or Ed25519PrivateKey.generate()
        public_key = self._private_key.public_key()
        self.public_key_pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_pem = self.public_key_pem_bytes.decode("ascii")
        self.public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_sha256 = _digest(self.public_key_der)

    def sign(self, claims: dict[str, Any]) -> str:
        signature = self._private_key.sign(
            TEST_RECEIPT_DOMAIN + _canonical_bytes(claims)
        )
        return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


class FixtureGenerationBudget:
    """One issue-global, strictly sequential fixture-attempt budget.

    The packaged ``patch-generator`` contract names its ordinal fields
    ``model_call_attempt`` and ``max_model_calls``.  In this conformance
    driver those fields carry only deterministic fixture-generation ordinals;
    no model is invoked.
    """

    def __init__(self, maximum: int = MAX_FIXTURE_GENERATION_ATTEMPTS) -> None:
        if maximum != MAX_FIXTURE_GENERATION_ATTEMPTS:
            raise DriverError("fixture_generation_budget_invalid", "local-contract")
        self.maximum = maximum
        self._consumed: list[int] = []

    @property
    def consumed(self) -> tuple[int, ...]:
        return tuple(self._consumed)

    def consume(self, attempt: int) -> None:
        expected = len(self._consumed) + 1
        if (
            isinstance(attempt, bool)
            or not isinstance(attempt, int)
            or attempt != expected
            or attempt > self.maximum
        ):
            raise DriverError(
                "fixture_generation_budget_exhausted",
                "fixture-generation-budget",
            )
        self._consumed.append(attempt)


def _validate_project_id(project_id: str) -> dict[str, str]:
    if (
        not isinstance(project_id, str)
        or len(project_id) > 42
        or SAFE_PROJECT.fullmatch(project_id) is None
    ):
        raise DriverError("project_id_invalid", "input")
    task_ids = {stage: f"{project_id}-{stage.replace('-', '')}" for stage in STAGE_ORDER}
    if len(set(task_ids.values())) != len(task_ids) or any(
        SAFE_ID.fullmatch(task_id) is None for task_id in task_ids.values()
    ):
        raise DriverError("derived_task_id_invalid", "input")
    return task_ids


def _artifact(
    artifact_type: str,
    schema_version: str,
    inline: dict[str, Any],
) -> dict[str, Any]:
    return {
        "type": artifact_type,
        "schema_version": schema_version,
        "inline": inline,
        "ref": None,
        "sha256": _digest(inline),
    }


def _handoff(
    *,
    run_id: str,
    task_id: str,
    producer: str,
    consumer: str,
    skill: str,
    artifact_type: str,
    artifact_schema: str,
    inline: dict[str, Any],
    created_at: str,
    status: str = "ready",
    parent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "envelope_version": "1.0",
        "run_id": run_id,
        "issue_id": ISSUE_ID,
        "task_id": task_id,
        "producer": producer,
        "consumer": consumer,
        "skill": skill,
        "trace_id": f"{run_id}:{task_id}",
        "idempotency_key": f"{run_id}:{task_id}:{consumer}:{skill}",
        "created_at": created_at,
        "status": status,
        "artifact": _artifact(artifact_type, artifact_schema, inline),
    }
    if parent is not None:
        envelope["parent_task_id"] = parent["task_id"]
        envelope["parent_handoff_sha256"] = _digest(parent)
    return envelope


def _issue() -> dict[str, Any]:
    return {
        "issue_number": ISSUE_ID,
        "title": "Calculator add returns the wrong value",
        "body": "The revision-pinned add helper subtracts instead of adding.",
        "labels": ["bug", "finals-fixture"],
        "state": "open",
        "author": "devflow-fixture",
        "created_at": "2026-07-28T12:00:00+00:00",
        "repo_owner": REPOSITORY_OWNER,
        "repo_name": REPOSITORY_NAME,
    }


def _issue_intake() -> dict[str, Any]:
    issue = _issue()
    return {
        "issue_number": issue["issue_number"],
        "title": issue["title"],
        "author": issue["author"],
        "repo_owner": issue["repo_owner"],
        "repo_name": issue["repo_name"],
        "created_at": issue["created_at"],
    }


def _classified_issue() -> dict[str, Any]:
    return {
        "issue": _issue(),
        "complexity_level": RISK_TIER,
        "category": "bug",
        "priority": "medium",
        "duplicate_of": None,
        "estimated_effort_hours": 1,
        "rationale": "A bounded one-line arithmetic defect with one regression test.",
        "confidence": 0.99,
        "evidence": {
            "risk_floor": {
                "proposed_tier": RISK_TIER,
                "effective_tier": RISK_TIER,
                "rule_ids": ["fixture.bounded-local-change"],
                "model_confidence": 0.99,
                "conflict": False,
            },
            "deduplication": {
                "status": "checked",
                "threshold": 0.92,
                "candidate_issue": None,
                "candidate_score": None,
            },
        },
    }


def _git_blob_sha1(content: str) -> str:
    raw = content.encode("utf-8")
    framed = f"blob {len(raw)}\0".encode("ascii") + raw
    return hashlib.sha1(framed, usedforsecurity=False).hexdigest()


def _github_file_fixture(path: str, content: str) -> tuple[dict[str, Any], dict[str, str]]:
    object_sha = _git_blob_sha1(content)
    content_sha256 = _digest(content.encode("utf-8"))
    response = {
        "repository": {
            "owner": REPOSITORY_OWNER,
            "repo": REPOSITORY_NAME,
        },
        "revision": REPOSITORY_REVISION,
        "path": path,
        "object_sha": object_sha,
        "content": content,
    }
    response_digest = _digest(response)
    operation = {
        "tool": "github:get_file_contents",
        "path": path,
        "revision": REPOSITORY_REVISION,
        "response_digest": response_digest,
        "fixture": True,
    }
    evidence = {
        "path": path,
        "object_sha": object_sha,
        "content_sha256": content_sha256,
        "response_digest": response_digest,
    }
    return operation, evidence


def _github_evidence(run_id: str, locator_task_id: str) -> dict[str, Any]:
    """Return a digest-valid source fixture, never a live Broker receipt."""

    file_fixtures = (
        _github_file_fixture(SOURCE_PATH, ORIGINAL_SOURCE),
        _github_file_fixture(TEST_PATH, TEST_SOURCE),
    )
    unsigned = {
        "run_id": run_id,
        "task_id": f"{locator_task_id}-github-evidence",
        "repository": {
            "owner": REPOSITORY_OWNER,
            "repo": REPOSITORY_NAME,
        },
        "revision": REPOSITORY_REVISION,
        "operations": [operation for operation, _evidence in file_fixtures],
        "evidence": [evidence for _operation, evidence in file_fixtures],
        "trace_id": f"{run_id}:{locator_task_id}-github-evidence",
        "status": "success",
    }
    return {**unsigned, "digest": _digest(unsigned)}


def _locator_input(
    *,
    run_id: str,
    locator_task_id: str,
    classified_issue: dict[str, Any],
) -> dict[str, Any]:
    return {
        "issue_id": ISSUE_ID,
        "repository_revision": REPOSITORY_REVISION,
        "classified_issue": classified_issue,
        "github_evidence": _github_evidence(run_id, locator_task_id),
    }


def _located_result(locator_input: dict[str, Any]) -> dict[str, Any]:
    github_evidence = locator_input["github_evidence"]
    evidence = github_evidence["evidence"]
    return {
        "issue_id": ISSUE_ID,
        "repository_revision": REPOSITORY_REVISION,
        "root_cause": {
            "summary": "The add helper returns a - b instead of a + b.",
            "file": SOURCE_PATH,
            "start_line": 4,
            "end_line": 6,
            "confidence": 0.99,
        },
        "affected_files": [
            {
                "path": SOURCE_PATH,
                "reason": "Contains the faulty arithmetic expression.",
                "change_type": "edit",
            }
        ],
        "related_tests": [TEST_PATH],
        "context_ref": {
            "path": SOURCE_PATH,
            "sha256": _digest(ORIGINAL_SOURCE.encode("utf-8")),
        },
        "confidence": 0.99,
        "evidence": evidence,
    }


def _patch_context(located_result: dict[str, Any]) -> dict[str, Any]:
    """Apply the explicit TeamLeader adapter into patch-generator's input."""

    return {
        "root_cause": located_result["root_cause"],
        "affected_files": located_result["affected_files"],
        "context_payload": (
            f"revision={located_result['repository_revision']} "
            f"path={located_result['context_ref']['path']} "
            f"sha256={located_result['context_ref']['sha256']} "
            f"summary={located_result['root_cause']['summary']}"
        ),
        "related_tests": located_result["related_tests"],
        "impact_analysis": {
            "affected_files": [
                item["path"] for item in located_result["affected_files"]
            ],
            "affected_modules": ["examples.calculator_bug"],
            "risk_level": "low",
            "breaking_changes": False,
            "test_files_needed": located_result["related_tests"],
        },
    }


def _patch(fixture_attempt: int) -> dict[str, Any]:
    new_content = CANDIDATE_ONE_SOURCE if fixture_attempt == 1 else CANDIDATE_TWO_SOURCE
    replacement = "    return a + b + 1" if fixture_attempt == 1 else "    return a + b"
    return {
        "branch_name": f"devflow/issue-{ISSUE_ID}-candidate-{fixture_attempt}",
        "changes": [
            {
                "file_path": SOURCE_PATH,
                "change_type": "modify",
                "original_content": ORIGINAL_SOURCE,
                "new_content": new_content,
                "diff": (
                    f"--- a/{SOURCE_PATH}\n"
                    f"+++ b/{SOURCE_PATH}\n"
                    "@@ -3,4 +3,4 @@\n"
                    " def add(a: int, b: int) -> int:\n"
                    '     """Return the sum of two integers."""\n'
                    "-    return a - b\n"
                    f"+{replacement}\n"
                ),
            }
        ],
        "commit_message": (
            "Propose bounded calculator fix"
            if fixture_attempt == 1
            else "Correct calculator addition after failed candidate"
        ),
        "description": "Change only the revision-pinned calculator implementation.",
    }


def _patch_input(
    fixture_attempt: int,
    located_context: dict[str, Any],
) -> dict[str, Any]:
    return {
        "issue_id": ISSUE_ID,
        "issue": _issue(),
        "tier": RISK_TIER,
        "located_context": located_context,
        # Required field name from the packaged skill schema.  Its value is a
        # deterministic fixture ordinal in this driver, not a model-call receipt.
        "model_call_attempt": fixture_attempt,
    }


def _patch_candidate(
    fixture_attempt: int,
    located_context: dict[str, Any],
) -> dict[str, Any]:
    patch = _patch(fixture_attempt)
    allowed_files = sorted({SOURCE_PATH, TEST_PATH})
    boundary_body = {
        "schema_version": "1.0",
        "located_context_digest": _digest(located_context),
        "allowed_files": allowed_files,
    }
    candidate: dict[str, Any] = {
        "schema_version": "1.2",
        "issue_id": ISSUE_ID,
        "tier": RISK_TIER,
        "patch": patch,
        "candidate_digest": _digest(patch),
        "evidence_boundary": {
            **boundary_body,
            "scope_digest": _digest(boundary_body),
        },
        "model_call_attempt": fixture_attempt,
        "retry_attempt": fixture_attempt,
    }
    if fixture_attempt > 1:
        candidate["revision_of"] = _digest(_patch(1))
    return candidate


def _integrity_attestation() -> dict[str, Any]:
    test_manifest = {TEST_PATH: _digest(TEST_SOURCE.encode("utf-8"))}
    return {
        "schema_version": "1.0",
        "policy": INTEGRITY_POLICY,
        "policy_digest": POLICY_DIGEST,
        "command_digest": _digest(list(TEST_COMMAND)),
        "baseline_manifest_digest": _digest(test_manifest),
        "candidate_baseline_manifest_digest": _digest(test_manifest),
        "candidate_pre_run_manifest_digest": _digest(test_manifest),
        "candidate_post_run_manifest_digest": _digest(test_manifest),
        "added_tests_manifest_digest": _digest({}),
        "baseline_protected_file_count": 1,
        "added_test_file_count": 0,
        "full_suite": False,
        "verified": True,
        "isolation_boundary": ISOLATION_BOUNDARY,
    }


def _test_result(passed: bool) -> dict[str, Any]:
    test_name = "tests/test_calculator.py::CalculatorTests.test_add"
    return {
        "total": 1,
        "passed": 1 if passed else 0,
        "failed": 0 if passed else 1,
        "errors": 0,
        "skipped": 0,
        "duration_ms": 0,
        "results": [
            {
                "name": test_name,
                "status": "passed" if passed else "failed",
                "duration_ms": 0,
                "error_message": None if passed else "AssertionError: 6 != 5",
                "traceback": None if passed else "bounded unittest assertion failure",
            }
        ],
        "baseline_comparison": {
            "baseline_passed": 0,
            "current_passed": 1 if passed else 0,
            "new_failures": [],
            "fixed_tests": [test_name] if passed else [],
            "regression": False,
        },
        "integrity_attestation": _integrity_attestation(),
    }


def _test_execution_policy() -> dict[str, Any]:
    return {
        "schema": "devflow.test-execution-policy/v1",
        "profile": "focused",
        "isolation_profile": INTEGRITY_POLICY,
        "isolation_boundary": ISOLATION_BOUNDARY,
        "credentials_forwarded": False,
        "network": "bubblewrap-unshare-all-mask-runtime-credentials",
        "shell": False,
        "deployment_tools_exposed": False,
        "timeout_seconds": 30,
        "resource_limits_applied": True,
        "policy_digest": TEST_CI_POLICY_SHA256,
        "server_digest": TEST_CI_SERVER_SHA256,
        "repository_archive_sha256": TEST_REPOSITORY_ARCHIVE_SHA256,
        "repository_manifest_sha256": TEST_REPOSITORY_MANIFEST_SHA256,
        "remaining_threat": (
            "This is a local conformance fixture; host root and kernel remain threats."
        ),
    }


def _test_evidence(
    candidate: dict[str, Any],
    passed: bool,
    *,
    run_id: str,
    task_id: str,
    issued_at: int,
    receipt_signer: TestReceiptSigner,
) -> dict[str, Any]:
    result = _test_result(passed)
    test_name = "tests/test_calculator.py::CalculatorTests.test_add"
    repository = {
        "archive_sha256": TEST_REPOSITORY_ARCHIVE_SHA256,
        "manifest_sha256": TEST_REPOSITORY_MANIFEST_SHA256,
    }
    execution_policy = _test_execution_policy()
    evidence: dict[str, Any] = {
        "issue_id": ISSUE_ID,
        "tier": candidate["tier"],
        "candidate_digest": candidate["candidate_digest"],
        "repository": repository,
        "revision": REPOSITORY_REVISION,
        "workspace_binding": TEST_CI_POLICY_SHA256,
        "execution_profile": "focused",
        "isolation_profile": INTEGRITY_POLICY,
        "execution_policy": execution_policy,
        "test_result": result,
        "test_result_redacted": False,
        "failing_tests": [] if passed else [test_name],
    }
    if not passed:
        evidence["failure_evidence"] = {
            "schema_version": "1.2",
            "issue_id": ISSUE_ID,
            "candidate_digest": candidate["candidate_digest"],
            "test_result_digest": _digest(result),
            "baseline_present": True,
            "failed": 1,
            "errors": 0,
            "regression": False,
            "reasons": ["test_failures"],
            "failing_tests": [test_name],
            "new_failures": [],
            "diagnostics": [
                {
                    "name": test_name,
                    "status": "failed",
                    "error_message": "AssertionError: 6 != 5",
                    "traceback": "bounded unittest assertion failure",
                }
            ],
            "redacted": False,
            "truncated": False,
        }
    claims = {
        "schema": TEST_RECEIPT_SCHEMA,
        "algorithm": "Ed25519",
        "issuer": TEST_RECEIPT_ISSUER,
        "audience": TEST_RECEIPT_AUDIENCE,
        "run_id": run_id,
        "task_id": task_id,
        "trace_id": f"{run_id}:{task_id}",
        "issue_id": ISSUE_ID,
        "repository": repository,
        "revision": REPOSITORY_REVISION,
        "workspace_binding": TEST_CI_POLICY_SHA256,
        "candidate_digest": candidate["candidate_digest"],
        "tier": candidate["tier"],
        "execution_profile": "focused",
        "isolation_profile": INTEGRITY_POLICY,
        "test_result_digest": _digest(result),
        "execution_policy_digest": _digest(execution_policy),
        "policy_digest": TEST_CI_POLICY_SHA256,
        "server_digest": TEST_CI_SERVER_SHA256,
        "key_sha256": receipt_signer.public_key_sha256,
        "iat": issued_at,
        "exp": issued_at + TEST_RECEIPT_TTL_SECONDS,
        "jti": _digest(
            {
                "run_id": run_id,
                "task_id": task_id,
                "candidate_digest": candidate["candidate_digest"],
            }
        )[:32],
    }
    evidence["test_execution_receipt"] = {
        **claims,
        "signature": receipt_signer.sign(claims),
    }
    return evidence


def _retry_invocation(
    tester_failure: dict[str, Any],
    tester_task_id: str,
    located_context: dict[str, Any],
) -> dict[str, Any]:
    failure = tester_failure["failure_evidence"]
    retry_input = {
        "issue_id": ISSUE_ID,
        "tier": RISK_TIER,
        "issue": _issue(),
        "located_context": located_context,
        "previous_patch": _patch(1),
        "test_failure_evidence": failure,
        "retry_attempt": 2,
        "model_call_attempt": 2,
    }
    return {
        "tier": RISK_TIER,
        "input": retry_input,
        "depends_on": [tester_task_id],
        "retry": {
            "attempt": 2,
            "max_attempts": MAX_FIXTURE_GENERATION_ATTEMPTS,
            "reason": "test_failed",
            "test_result_digest": failure["test_result_digest"],
        },
        "generation_budget": {
            "schema_version": "devflow.generation-budget/v1",
            "model_call_attempt": 2,
            "max_model_calls": MAX_FIXTURE_GENERATION_ATTEMPTS,
        },
    }


def _review_input(candidate: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    result = evidence["test_result"]
    security_scan_body = {
        "schema_version": "1.0",
        "scanner": "deterministic-conformance-fixture",
        "policy_version": "devflow-security-v1",
        "status": "passed",
        "findings": [],
    }
    return {
        "issue_id": ISSUE_ID,
        "tier": RISK_TIER,
        "candidate": candidate,
        "candidate_digest": candidate["candidate_digest"],
        "baseline_revision": REPOSITORY_REVISION,
        "suite": "python-unittest",
        "status": "passed",
        "totals": {
            name: result[name] for name in ("total", "passed", "failed", "errors", "skipped")
        },
        "baseline_comparison": result["baseline_comparison"],
        "evidence": {
            "test_result_sha256": _digest(result),
            "integrity_attestation_sha256": _digest(result["integrity_attestation"]),
            "security_scan": {
                **security_scan_body,
                "report_sha256": _digest(security_scan_body),
            },
        },
    }


def _review_output() -> dict[str, Any]:
    return {
        "issue_id": ISSUE_ID,
        "tier": RISK_TIER,
        "review": {
            "decision": "approved",
            "findings": [],
            "summary": "The second candidate is bounded, integrity-attested, and green.",
            "pr_url": None,
            "requires_human_approval": False,
        },
    }


def _experience_input(
    candidate: dict[str, Any],
    passing_evidence: dict[str, Any],
    review_output: dict[str, Any],
    located_context: dict[str, Any],
    run_id: str,
) -> dict[str, Any]:
    patch = candidate["patch"]
    # The receipt-backed TestEvidence is consumed at the TeamHarness boundary.
    # ExperiencePattern v1 still carries the separately named portable result
    # shape, so make that compatibility conversion explicit rather than
    # pretending its self-attestation is the cryptographic receipt.
    tests = _strict_loads(
        _canonical_bytes(passing_evidence["test_result"]).decode("utf-8")
    )
    integrity = tests["integrity_attestation"]
    integrity.update(
        {
            "policy": "immutable-baseline-tests/v1",
            "policy_digest": PORTABLE_POLICY_DIGEST,
            "isolation_boundary": PORTABLE_ISOLATION_BOUNDARY,
        }
    )
    review = review_output["review"]
    receipt_body = {
        "schema_version": "1.0",
        "issuer": "TeamLeader",
        "run_id": run_id,
        "issue_id": ISSUE_ID,
        "repository_revision": REPOSITORY_REVISION,
        "terminal_state": "review_approved",
        "candidate_digest": _digest(patch),
        "test_result_digest": _digest(tests),
        "review_digest": _digest(review),
        "approval_digest": None,
    }
    return {
        "issue_id": ISSUE_ID,
        "issue": _issue(),
        "tier": RISK_TIER,
        "repository_revision": REPOSITORY_REVISION,
        "located_context": located_context,
        "patch": patch,
        "test_result": tests,
        "review": review,
        "trace_id": run_id,
        "terminal_receipt": {
            **receipt_body,
            "receipt_sha256": _digest(receipt_body),
        },
    }


def _experience_output(
    experience_input: dict[str, Any],
) -> dict[str, Any]:
    receipt = experience_input["terminal_receipt"]
    review = experience_input["review"]
    patch = experience_input["patch"]
    summary = "A bounded arithmetic fix passed isolated regression evidence."
    reusable_lesson = "Route red tests through Leader and bind retries to exact evidence."
    redaction = _experience_redaction_evidence(
        summary=summary,
        reusable_lesson=reusable_lesson,
    )
    return {
        "pattern_id": f"exp-{ISSUE_ID}-{_digest(patch)[:12]}",
        "schema_version": "1.0",
        "outcome": "approved",
        "summary": summary,
        "reusable_lesson": reusable_lesson,
        "provenance": {
            "trace_id": experience_input["trace_id"],
            "issue_id": ISSUE_ID,
            "repository_revision": REPOSITORY_REVISION,
            "candidate_digest": _digest(patch),
            "review_digest": _digest(review),
            "terminal_receipt_sha256": receipt["receipt_sha256"],
        },
        "redaction": redaction,
        "stored": True,
    }


def _experience_redaction_evidence(
    *,
    summary: str,
    reusable_lesson: str,
) -> dict[str, Any]:
    """Return evidence only after scanning the exact persisted prose."""

    persisted_prose = {
        "summary": summary,
        "reusable_lesson": reusable_lesson,
    }
    try:
        secret_scan_passed = not contains_secret(persisted_prose)
    except Exception as exc:
        raise DriverError("redaction_scan_unavailable", "experience-output") from exc
    pii_scan_passed = re.search(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "\n".join(persisted_prose.values()),
    ) is None
    if not secret_scan_passed or not pii_scan_passed:
        raise DriverError("redaction_gate_failed", "experience-output")
    return {
        "policy_version": "1.0",
        "secret_scan_passed": secret_scan_passed,
        "pii_scan_passed": pii_scan_passed,
    }


def _make_material(
    *,
    signer: EnvelopeSigner,
    run_id: str,
    task_id: str,
    stage: str,
    source_type: str,
    source_schema: str,
    source_inline: dict[str, Any],
    result_type: str,
    result_schema: str,
    result_inline: dict[str, Any],
    created_at: str,
    prior_result: dict[str, Any] | None,
    source_status: str = "ready",
    result_status: str = "ready",
    execution_fixture: ExecutionFixture | None = None,
) -> StageMaterial:
    role = STAGE_ROLE[stage]
    agent = ROLE_TO_AGENT[role]
    skill = STAGE_SKILL[stage]
    source = _handoff(
        run_id=run_id,
        task_id=task_id,
        producer="TeamLeader",
        consumer=agent,
        skill=skill,
        artifact_type=source_type,
        artifact_schema=source_schema,
        inline=source_inline,
        created_at=created_at,
        status=source_status,
        parent=prior_result,
    )
    result = _handoff(
        run_id=run_id,
        task_id=task_id,
        producer=agent,
        consumer="TeamLeader",
        skill=skill,
        artifact_type=result_type,
        artifact_schema=result_schema,
        inline=result_inline,
        created_at=created_at,
        status=result_status,
        parent=source,
    )
    transport_status = "SUCCESS" if result_status == "ready" else "FAILED"
    summary = {
        "triage": "Classified the fixed issue.",
        "locator": "Located the revision-pinned defect.",
        "coder-1": "Generated candidate one within evidence bounds.",
        "tester-1": "Candidate one failed the isolated regression gate.",
        "coder-2": "Generated candidate two from Leader-validated failure evidence.",
        "tester-2": "Candidate two passed the isolated regression gate.",
        "reviewer": "Approved the digest-matched green candidate.",
        "experience": "Stored one receipt-bound redacted experience pattern.",
    }[stage]
    return StageMaterial(
        stage=stage,
        role=role,
        skill=skill,
        task_id=task_id,
        title=STAGE_TITLE[stage],
        source_envelope=source,
        result_envelope=result,
        source_signature=signer.sign(source),
        result_signature=signer.sign(result),
        signer_public_key_pem=signer.public_key_pem,
        signer_public_key_sha256=signer.public_key_sha256,
        result_status=transport_status,
        summary=summary,
        execution_fixture=execution_fixture,
    )


def _created_at_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def build_stage_materials(
    *,
    project_id: str,
    task_ids: dict[str, str],
    signer: EnvelopeSigner,
    receipt_signer: TestReceiptSigner | None = None,
    created_at: str | None = None,
) -> tuple[StageMaterial, ...]:
    """Build the fixed causal route and all detached signatures."""

    timestamp = created_at or _created_at_now()
    try:
        receipt_issued_at = int(
            dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            .astimezone(dt.timezone.utc)
            .timestamp()
        )
    except (TypeError, ValueError) as exc:
        raise DriverError("created_at_invalid", "local-contract") from exc
    test_receipt_signer = receipt_signer or TestReceiptSigner()
    classified = _classified_issue()
    locator_input = _locator_input(
        run_id=project_id,
        locator_task_id=task_ids["locator"],
        classified_issue=classified,
    )
    located_result = _located_result(locator_input)
    located_context = _patch_context(located_result)
    candidate_one = _patch_candidate(1, located_context)
    failed_tests = _test_evidence(
        candidate_one,
        False,
        run_id=project_id,
        task_id=task_ids["tester-1"],
        issued_at=receipt_issued_at,
        receipt_signer=test_receipt_signer,
    )
    candidate_two = _patch_candidate(2, located_context)
    passing_tests = _test_evidence(
        candidate_two,
        True,
        run_id=project_id,
        task_id=task_ids["tester-2"],
        issued_at=receipt_issued_at,
        receipt_signer=test_receipt_signer,
    )
    review_input = _review_input(candidate_two, passing_tests)
    review_output = _review_output()
    experience_input = _experience_input(
        candidate_two,
        passing_tests,
        review_output,
        located_context,
        project_id,
    )
    experience_output = _experience_output(experience_input)

    values: list[StageMaterial] = []
    prior: dict[str, Any] | None = None
    triage = _make_material(
        signer=signer,
        run_id=project_id,
        task_id=task_ids["triage"],
        stage="triage",
        source_type="IssueIntake",
        source_schema="1.0",
        source_inline=_issue_intake(),
        result_type="ClassifiedIssue",
        result_schema="1.0",
        result_inline=classified,
        created_at=timestamp,
        prior_result=prior,
    )
    values.append(triage)
    prior = triage.result_envelope

    locator = _make_material(
        signer=signer,
        run_id=project_id,
        task_id=task_ids["locator"],
        stage="locator",
        source_type="SkillInvocation",
        source_schema="1.0",
        source_inline=locator_input,
        result_type="LocatedContext",
        result_schema="1.0",
        result_inline=located_result,
        created_at=timestamp,
        prior_result=prior,
    )
    values.append(locator)
    prior = locator.result_envelope

    coder_one_source = {
        "tier": RISK_TIER,
        "input": _patch_input(1, located_context),
        "depends_on": [task_ids["locator"]],
        "generation_budget": {
            "schema_version": "devflow.generation-budget/v1",
            "model_call_attempt": 1,
            "max_model_calls": MAX_FIXTURE_GENERATION_ATTEMPTS,
        },
    }
    coder_one = _make_material(
        signer=signer,
        run_id=project_id,
        task_id=task_ids["coder-1"],
        stage="coder-1",
        source_type="SkillInvocation",
        source_schema="1.0",
        source_inline=coder_one_source,
        result_type="PatchCandidate",
        result_schema="1.2",
        result_inline=candidate_one,
        created_at=timestamp,
        prior_result=prior,
    )
    values.append(coder_one)
    prior = coder_one.result_envelope

    tester_one = _make_material(
        signer=signer,
        run_id=project_id,
        task_id=task_ids["tester-1"],
        stage="tester-1",
        source_type="PatchCandidate",
        source_schema="1.2",
        source_inline=candidate_one,
        result_type="TestEvidence",
        result_schema="1.0",
        result_inline=failed_tests,
        created_at=timestamp,
        prior_result=prior,
        result_status="retry",
        execution_fixture=ExecutionFixture(
            source_path=SOURCE_PATH,
            test_path=TEST_PATH,
            original_source=ORIGINAL_SOURCE,
            test_source=TEST_SOURCE,
            expected_candidate_passed=False,
            command=TEST_COMMAND,
        ),
    )
    values.append(tester_one)
    prior = tester_one.result_envelope

    coder_two = _make_material(
        signer=signer,
        run_id=project_id,
        task_id=task_ids["coder-2"],
        stage="coder-2",
        source_type="SkillInvocation",
        source_schema="1.0",
        source_inline=_retry_invocation(
            failed_tests,
            task_ids["tester-1"],
            located_context,
        ),
        result_type="PatchCandidate",
        result_schema="1.2",
        result_inline=candidate_two,
        created_at=timestamp,
        prior_result=prior,
        source_status="retry",
    )
    values.append(coder_two)
    prior = coder_two.result_envelope

    tester_two = _make_material(
        signer=signer,
        run_id=project_id,
        task_id=task_ids["tester-2"],
        stage="tester-2",
        source_type="PatchCandidate",
        source_schema="1.2",
        source_inline=candidate_two,
        result_type="TestEvidence",
        result_schema="1.0",
        result_inline=passing_tests,
        created_at=timestamp,
        prior_result=prior,
        execution_fixture=ExecutionFixture(
            source_path=SOURCE_PATH,
            test_path=TEST_PATH,
            original_source=ORIGINAL_SOURCE,
            test_source=TEST_SOURCE,
            expected_candidate_passed=True,
            command=TEST_COMMAND,
        ),
    )
    values.append(tester_two)
    prior = tester_two.result_envelope

    reviewer = _make_material(
        signer=signer,
        run_id=project_id,
        task_id=task_ids["reviewer"],
        stage="reviewer",
        source_type="TestEvidence",
        source_schema="1.0",
        source_inline=review_input,
        result_type="ReviewDecision",
        result_schema="1.0",
        result_inline=review_output,
        created_at=timestamp,
        prior_result=prior,
    )
    values.append(reviewer)
    prior = reviewer.result_envelope

    experience = _make_material(
        signer=signer,
        run_id=project_id,
        task_id=task_ids["experience"],
        stage="experience",
        source_type="VerifiedRunBundle",
        source_schema="1.0",
        source_inline=experience_input,
        result_type="ExperiencePattern",
        result_schema="1.0",
        result_inline=experience_output,
        created_at=timestamp,
        prior_result=prior,
    )
    values.append(experience)
    return tuple(values)


def _run_validator(
    skill: str,
    mode: str,
    artifact: dict[str, Any],
    source: dict[str, Any] | None = None,
) -> None:
    validator = ROOT / "skills" / skill / "scripts" / "validate.py"
    if not validator.is_file():
        raise DriverError("packaged_validator_missing", "local-contract")
    with tempfile.TemporaryDirectory(prefix="devflow-finals-validator-") as directory:
        root = Path(directory)
        artifact_path = root / "artifact.json"
        artifact_path.write_bytes(_canonical_bytes(artifact))
        command = [sys.executable, "-S", str(validator), mode, str(artifact_path)]
        if source is not None:
            source_path = root / "source.json"
            source_path.write_bytes(_canonical_bytes(source))
            command.append(str(source_path))
        environment = {
            name: os.environ[name] for name in ("SystemRoot", "WINDIR") if name in os.environ
        }
        environment["PYTHONIOENCODING"] = "utf-8"
        try:
            completed = subprocess.run(
                command,
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DriverError("packaged_validator_unavailable", "local-contract") from exc
    if completed.returncode != 0:
        raise DriverError("packaged_validator_rejected_fixture", "local-contract")
    try:
        result = _strict_loads(completed.stdout.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise DriverError("packaged_validator_output_invalid", "local-contract") from exc
    if result != {"valid": True, "skill": skill, "mode": mode}:
        raise DriverError("packaged_validator_output_invalid", "local-contract")


def _skill_failure_probe(
    skill: str,
    source_inline: dict[str, Any],
) -> dict[str, Any]:
    try:
        policy = SKILL_FAILURE_PROBE_POLICIES[skill]
    except KeyError as exc:
        raise DriverError("skill_failure_probe_unknown", "local-contract") from exc
    retryable = bool(policy["retryable"])
    retry_count = int(policy["retry_count"])
    max_attempts = int(policy["max_attempts"])
    return {
        "schema_version": "1.0",
        "skill": skill,
        "code": str(policy["code"]),
        "retryable": retryable,
        "retry_count": retry_count,
        "max_attempts": max_attempts,
        "exhausted": not retryable or retry_count == max_attempts,
        "route_to": "TeamLeader",
        "event": str(policy["event"]),
        "source_artifact_sha256": _digest(source_inline),
        "summary": "Deterministic local probe of the declared execution-failure contract.",
        "diagnostics": [],
    }


def _validate_source_bound_failure_probes(
    materials: tuple[StageMaterial, ...],
) -> None:
    """Validate unified SkillFailure locally without submitting fake failures."""

    by_skill = {material.skill: material for material in materials}
    for skill in SOURCE_BOUND_FAILURE_PROBE_SKILLS:
        try:
            source_inline = by_skill[skill].source_envelope["artifact"]["inline"]
        except (KeyError, TypeError) as exc:
            raise DriverError("skill_failure_probe_source_missing", "local-contract") from exc
        if not isinstance(source_inline, dict):
            raise DriverError("skill_failure_probe_source_invalid", "local-contract")
        _run_validator(
            skill,
            "output",
            _skill_failure_probe(skill, source_inline),
            source_inline,
        )


def validate_stage_materials(
    materials: tuple[StageMaterial, ...],
    signer: EnvelopeSigner,
) -> None:
    """Verify signatures, causal edges, budgets and standalone validators."""

    if tuple(item.stage for item in materials) != STAGE_ORDER:
        raise DriverError("stage_order_invalid", "local-contract")
    prior_result: dict[str, Any] | None = None
    for material in materials:
        signer.verify(material.source_envelope, material.source_signature)
        signer.verify(material.result_envelope, material.result_signature)
        source = material.source_envelope
        result = material.result_envelope
        if (
            source["task_id"] != material.task_id
            or result["task_id"] != material.task_id
            or source["run_id"] != result["run_id"]
            or source["skill"] != material.skill
            or result["skill"] != material.skill
            or source["producer"] != "TeamLeader"
            or source["consumer"] != ROLE_TO_AGENT[material.role]
            or result["producer"] != ROLE_TO_AGENT[material.role]
            or result["consumer"] != "TeamLeader"
            or result.get("parent_task_id") != source["task_id"]
            or result.get("parent_handoff_sha256") != _digest(source)
            or material.artifact_sha256 != _digest(result["artifact"]["inline"])
        ):
            raise DriverError("handoff_contract_invalid", "local-contract")
        if prior_result is None:
            if "parent_task_id" in source or "parent_handoff_sha256" in source:
                raise DriverError("root_causality_invalid", "local-contract")
        elif source.get("parent_task_id") != prior_result["task_id"] or source.get(
            "parent_handoff_sha256"
        ) != _digest(prior_result):
            raise DriverError("cross_stage_causality_invalid", "local-contract")

        source_inline = source["artifact"]["inline"]
        result_inline = result["artifact"]["inline"]
        if material.skill == "patch-generator":
            if source["status"] == "retry":
                _run_validator(material.skill, "retry", source)
                validator_source = source
            else:
                validator_source = source_inline["input"]
                _run_validator(material.skill, "input", validator_source)
            _run_validator(
                material.skill,
                "output",
                result_inline,
                validator_source,
            )
        elif material.skill == "test-runner":
            _run_validator(material.skill, "input", source_inline)
            _run_validator(material.skill, "output", result_inline, source_inline)
        else:
            _run_validator(material.skill, "input", source_inline)
            _run_validator(
                material.skill,
                "output",
                result_inline,
                source_inline,
            )
        prior_result = result

    fixture_attempts = [
        int(item.result_envelope["artifact"]["inline"]["model_call_attempt"])
        for item in materials
        if item.skill == "patch-generator"
    ]
    if fixture_attempts != [1, 2]:
        raise DriverError(
            "fixture_generation_route_invalid",
            "fixture-generation-budget",
        )
    budget = FixtureGenerationBudget()
    for attempt in fixture_attempts:
        budget.consume(attempt)
    _validate_source_bound_failure_probes(materials)


def _expect_identity(
    response: Any,
    *,
    tool: str,
    action: str,
    stage: str,
) -> dict[str, Any]:
    if (
        not isinstance(response, dict)
        or response.get("tool") != tool
        or response.get("action") != action
    ):
        raise DriverError("response_identity_invalid", stage)
    return response


def _expect_ok(
    response: Any,
    *,
    tool: str,
    action: str,
    stage: str,
) -> dict[str, Any]:
    checked = _expect_identity(response, tool=tool, action=action, stage=stage)
    if checked.get("ok") is not True:
        raise DriverError("remote_action_failed", stage)
    return checked


def _expect_absent(
    response: Any,
    *,
    tool: str,
    action: str,
    error: str,
    stage: str,
) -> None:
    checked = _expect_identity(response, tool=tool, action=action, stage=stage)
    if checked.get("ok") is not False or checked.get("error") != error:
        raise DriverError("freshness_not_proven", stage)


def _validate_runtime_context(context: RuntimeContext) -> dict[str, str]:
    leader = MATRIX_USER.fullmatch(context.leader_matrix_user_id)
    workers = dict(context.worker_matrix_user_ids)
    if (
        leader is None
        or leader.group(1) != LEADER_ROLE
        or set(workers) != set(WORKER_ROLES)
        or len(set(workers.values())) != len(workers)
        or context.leader_matrix_user_id in workers.values()
    ):
        raise DriverError("runtime_identity_invalid", "runtime-preflight")
    for role, matrix_user_id in workers.items():
        match = MATRIX_USER.fullmatch(matrix_user_id)
        if match is None or match.group(1) != role:
            raise DriverError("runtime_identity_invalid", "runtime-preflight")
    return workers


def _binding_digest(binding: Any, stage: str) -> str:
    if not isinstance(binding, dict):
        raise DriverError("project_binding_invalid", stage)
    expected = {
        "schema",
        "audience",
        "approvalDomain",
        "policyKeySha256",
        "riskTierAuthority",
        "sourceAuthority",
        "incarnationAuthority",
        "projectBindingDigest",
    }
    if (
        set(binding) != expected
        or binding.get("schema") != "devflow.project-binding/v2"
        or binding.get("riskTierAuthority") != "root-only-approval-ledger"
        or binding.get("sourceAuthority") != "persistent-project-state"
        or binding.get("incarnationAuthority") != "guard-generated-root-only-approval-ledger"
        or any(
            not isinstance(binding.get(name), str) or DIGEST.fullmatch(str(binding[name])) is None
            for name in (
                "approvalDomain",
                "policyKeySha256",
                "projectBindingDigest",
            )
        )
        or not isinstance(binding.get("audience"), str)
        or not binding["audience"]
    ):
        raise DriverError("project_binding_invalid", stage)
    return _digest(binding)


def _project(
    response: dict[str, Any],
    *,
    project_id: str,
    binding_sha256: str | None,
    stage: str,
) -> tuple[dict[str, Any], str]:
    project = response.get("project")
    if (
        not isinstance(project, dict)
        or project.get("project_id") != project_id
        or project.get("source") != SOURCE
        or project.get("risk_tier") != RISK_TIER
    ):
        raise DriverError("project_state_invalid", stage)
    digest = _binding_digest(project.get("binding"), stage)
    if binding_sha256 is not None and digest != binding_sha256:
        raise DriverError("project_binding_changed", stage)
    response_digest = _binding_digest(response.get("binding"), stage)
    if response_digest != digest:
        raise DriverError("project_binding_changed", stage)
    return project, digest


def _loop_tasks(
    project: dict[str, Any],
    expected: dict[str, tuple[str, list[str], str]],
    stage: str,
) -> None:
    if project.get("plan_type") != "loop":
        raise DriverError("loop_plan_invalid", stage)
    loop = project.get("loop")
    if not isinstance(loop, dict):
        raise DriverError("loop_plan_invalid", stage)
    tasks = loop.get("tasks")
    if not isinstance(tasks, list) or len(tasks) != len(expected):
        raise DriverError("loop_plan_invalid", stage)
    observed: dict[str, tuple[str, list[str], str]] = {}
    for task in tasks:
        if not isinstance(task, dict) or set(task) != {
            "task_id",
            "title",
            "assigned_to",
            "depends_on",
            "status",
        }:
            raise DriverError("loop_task_invalid", stage)
        task_id = task.get("task_id")
        if not isinstance(task_id, str) or task_id in observed:
            raise DriverError("loop_task_invalid", stage)
        observed[task_id] = (
            str(task.get("assigned_to") or ""),
            list(task.get("depends_on") or []),
            str(task.get("status") or ""),
        )
    if observed != expected:
        raise DriverError("loop_task_invalid", stage)


def _plan_tasks(
    materials: dict[str, StageMaterial],
    stages: tuple[str, ...],
    statuses: dict[str, str],
) -> list[dict[str, Any]]:
    dependencies = {
        "triage": [],
        "locator": [materials["triage"].task_id],
        "coder-1": [materials["locator"].task_id],
        "tester-1": [materials["coder-1"].task_id],
        # The TeamHarness graph requires completed dependencies.  The exact
        # failed Tester causal edge is carried by coder-2's signed source
        # HandoffEnvelope; coder-1 is the last completed graph dependency.
        "coder-2": [materials["coder-1"].task_id],
        "tester-2": [materials["coder-2"].task_id],
        "reviewer": [materials["tester-2"].task_id],
        "experience": [materials["reviewer"].task_id],
    }
    return [
        {
            "taskId": materials[stage].task_id,
            "title": materials[stage].title,
            "assignedTo": materials[stage].role,
            "dependsOn": dependencies[stage],
            "status": statuses.get(stage, "planned"),
        }
        for stage in stages
    ]


def _expected_loop_tasks(
    materials: dict[str, StageMaterial],
    stages: tuple[str, ...],
    statuses: dict[str, str],
) -> dict[str, tuple[str, list[str], str]]:
    return {
        item["taskId"]: (
            item["assignedTo"],
            item["dependsOn"],
            item["status"],
        )
        for item in _plan_tasks(materials, stages, statuses)
    }


def _validate_worker_proof(
    proof: Any,
    material: StageMaterial,
) -> dict[str, Any]:
    expected_fields = {
        "ok",
        "taskId",
        "stage",
        "role",
        "skill",
        "resultStatus",
        "deliverables",
        "sourceRouteSha256",
        "resultHandoffSha256",
        "artifactSha256",
        "validatorSha256",
        "signerPublicKeySha256",
        "sourceSignatureSha256",
        "resultSignatureSha256",
        "submissionSha256",
        "conflictRequestedSha256",
        "sourceSignatureVerified",
        "resultSignatureVerified",
        "ackIdempotentRetry",
        "firstSubmit",
        "idempotentRetry",
        "conflictRetry",
        "isolatedExecutionVerified",
    }
    if not isinstance(proof, dict) or set(proof) != expected_fields:
        raise DriverError("worker_proof_invalid", f"worker-{material.stage}")
    expected_submission = _submission_digest(
        material.task_id,
        material.result_status,
        material.summary,
        material.deliverables,
    )
    expected_conflict = _submission_digest(
        material.task_id,
        material.result_status,
        material.summary + " Conflict probe.",
        material.deliverables,
    )
    if (
        proof.get("ok") is not True
        or proof.get("taskId") != material.task_id
        or proof.get("stage") != material.stage
        or proof.get("role") != material.role
        or proof.get("skill") != material.skill
        or proof.get("resultStatus") != material.result_status
        or proof.get("deliverables") != material.deliverables
        or proof.get("sourceRouteSha256") != material.source_route_sha256
        or proof.get("resultHandoffSha256") != material.result_handoff_sha256
        or proof.get("artifactSha256") != material.artifact_sha256
        or proof.get("signerPublicKeySha256") != material.signer_public_key_sha256
        or proof.get("sourceSignatureSha256") != material.source_signature.signature_sha256
        or proof.get("resultSignatureSha256") != material.result_signature.signature_sha256
        or proof.get("submissionSha256") != expected_submission
        or proof.get("conflictRequestedSha256") != expected_conflict
        or not isinstance(proof.get("validatorSha256"), str)
        or DIGEST.fullmatch(str(proof["validatorSha256"])) is None
        or any(
            proof.get(field) is not True
            for field in (
                "sourceSignatureVerified",
                "resultSignatureVerified",
                "ackIdempotentRetry",
                "firstSubmit",
                "idempotentRetry",
                "conflictRetry",
            )
        )
        or proof.get("isolatedExecutionVerified") is not (material.execution_fixture is not None)
    ):
        raise DriverError("worker_proof_invalid", f"worker-{material.stage}")
    _assert_public_safe(proof)
    return proof


def _submission_digest(
    task_id: str,
    status: str,
    summary: str,
    deliverables: list[str],
) -> str:
    return _digest(
        {
            "taskId": task_id,
            "status": status,
            "summary": summary,
            "deliverables": deliverables,
        }
    )


def _validate_checked_task(
    checked: Any,
    material: StageMaterial,
) -> None:
    response = _expect_ok(
        checked,
        tool="taskflow",
        action="check_task",
        stage=f"leader-check-{material.stage}",
    )
    task = response.get("task")
    expected_result = {
        "status": material.result_status,
        "summary": material.summary,
        "deliverables": material.deliverables,
    }
    if (
        response.get("effective") is not True
        or response.get("validationErrors") != []
        or response.get("pulled") is not True
        or response.get("result") != expected_result
        or not isinstance(task, dict)
        or task.get("task_id") != material.task_id
        or task.get("assigned_to") != material.role
        or task.get("status") != "submitted"
        or task.get("result_status") != material.result_status
        or task.get("summary") != material.summary
        or task.get("deliverables") != material.deliverables
        or task.get("result_path") != f"shared/tasks/{material.task_id}/result.md"
    ):
        raise DriverError("checked_result_invalid", f"leader-check-{material.stage}")


def _expect_filesync(
    response: Any,
    *,
    action: str,
    path: str,
    expected_objects: int | None,
    stage: str,
) -> int:
    checked = _expect_ok(response, tool="filesync", action=action, stage=stage)
    leader_workspace = f"/root/hiclaw-fs/agents/{LEADER_ROLE}"
    expected_fields = {
        "ok",
        "tool",
        "action",
        "kind",
        "path",
        "localPath",
        "workspaceBindingSha256",
    }
    if action == "stat":
        expected_fields.add("exists")
    if expected_objects is not None:
        expected_fields.update(
            {
                "expectedObjectCount",
                "verifiedObjectCount",
                "localTreeSha256",
            }
        )
    if (
        set(checked) != expected_fields
        or checked.get("kind") != "shared"
        or checked.get("path") != path
        or checked.get("localPath") != f"{leader_workspace}/{path.rstrip('/')}"
        or checked.get("workspaceBindingSha256") != _digest(leader_workspace.encode("utf-8"))
        or (action == "stat" and checked.get("exists") is not True)
    ):
        raise DriverError("filesync_attestation_invalid", stage)
    if expected_objects is not None and (
        checked.get("expectedObjectCount") != expected_objects
        or checked.get("verifiedObjectCount") != expected_objects
        or not isinstance(checked.get("localTreeSha256"), str)
        or DIGEST.fullmatch(str(checked["localTreeSha256"])) is None
    ):
        raise DriverError("filesync_attestation_invalid", stage)
    return expected_objects if expected_objects is not None else 1


def _expect_notification(
    response: dict[str, Any],
    *,
    event: str,
    project_id: str,
    summary: str,
    target_room: str | None,
    stage: str,
) -> dict[str, Any]:
    """Validate one pinned TeamHarness ``notificationNeeded`` hint."""

    expected: dict[str, Any] = {
        "event": event,
        "projectId": project_id,
        "summary": summary,
    }
    if target_room is not None:
        expected["targetRoom"] = target_room
    hint = response.get("notificationNeeded")
    if hint != expected:
        raise DriverError("notification_hint_invalid", stage)
    return expected


def _send_team_room_message(
    backend: Backend,
    *,
    room_id: str,
    notification: dict[str, Any],
    message_text: str,
    kind: str,
    target_mode: str,
    expected_mentions: list[str],
    stage: str,
) -> tuple[dict[str, Any], str]:
    """Send and attest one Matrix message without publishing room identifiers."""

    if (
        kind not in {"assignment", "failure", "final", "status"}
        or target_mode not in {"hint", "team-room-fallback"}
        or not 1 <= len(message_text.encode("utf-8")) <= 4_000
        or CONTROL.search(message_text) is not None
        or SECRET.search(message_text) is not None
        or len(expected_mentions) != len(set(expected_mentions))
        or any(MATRIX_USER.fullmatch(value) is None for value in expected_mentions)
    ):
        raise DriverError("notification_message_invalid", stage)

    response = _expect_ok(
        backend.leader_call(
            "message",
            {
                "action": "send",
                "channel": "matrix",
                "target": f"room:{room_id}",
                "message": message_text,
            },
        ),
        tool="message",
        action="send",
        stage=stage,
    )
    content = response.get("content")
    message_id = response.get("messageId")
    mention_content_valid = (
        content.get("m.mentions") == {"user_ids": expected_mentions}
        if isinstance(content, dict) and expected_mentions
        else isinstance(content, dict) and "m.mentions" not in content
    )
    if (
        response.get("channel") != "matrix"
        or response.get("target") != f"room:{room_id}"
        or response.get("targetKind") != "room"
        or response.get("mentions") != expected_mentions
        or not isinstance(content, dict)
        or content.get("msgtype") != "m.text"
        or content.get("body") != message_text
        or content.get("format") != "org.matrix.custom.html"
        or not isinstance(content.get("formatted_body"), str)
        or not content["formatted_body"]
        or not mention_content_valid
    ):
        raise DriverError("notification_delivery_invalid", stage)
    if (
        not isinstance(message_id, str)
        or not 1 <= len(message_id.encode("utf-8")) <= 512
        or CONTROL.search(message_id) is not None
        or response.get("sessionRecorded") is not True
    ):
        raise DriverError("notification_delivery_invalid", stage)

    receipt = {
        "event": notification["event"],
        "kind": kind,
        "targetMode": target_mode,
        "messageSha256": _digest(message_text.encode("utf-8")),
        "messageIdSha256": _digest(message_id.encode("utf-8")),
        "sessionRecorded": True,
    }
    _assert_public_safe(receipt)
    return receipt, message_id


def execute_finals_flow(
    backend: Backend,
    *,
    project_id: str,
    confirmation: str,
    signer: EnvelopeSigner | None = None,
    receipt_signer: TestReceiptSigner | None = None,
) -> dict[str, Any]:
    """Execute and verify one fresh deterministic conformance flow."""

    if confirmation != CONFIRMATION:
        raise DriverError("confirmation_required", "input")
    task_ids = _validate_project_id(project_id)
    context = backend.preflight()
    worker_matrix_ids = _validate_runtime_context(context)

    envelope_signer = signer or EnvelopeSigner()
    materials_tuple = build_stage_materials(
        project_id=project_id,
        task_ids=task_ids,
        signer=envelope_signer,
        receipt_signer=receipt_signer,
    )
    validate_stage_materials(materials_tuple, envelope_signer)
    materials = {item.stage: item for item in materials_tuple}
    queued_room_notifications: list[tuple[dict[str, Any], str, str]] = []

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
    for stage in STAGE_ORDER:
        _expect_absent(
            backend.leader_call(
                "taskflow",
                {
                    "action": "check_task",
                    "payload": {"taskId": materials[stage].task_id},
                },
            ),
            tool="taskflow",
            action="check_task",
            error="task not found",
            stage="fresh-tasks",
        )

    created = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "create_project",
                "riskTier": RISK_TIER,
                "payload": {
                    "projectId": project_id,
                    "title": PROJECT_TITLE,
                    "source": SOURCE,
                },
            },
        ),
        tool="projectflow",
        action="create_project",
        stage="create-project",
    )
    created_project, binding_sha256 = _project(
        created,
        project_id=project_id,
        binding_sha256=None,
        stage="create-project",
    )
    if created_project.get("status") != "active" or created_project.get("tasks") != []:
        raise DriverError("created_project_invalid", "create-project")
    queued_room_notifications.append(
        (
            _expect_notification(
                created,
                event="create_project",
                project_id=project_id,
                summary=f"create_project: {PROJECT_TITLE}",
                target_room=None,
                stage="create-project-notification",
            ),
            "status",
            (
                f"[CONFORMANCE FIXTURE][STATUS] project={project_id} created. "
                "Artifacts are pre-generated; autonomous inference, model calls, "
                "repository checkout, live GitHub MCP/Broker proof, and repository "
                "mutation are outside this run."
            ),
        )
    )

    initial_statuses = {stage: "planned" for stage in INITIAL_STAGES}
    planned = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "plan_loop",
                "riskTier": RISK_TIER,
                "payload": {
                    "projectId": project_id,
                    "goal": "Produce one reviewed green candidate and trusted experience.",
                    "stopCondition": "Green tests, approved review, and stored experience.",
                    "iterationTemplate": (
                        "TeamLeader validates every result and replans only from typed evidence."
                    ),
                    "maxIterations": MAX_FIXTURE_GENERATION_ATTEMPTS,
                    "currentIteration": 0,
                    "status": "running",
                    "tasks": _plan_tasks(
                        materials,
                        INITIAL_STAGES,
                        initial_statuses,
                    ),
                },
            },
        ),
        tool="projectflow",
        action="plan_loop",
        stage="initial-loop-plan",
    )
    initial_project, _ = _project(
        planned,
        project_id=project_id,
        binding_sha256=binding_sha256,
        stage="initial-loop-plan",
    )
    _loop_tasks(
        initial_project,
        _expected_loop_tasks(
            materials,
            INITIAL_STAGES,
            initial_statuses,
        ),
        "initial-loop-plan",
    )
    queued_room_notifications.append(
        (
            _expect_notification(
                planned,
                event="plan_loop",
                project_id=project_id,
                summary=f"plan_loop: {PROJECT_TITLE}",
                target_room=None,
                stage="initial-loop-plan-notification",
            ),
            "status",
            (
                f"[CONFORMANCE FIXTURE][STATUS] project={project_id} initial "
                "four-node Loop plan recorded; deterministic failure recovery "
                "will be exercised through typed handoffs."
            ),
        )
    )

    room = _expect_ok(
        backend.leader_call(
            "roomflow",
            {
                "action": "create_task_room",
                "payload": {
                    "projectId": project_id,
                    "source": SOURCE,
                    "invite": [worker_matrix_ids[role] for role in WORKER_ROLES],
                },
            },
        ),
        tool="roomflow",
        action="create_task_room",
        stage="create-room",
    )
    room_id = room.get("roomId")
    invited = [worker_matrix_ids[role] for role in WORKER_ROLES]
    if (
        not isinstance(room_id, str)
        or MATRIX_ROOM.fullmatch(room_id) is None
        or room.get("reused") is not False
        or room.get("private") is not True
        or room.get("joinRule") != "invite"
        or room.get("membershipStateVerified") is not True
        or room.get("creator") != context.leader_matrix_user_id
        or room.get("invite") != invited
        or room.get("members") != invited
        or not isinstance(room.get("authorizedMembersSha256"), str)
        or DIGEST.fullmatch(str(room["authorizedMembersSha256"])) is None
        or _binding_digest(room.get("binding"), "create-room") != binding_sha256
    ):
        raise DriverError("task_room_invalid", "create-room")

    worker_proofs: dict[str, dict[str, Any]] = {}
    message_receipts: list[dict[str, Any]] = []
    message_ids: set[str] = set()

    def deliver_notification(
        notification: dict[str, Any],
        *,
        kind: str,
        message_text: str,
        expected_mentions: list[str],
        stage: str,
    ) -> None:
        hinted_room = notification.get("targetRoom")
        if hinted_room is not None and hinted_room != room_id:
            raise DriverError("notification_target_invalid", stage)
        receipt, message_id = _send_team_room_message(
            backend,
            room_id=room_id,
            notification=notification,
            message_text=message_text,
            kind=kind,
            target_mode=("hint" if hinted_room == room_id else "team-room-fallback"),
            expected_mentions=expected_mentions,
            stage=stage,
        )
        if message_id in message_ids:
            raise DriverError("notification_event_replayed", stage)
        message_ids.add(message_id)
        message_receipts.append(receipt)

    for index, (notification, kind, message_text) in enumerate(
        queued_room_notifications,
        start=1,
    ):
        deliver_notification(
            notification,
            kind=kind,
            message_text=message_text,
            expected_mentions=[],
            stage=f"queued-room-notification-{index}",
        )

    def run_material(material: StageMaterial, *, accept: bool) -> None:
        delegated = _expect_ok(
            backend.leader_call(
                "taskflow",
                {
                    "action": "delegate_task",
                    "payload": {
                        "projectId": project_id,
                        "taskId": material.task_id,
                        "assignedTo": material.role,
                        "roomId": room_id,
                        "spec": _canonical_text(material.source_envelope),
                    },
                },
            ),
            tool="taskflow",
            action="delegate_task",
            stage=f"delegate-{material.stage}",
        )
        delegated_task = delegated.get("task")
        if (
            not isinstance(delegated_task, dict)
            or delegated_task.get("task_id") != material.task_id
            or delegated_task.get("project_id") != project_id
            or delegated_task.get("assigned_to") != material.role
            or delegated_task.get("status") != "assigned"
            or delegated_task.get("room_id") != room_id
            or delegated.get("synced") is not True
        ):
            raise DriverError("delegation_invalid", f"delegate-{material.stage}")
        assignment_notification = _expect_notification(
            delegated,
            event="delegate_task",
            project_id=project_id,
            summary=(f"delegate_task: {material.task_id} assigned to {material.role}"),
            target_room=room_id,
            stage=f"delegate-{material.stage}-notification",
        )
        assignee_matrix_id = worker_matrix_ids[material.role]
        deliver_notification(
            assignment_notification,
            kind="assignment",
            message_text=(
                f"[CONFORMANCE FIXTURE][ASSIGNMENT] {assignee_matrix_id} "
                f"stage={material.stage} task={material.task_id} "
                f"skill={material.skill}. Verify the synced, digest-bound signed "
                "spec; ACK idempotently; run only the packaged validator/fixture "
                "contract; submit the bounded result."
            ),
            expected_mentions=[assignee_matrix_id],
            stage=f"delegate-{material.stage}-message",
        )

        proof = _validate_worker_proof(
            backend.worker_execute(material),
            material,
        )
        worker_proofs[material.stage] = proof
        _validate_checked_task(
            backend.leader_call(
                "taskflow",
                {
                    "action": "check_task",
                    "payload": {"taskId": material.task_id},
                },
            ),
            material,
        )
        if not accept:
            return
        accepted = _expect_ok(
            backend.leader_call(
                "projectflow",
                {
                    "action": "accept_task_result",
                    "riskTier": RISK_TIER,
                    "payload": {
                        "projectId": project_id,
                        "taskId": material.task_id,
                        "resultStatus": "SUCCESS",
                        "accepted": True,
                        "summary": material.summary,
                    },
                },
            ),
            tool="projectflow",
            action="accept_task_result",
            stage=f"accept-{material.stage}",
        )
        if accepted.get("accepted") is not True or accepted.get("nodeStatus") != "completed":
            raise DriverError("acceptance_invalid", f"accept-{material.stage}")
        _project(
            accepted,
            project_id=project_id,
            binding_sha256=binding_sha256,
            stage=f"accept-{material.stage}",
        )
        accepted_notification = _expect_notification(
            accepted,
            event="accept_task_result",
            project_id=project_id,
            summary=(f"accept_task_result: {material.task_id} -> completed"),
            target_room=None,
            stage=f"accept-{material.stage}-notification",
        )
        deliver_notification(
            accepted_notification,
            kind="status",
            message_text=(
                f"[CONFORMANCE FIXTURE][STATUS] stage={material.stage} "
                f"task={material.task_id} accepted after effective-result, "
                "validator, signature, idempotency, and conflict checks."
            ),
            expected_mentions=[],
            stage=f"accept-{material.stage}-message",
        )

    budget = FixtureGenerationBudget()
    run_material(materials["triage"], accept=True)
    run_material(materials["locator"], accept=True)
    budget.consume(1)
    run_material(materials["coder-1"], accept=True)
    run_material(materials["tester-1"], accept=False)

    iteration_one = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "record_loop_iteration",
                "riskTier": RISK_TIER,
                "payload": {
                    "projectId": project_id,
                    "iteration": 1,
                    "decision": "replan",
                    "summary": "Candidate one failed; route bounded evidence through Leader.",
                    "nextAction": "Generate and test candidate two.",
                },
            },
        ),
        tool="projectflow",
        action="record_loop_iteration",
        stage="record-failed-iteration",
    )
    iteration_project, _ = _project(
        iteration_one,
        project_id=project_id,
        binding_sha256=binding_sha256,
        stage="record-failed-iteration",
    )
    loop = iteration_project.get("loop")
    if (
        not isinstance(loop, dict)
        or loop.get("current_iteration") != 1
        or loop.get("status") != "running"
        or not isinstance(loop.get("history"), list)
        or len(loop["history"]) != 1
        or loop["history"][0].get("decision") != "replan"
    ):
        raise DriverError("loop_iteration_invalid", "record-failed-iteration")
    failure_notification = _expect_notification(
        iteration_one,
        event="record_loop_iteration",
        project_id=project_id,
        summary="record_loop_iteration: iteration 1 -> replan",
        target_room=None,
        stage="record-failed-iteration-notification",
    )
    deliver_notification(
        failure_notification,
        kind="failure",
        message_text=(
            f"[CONFORMANCE FIXTURE][FAILURE] project={project_id} tester-1 "
            "returned effective FAILED. The node is retained as revision; "
            "Loop iteration 1 recorded replan before routing bounded failure "
            "evidence to fixture candidate 2."
        ),
        expected_mentions=[],
        stage="record-failed-iteration-message",
    )

    recovery_statuses = {
        "triage": "completed",
        "locator": "completed",
        "coder-1": "completed",
        "tester-1": "revision",
        "coder-2": "planned",
        "tester-2": "planned",
        "reviewer": "planned",
        "experience": "planned",
    }
    recovery_plan = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "plan_loop",
                "riskTier": RISK_TIER,
                "payload": {
                    "projectId": project_id,
                    "goal": "Produce one reviewed green candidate and trusted experience.",
                    "stopCondition": "Green tests, approved review, and stored experience.",
                    "iterationTemplate": (
                        "TeamLeader validates every result and replans only from typed evidence."
                    ),
                    "maxIterations": MAX_FIXTURE_GENERATION_ATTEMPTS,
                    "currentIteration": 1,
                    "status": "running",
                    "tasks": _plan_tasks(
                        materials,
                        STAGE_ORDER,
                        recovery_statuses,
                    ),
                },
            },
        ),
        tool="projectflow",
        action="plan_loop",
        stage="recovery-loop-plan",
    )
    recovery_project, _ = _project(
        recovery_plan,
        project_id=project_id,
        binding_sha256=binding_sha256,
        stage="recovery-loop-plan",
    )
    _loop_tasks(
        recovery_project,
        _expected_loop_tasks(materials, STAGE_ORDER, recovery_statuses),
        "recovery-loop-plan",
    )
    recovery_loop = recovery_project["loop"]
    if (
        recovery_loop.get("current_iteration") != 1
        or recovery_loop.get("status") != "running"
        or len(recovery_loop.get("history", [])) != 1
    ):
        raise DriverError("loop_history_lost", "recovery-loop-plan")
    recovery_notification = _expect_notification(
        recovery_plan,
        event="plan_loop",
        project_id=project_id,
        summary=f"plan_loop: {PROJECT_TITLE}",
        target_room=None,
        stage="recovery-loop-plan-notification",
    )
    deliver_notification(
        recovery_notification,
        kind="status",
        message_text=(
            f"[CONFORMANCE FIXTURE][STATUS] project={project_id} recovery "
            "Loop plan recorded with tester-1=revision and the bounded "
            "coder-2 -> tester-2 -> reviewer -> experience branch."
        ),
        expected_mentions=[],
        stage="recovery-loop-plan-message",
    )

    budget.consume(2)
    run_material(materials["coder-2"], accept=True)
    run_material(materials["tester-2"], accept=True)
    run_material(materials["reviewer"], accept=True)
    run_material(materials["experience"], accept=True)

    budget_policy_probe = FixtureGenerationBudget()
    for allowed_attempt in range(1, MAX_FIXTURE_GENERATION_ATTEMPTS + 1):
        budget_policy_probe.consume(allowed_attempt)
    try:
        budget_policy_probe.consume(MAX_FIXTURE_GENERATION_ATTEMPTS + 1)
    except DriverError as exc:
        if exc.code != "fixture_generation_budget_exhausted":
            raise
        fourth_attempt_rejected = True
    else:  # pragma: no cover - fail-closed invariant
        raise DriverError(
            "fixture_generation_budget_probe_failed",
            "fixture-generation-budget",
        )

    iteration_two = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "record_loop_iteration",
                "riskTier": RISK_TIER,
                "payload": {
                    "projectId": project_id,
                    "iteration": 2,
                    "decision": "stop_success",
                    "summary": "Candidate two is green, approved, and distilled.",
                    "nextAction": "Complete and publish sanitized state evidence.",
                },
            },
        ),
        tool="projectflow",
        action="record_loop_iteration",
        stage="record-success-iteration",
    )
    success_project, _ = _project(
        iteration_two,
        project_id=project_id,
        binding_sha256=binding_sha256,
        stage="record-success-iteration",
    )
    success_loop = success_project.get("loop")
    if (
        not isinstance(success_loop, dict)
        or success_loop.get("current_iteration") != 2
        or success_loop.get("status") != "completed"
        or not isinstance(success_loop.get("history"), list)
        or [entry.get("decision") for entry in success_loop["history"]]
        != ["replan", "stop_success"]
    ):
        raise DriverError("loop_iteration_invalid", "record-success-iteration")
    success_notification = _expect_notification(
        iteration_two,
        event="record_loop_iteration",
        project_id=project_id,
        summary="record_loop_iteration: iteration 2 -> stop_success",
        target_room=None,
        stage="record-success-iteration-notification",
    )
    deliver_notification(
        success_notification,
        kind="status",
        message_text=(
            f"[CONFORMANCE FIXTURE][STATUS] project={project_id} Loop "
            "iteration 2 recorded stop_success after fixture candidate 2, "
            "green disposable tests, review, and experience validation."
        ),
        expected_mentions=[],
        stage="record-success-iteration-message",
    )

    completed = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "complete_project",
                "riskTier": RISK_TIER,
                "payload": {"projectId": project_id, "publishArtifacts": False},
            },
        ),
        tool="projectflow",
        action="complete_project",
        stage="complete-project",
    )
    completed_project, _ = _project(
        completed,
        project_id=project_id,
        binding_sha256=binding_sha256,
        stage="complete-project",
    )
    if (
        completed_project.get("status") != "completed"
        or not isinstance(completed_project.get("loop"), dict)
        or completed_project["loop"].get("status") != "completed"
    ):
        raise DriverError("completion_invalid", "complete-project")
    completion_notification = _expect_notification(
        completed,
        event="complete_project",
        project_id=project_id,
        summary=f"complete_project: {PROJECT_TITLE}",
        target_room=None,
        stage="complete-project-notification",
    )
    deliver_notification(
        completion_notification,
        kind="final",
        message_text=(
            f"[CONFORMANCE FIXTURE][FINAL] project={project_id} completed "
            "with 7 completed nodes and tester-1 retained as revision. "
            "This proves deterministic TeamHarness transitions, signed "
            "handoffs, failure replan, and disposable tests only: actual "
            "model calls=0, runtime repository checkout=false, "
            "GitHub MCP calls=0, reviewer repository mutation=false, "
            "repository benchmark=false."
        ),
        expected_mentions=[],
        stage="complete-project-final-message",
    )
    message_kind_counts = {
        kind: sum(receipt["kind"] == kind for receipt in message_receipts)
        for kind in ("assignment", "failure", "final", "status")
    }
    message_event_counts = {
        event: sum(receipt["event"] == event for receipt in message_receipts)
        for event in (
            "accept_task_result",
            "complete_project",
            "create_project",
            "delegate_task",
            "plan_loop",
            "record_loop_iteration",
        )
    }
    if (
        message_kind_counts != {"assignment": 8, "failure": 1, "final": 1, "status": 11}
        or message_event_counts
        != {
            "accept_task_result": 7,
            "complete_project": 1,
            "create_project": 1,
            "delegate_task": 8,
            "plan_loop": 2,
            "record_loop_iteration": 2,
        }
        or len(message_receipts) != 21
        or len(message_ids) != len(message_receipts)
        or sum(receipt["targetMode"] == "hint" for receipt in message_receipts) != 8
    ):
        raise DriverError("notification_coverage_invalid", "complete-project")

    reported = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "mark_requester_report_sent",
                "riskTier": RISK_TIER,
                "payload": {"projectId": project_id},
            },
        ),
        tool="projectflow",
        action="mark_requester_report_sent",
        stage="mark-report-sent",
    )
    reported_project, _ = _project(
        reported,
        project_id=project_id,
        binding_sha256=binding_sha256,
        stage="mark-report-sent",
    )
    requester_report = reported_project.get("requester_report")
    if (
        not isinstance(requester_report, dict)
        or requester_report.get("pending") is not False
        or requester_report.get("task_id") != materials["experience"].task_id
        or not isinstance(requester_report.get("sent_at"), str)
    ):
        raise DriverError("requester_report_pending", "mark-report-sent")

    project_path = f"shared/projects/{project_id}/"
    verified_files = _expect_filesync(
        backend.leader_call(
            "filesync",
            {"action": "push", "path": project_path},
        ),
        action="push",
        path=project_path,
        expected_objects=2,
        stage="filesync-project-push",
    )
    for name in ("meta.json", "plan.md"):
        path = f"{project_path}{name}"
        verified_files += _expect_filesync(
            backend.leader_call("filesync", {"action": "stat", "path": path}),
            action="stat",
            path=path,
            expected_objects=None,
            stage="filesync-project-stat",
        )
    # The push count and the two independent stat proofs describe the same two
    # objects, so do not double-count them in the public object total.
    verified_files = 2
    for material in materials_tuple:
        for name in ("result.handoff.json", "result.handoff.sig.json"):
            path = f"shared/tasks/{material.task_id}/{name}"
            verified_files += _expect_filesync(
                backend.leader_call("filesync", {"action": "stat", "path": path}),
                action="stat",
                path=path,
                expected_objects=None,
                stage="filesync-task-stat",
            )

    resolved = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "resolve_project",
                "riskTier": RISK_TIER,
                "payload": {"projectId": project_id},
            },
        ),
        tool="projectflow",
        action="resolve_project",
        stage="terminal-readback",
    )
    final_project, _ = _project(
        resolved,
        project_id=project_id,
        binding_sha256=binding_sha256,
        stage="terminal-readback",
    )
    final_statuses = {
        stage: ("revision" if stage == "tester-1" else "completed") for stage in STAGE_ORDER
    }
    _loop_tasks(
        final_project,
        _expected_loop_tasks(materials, STAGE_ORDER, final_statuses),
        "terminal-readback",
    )
    final_loop = final_project["loop"]
    final_report = final_project.get("requester_report")
    if (
        final_project.get("status") != "completed"
        or final_loop.get("status") != "completed"
        or final_loop.get("current_iteration") != 2
        or not isinstance(final_report, dict)
        or final_report.get("pending") is not False
    ):
        raise DriverError("terminal_state_invalid", "terminal-readback")

    result = {
        "ok": True,
        "mode": "execute",
        "executionMode": "operator-driven-deterministic-conformance-fixture",
        "projectId": project_id,
        "riskTier": RISK_TIER,
        "projectStatus": "completed",
        "loopStatus": "completed",
        "loopIterations": 2,
        "requesterReportPending": False,
        "teamRoomMessaging": {
            "deliveryVerified": True,
            "notificationHintsHandled": len(message_receipts),
            "messageCount": len(message_receipts),
            "kindCounts": message_kind_counts,
            "eventCounts": message_event_counts,
            "hintTargetCount": 8,
            "fallbackTargetCount": 13,
            "finalMessageBeforeRequesterReportMark": True,
            "receipts": message_receipts,
        },
        "taskNodeCounts": {
            "completed": 7,
            "revision": 1,
        },
        "failedTester": {
            "transportStatus": "FAILED",
            "artifactType": "TestEvidence",
            "envelopeStatus": "retry",
            "executionFailureArtifact": False,
            "projectNodeStatus": "revision",
            "leaderCheckEffective": True,
            "replanRecorded": True,
        },
        "failureContract": {
            "executionFailureArtifact": "SkillFailure",
            "executionFailureEnvelopeStatus": "failed",
            "routeTo": "TeamLeader",
            "workerDirectHumanEscalation": False,
            "stageSkillPoliciesModeled": len(SKILL_FAILURE_PROBE_POLICIES),
            "localSourceBoundContractProbesPassed": len(
                SOURCE_BOUND_FAILURE_PROBE_SKILLS
            ),
            "submittedInSuccessFixture": False,
        },
        "reviewBoundary": {
            "candidateOnly": True,
            "pullRequestUrl": None,
            "repositoryMutation": False,
        },
        "fixtureGenerationBudget": {
            "maxAttempts": budget.maximum,
            "consumedAttempts": list(budget.consumed),
            "remainingAttempts": budget.maximum - len(budget.consumed),
            "fourthAttemptRejected": fourth_attempt_rejected,
        },
        "signing": {
            "algorithm": "Ed25519",
            "authority": "ephemeral-operator-driver",
            "publicKeySha256": envelope_signer.public_key_sha256,
            "signedEnvelopeCount": len(materials_tuple) * 2,
            "remoteVerificationCount": len(materials_tuple) * 2,
            "trustBoundary": (
                "run-local byte integrity, not a persistent human or release identity"
            ),
        },
        "filesync": {
            "projectStatePushed": True,
            "verifiedObjectCount": verified_files,
        },
        "proofs": {
            "stageOrder": list(STAGE_ORDER),
            "packagedValidatorsPassed": len(materials_tuple),
            "idempotentAckCount": len(materials_tuple),
            "idempotentSubmitCount": len(materials_tuple),
            "conflictRejectedCount": len(materials_tuple),
            "isolatedTestRunCount": 2,
            "terminalReadbackVerified": True,
            "driverEnvelopeCausalChainVerified": True,
            "sourceBoundValidatorCount": len(materials_tuple),
        },
        "stageEvidence": [
            {
                "stage": material.stage,
                "taskId": material.task_id,
                "role": material.role,
                "skill": material.skill,
                "resultStatus": material.result_status,
                "sourceRouteSha256": worker_proofs[material.stage]["sourceRouteSha256"],
                "resultHandoffSha256": worker_proofs[material.stage]["resultHandoffSha256"],
                "artifactSha256": worker_proofs[material.stage]["artifactSha256"],
                "validatorSha256": worker_proofs[material.stage]["validatorSha256"],
                "sourceSignatureSha256": worker_proofs[material.stage]["sourceSignatureSha256"],
                "resultSignatureSha256": worker_proofs[material.stage]["resultSignatureSha256"],
            }
            for material in materials_tuple
        ],
        "claims": {
            "autonomousInference": False,
            "actualModelCalls": 0,
            "runtimeRepositoryCheckout": False,
            "actualGitHubMcpCalls": 0,
            "liveBrokerReceiptVerification": False,
            "reviewerRepositoryMutation": False,
            "realRepositoryBenchmark": False,
            "fixtureArtifactsPreGeneratedByOperator": True,
        },
        "skillContractCompatibility": {
            "schemaFieldNames": ["model_call_attempt", "max_model_calls"],
            "interpretation": (
                "deterministic fixture-generation ordinals only; "
                "they do not attest model invocation"
            ),
        },
        "claimBoundary": (
            "real TeamHarness transitions and real disposable unittest processes; "
            "pre-generated deterministic fixture artifacts, zero model calls, "
            "no repository checkout, no GitHub MCP or live Broker receipt, "
            "no repository mutation, and no repository benchmark claim"
        ),
    }
    _assert_public_safe(result)
    return result


_REMOTE_COMMON = r"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import threading
from contextlib import suppress
from pathlib import Path, PurePosixPath

MAX_OUTPUT = 3200000
GUARD = "/opt/devflow/teamharness/guarded_server.py"
SHARED = "/root/hiclaw-fs/shared"

def pairs(items):
    value = {}
    for key, child in items:
        if key in value:
            raise ValueError("duplicate")
        value[key] = child
    return value

def reject_constant(_value):
    raise ValueError("constant")

def load(text):
    return json.loads(
        text,
        object_pairs_hook=pairs,
        parse_constant=reject_constant,
    )

def canonical(value):
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )

def digest(value):
    payload = value if isinstance(value, bytes) else canonical(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def kill(process):
    if process.poll() is not None:
        return
    with suppress(OSError):
        os.killpg(process.pid, signal.SIGKILL)
    with suppress(OSError):
        process.kill()
    with suppress(OSError, subprocess.SubprocessError):
        process.wait(timeout=5)

def request(workspace, document):
    child_environment = dict(os.environ)
    child_environment["TEAMHARNESS_SHARED_DIR"] = SHARED
    try:
        process = subprocess.Popen(
            ["/usr/bin/python3", GUARD],
            cwd=workspace,
            env=child_environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise ValueError("server") from exc
    chunks = []
    state = {"size": 0, "overflow": False, "failed": False}

    def reader():
        try:
            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    return
                state["size"] += len(chunk)
                if state["size"] <= MAX_OUTPUT:
                    chunks.append(chunk)
                else:
                    state["overflow"] = True
        except (OSError, ValueError, AttributeError):
            state["failed"] = True

    def writer():
        try:
            process.stdin.write(canonical(document).encode("utf-8") + b"\n")
            process.stdin.close()
        except (BrokenPipeError, OSError, ValueError, AttributeError):
            state["failed"] = True

    read_thread = threading.Thread(target=reader, daemon=True)
    write_thread = threading.Thread(target=writer, daemon=True)
    read_thread.start()
    write_thread.start()
    timed_out = False
    try:
        process.wait(timeout=150)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill(process)
    finally:
        if process.poll() is None:
            kill(process)
    read_thread.join(timeout=5)
    write_thread.join(timeout=5)
    if (
        timed_out
        or read_thread.is_alive()
        or write_thread.is_alive()
        or state["failed"]
        or state["overflow"]
        or process.returncode != 0
    ):
        kill(process)
        raise ValueError("server")
    value = load(b"".join(chunks).decode("utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("jsonrpc") != "2.0"
        or value.get("id") != 1
        or ("result" in value) == ("error" in value)
    ):
        raise ValueError("server")
    return value

def walk(value):
    values = [value]
    if isinstance(value, dict):
        for child in value.values():
            values.extend(walk(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(walk(child))
    elif isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        try:
            values.extend(walk(load(value)))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    return values

def team_payload(response, tool, action):
    candidates = {}
    for item in walk(response):
        if (
            isinstance(item, dict)
            and isinstance(item.get("ok"), bool)
            and item.get("action") == action
            and item.get("tool") in {None, tool}
        ):
            candidates[canonical(item)] = item
    if len(candidates) != 1:
        raise ValueError("response")
    return next(iter(candidates.values()))

def rpc(workspace, tool, arguments):
    action = arguments.get("action")
    if not isinstance(action, str):
        raise ValueError("action")
    response = request(
        workspace,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        },
    )
    return team_payload(response, tool, action)
""".strip()


_REMOTE_PREFLIGHT_MAIN = r"""
ROLE_SKILLS = {
    "devflow-lead": [],
    "devflow-triage": ["issue-classifier"],
    "devflow-locator": ["code-root-cause", "github-evidence"],
    "devflow-coder": ["patch-generator"],
    "devflow-tester": ["test-runner"],
    "devflow-reviewer": ["experience-distiller", "pr-reviewer"],
}

def main():
    try:
        if len(sys.argv) != 3:
            raise ValueError("argv")
        role, workspace = sys.argv[1:]
        expected_workspace = f"/root/hiclaw-fs/agents/{role}"
        if (
            role not in ROLE_SKILLS
            or workspace != expected_workspace
            or os.environ.get("AGENTTEAMS_WORKER_NAME") != role
            or os.environ.get("HOME") != workspace
            or Path.cwd().resolve(strict=True) != Path(workspace)
        ):
            raise ValueError("identity")
        response = request(
            workspace,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        result = response.get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            raise ValueError("tools")
        names = sorted(
            item.get("name")
            for item in tools
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        )
        expected_tools = (
            ["artifact", "filesync", "health", "message", "projectflow", "roomflow", "taskflow"]
            if role == "devflow-lead"
            else ["health", "taskflow"]
        )
        if names != expected_tools:
            raise ValueError("tools")
        for skill in ROLE_SKILLS[role]:
            root = Path(workspace) / "skills" / skill
            if root.is_symlink() or root.resolve(strict=True) != root:
                raise ValueError("skill")
            for relative in (
                "scripts/validate.py",
                "scripts/_contract.py",
                "references/contract.yaml",
            ):
                path = root / relative
                metadata = path.stat()
                if (
                    path.is_symlink()
                    or path.resolve(strict=True) != path
                    or not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) & 0o022
                    or not 1 <= metadata.st_size <= 1048576
                ):
                    raise ValueError("skill")
        print(canonical({
            "ok": True,
            "role": role,
            "visibleTools": names,
            "skillNames": ROLE_SKILLS[role],
        }))
    except Exception:
        print(canonical({"ok": False, "code": "runtime_preflight_failed"}))
    return 0

raise SystemExit(main())
""".strip()


_REMOTE_LEADER_MAIN = r"""
def main():
    tool = "unknown"
    action = "unknown"
    try:
        if len(sys.argv) != 5:
            raise ValueError("argv")
        role, workspace, tool, action = sys.argv[1:]
        allowed = {
            "projectflow": {
                "resolve_project",
                "create_project",
                "plan_loop",
                "record_loop_iteration",
                "accept_task_result",
                "complete_project",
                "mark_requester_report_sent",
            },
            "taskflow": {"delegate_task", "check_task"},
            "roomflow": {"create_task_room"},
            "filesync": {"push", "stat"},
            "message": {"send"},
        }
        if (
            role != "devflow-lead"
            or workspace != "/root/hiclaw-fs/agents/devflow-lead"
            or os.environ.get("AGENTTEAMS_WORKER_NAME") != role
            or os.environ.get("HOME") != workspace
            or Path.cwd().resolve(strict=True) != Path(workspace)
            or tool not in allowed
            or action not in allowed[tool]
        ):
            raise ValueError("identity")
        raw = sys.stdin.buffer.read(200001)
        if not 1 <= len(raw) <= 200000:
            raise ValueError("input")
        arguments = load(raw.decode("utf-8"))
        if not isinstance(arguments, dict) or arguments.get("action") != action:
            raise ValueError("input")
        print(canonical(rpc(workspace, tool, arguments)))
    except Exception:
        print(canonical({
            "ok": False,
            "tool": tool,
            "action": action,
            "error": "driver_transport_failed",
        }))
    return 0

raise SystemExit(main())
""".strip()


_REMOTE_WORKER_MAIN = r"""
DIGEST = __import__("re").compile(r"[0-9a-f]{64}")
SAFE_ID = __import__("re").compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
EXPECTED_COMMAND = ["python3", "-m", "unittest", "discover", "-s", "tests"]
POLICY_DIGEST = "e1527ec714370ab983443b14559953d1a0d6a0a4d838930a120c3559f095fe13"

def require_digest(value):
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ValueError("digest")
    return value

def safe_relative(value):
    if not isinstance(value, str):
        raise ValueError("path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("path")
    return path

def verify_signature(envelope, signature, public_pem, public_digest):
    if (
        not isinstance(signature, dict)
        or set(signature) != {"signatureB64", "signatureSha256"}
        or not isinstance(public_pem, str)
        or not 1 <= len(public_pem.encode("ascii")) <= 1024
        or digest(public_pem.encode("ascii")) != require_digest(public_digest)
    ):
        raise ValueError("signature")
    try:
        raw = base64.b64decode(signature["signatureB64"], validate=True)
    except (ValueError, TypeError):
        raise ValueError("signature") from None
    if len(raw) != 64 or digest(raw) != require_digest(signature["signatureSha256"]):
        raise ValueError("signature")
    with tempfile.TemporaryDirectory(prefix="devflow-finals-signature-") as directory:
        root = Path(directory)
        public_path = root / "public.pem"
        message_path = root / "message.json"
        signature_path = root / "signature.bin"
        public_path.write_text(public_pem, encoding="ascii")
        message_path.write_bytes(canonical(envelope).encode("utf-8"))
        signature_path.write_bytes(raw)
        completed = subprocess.run(
            [
                "/usr/bin/openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_path),
                "-rawin",
                "-in",
                str(message_path),
                "-sigfile",
                str(signature_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
    if completed.returncode != 0:
        raise ValueError("signature")

def atomic_write(path, payload):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count < 1:
                raise ValueError("write")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def run_once(root):
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=root,
        env={"PYTHONIOENCODING": "utf-8"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
        start_new_session=True,
    )
    return completed.returncode == 0

def verify_execution_fixture(value, source_envelope, result_envelope):
    if value is None:
        return False
    required = {
        "sourcePath",
        "testPath",
        "originalSource",
        "testSource",
        "expectedCandidatePassed",
        "command",
        "publicBinding",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("fixture")
    source_path = safe_relative(value["sourcePath"])
    test_path = safe_relative(value["testPath"])
    if (
        value["command"] != EXPECTED_COMMAND
        or not isinstance(value["originalSource"], str)
        or not isinstance(value["testSource"], str)
        or not isinstance(value["expectedCandidatePassed"], bool)
        or source_path.parent not in test_path.parents
    ):
        raise ValueError("fixture")
    expected_binding = {
        "sourcePath": source_path.as_posix(),
        "testPath": test_path.as_posix(),
        "originalSourceSha256": digest(value["originalSource"].encode("utf-8")),
        "testSourceSha256": digest(value["testSource"].encode("utf-8")),
        "expectedCandidatePassed": value["expectedCandidatePassed"],
        "commandSha256": digest(EXPECTED_COMMAND),
    }
    if value["publicBinding"] != expected_binding:
        raise ValueError("fixture")
    candidate = source_envelope["artifact"]["inline"]
    changes = candidate.get("patch", {}).get("changes", [])
    if (
        not isinstance(changes, list)
        or len(changes) != 1
        or changes[0].get("file_path") != source_path.as_posix()
        or changes[0].get("original_content") != value["originalSource"]
        or not isinstance(changes[0].get("new_content"), str)
    ):
        raise ValueError("fixture")
    with tempfile.TemporaryDirectory(prefix="devflow-finals-test-") as directory:
        checkout = Path(directory)
        source_file = checkout.joinpath(*source_path.parts)
        test_file = checkout.joinpath(*test_path.parts)
        source_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.parent.mkdir(parents=True, exist_ok=True)
        source_file.write_text(value["originalSource"], encoding="utf-8")
        test_file.write_text(value["testSource"], encoding="utf-8")
        execution_root = source_file.parent
        baseline_passed = run_once(execution_root)
        source_file.write_text(changes[0]["new_content"], encoding="utf-8")
        candidate_passed = run_once(execution_root)
        if baseline_passed or candidate_passed is not value["expectedCandidatePassed"]:
            raise ValueError("fixture")
        if test_file.read_text(encoding="utf-8") != value["testSource"]:
            raise ValueError("fixture")
    test_manifest = {
        test_path.as_posix(): digest(value["testSource"].encode("utf-8"))
    }
    expected_integrity = {
        "schema_version": "1.0",
        "policy": "agentteams-bwrap-tests/v1",
        "policy_digest": POLICY_DIGEST,
        "command_digest": digest(EXPECTED_COMMAND),
        "baseline_manifest_digest": digest(test_manifest),
        "candidate_baseline_manifest_digest": digest(test_manifest),
        "candidate_pre_run_manifest_digest": digest(test_manifest),
        "candidate_post_run_manifest_digest": digest(test_manifest),
        "added_tests_manifest_digest": digest({}),
        "baseline_protected_file_count": 1,
        "added_test_file_count": 0,
        "full_suite": False,
        "verified": True,
        "isolation_boundary": (
            "linux-bubblewrap-unshare-all-cap-drop-process-boundary-"
            "not-node-root-or-kernel"
        ),
    }
    inline = result_envelope["artifact"]["inline"]
    result = inline.get("test_result")
    if (
        not isinstance(result, dict)
        or result.get("integrity_attestation") != expected_integrity
        or result.get("failed") != (0 if candidate_passed else 1)
        or result.get("errors") != 0
        or result.get("baseline_comparison", {}).get("regression") is not False
        or result.get("baseline_comparison", {}).get("new_failures") != []
    ):
        raise ValueError("fixture")
    return True

def submission_digest(task_id, status, summary, deliverables):
    return digest({
        "taskId": task_id,
        "status": status,
        "summary": summary,
        "deliverables": deliverables,
    })

def main():
    stage = "bootstrap"
    try:
        if len(sys.argv) != 3:
            raise ValueError("argv")
        role, workspace = sys.argv[1:]
        allowed_roles = {
            "devflow-triage",
            "devflow-locator",
            "devflow-coder",
            "devflow-tester",
            "devflow-reviewer",
        }
        if (
            role not in allowed_roles
            or workspace != f"/root/hiclaw-fs/agents/{role}"
            or os.environ.get("AGENTTEAMS_WORKER_NAME") != role
            or os.environ.get("HOME") != workspace
            or Path.cwd().resolve(strict=True) != Path(workspace)
        ):
            raise ValueError("identity")
        raw = sys.stdin.buffer.read(250001)
        if not 1 <= len(raw) <= 250000:
            raise ValueError("input")
        value = load(raw.decode("utf-8"))
        required = {
            "stage",
            "role",
            "skill",
            "taskId",
            "sourceEnvelope",
            "resultEnvelope",
            "sourceSignature",
            "resultSignature",
            "signerPublicKeyPem",
            "signerPublicKeySha256",
            "resultStatus",
            "summary",
            "deliverables",
            "executionFixture",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("input")
        stage = value["stage"]
        task_id = value["taskId"]
        if (
            value["role"] != role
            or not isinstance(stage, str)
            or not isinstance(task_id, str)
            or SAFE_ID.fullmatch(task_id) is None
            or value["resultStatus"] not in {"SUCCESS", "FAILED"}
            or not isinstance(value["summary"], str)
            or not value["summary"]
            or not isinstance(value["deliverables"], list)
        ):
            raise ValueError("input")
        source = value["sourceEnvelope"]
        result = value["resultEnvelope"]
        if (
            not isinstance(source, dict)
            or not isinstance(result, dict)
            or source.get("task_id") != task_id
            or result.get("task_id") != task_id
            or source.get("skill") != value["skill"]
            or result.get("skill") != value["skill"]
        ):
            raise ValueError("input")
        stage = "verify-signatures"
        verify_signature(
            source,
            value["sourceSignature"],
            value["signerPublicKeyPem"],
            value["signerPublicKeySha256"],
        )
        verify_signature(
            result,
            value["resultSignature"],
            value["signerPublicKeyPem"],
            value["signerPublicKeySha256"],
        )

        stage = "ack"
        ack_arguments = {"action": "ack_task", "payload": {"taskId": task_id}}
        first_ack = rpc(workspace, "taskflow", ack_arguments)
        task = first_ack.get("task")
        if (
            first_ack.get("ok") is not True
            or first_ack.get("action") != "ack_task"
            or not isinstance(task, dict)
            or task.get("task_id") != task_id
            or task.get("assigned_to") != role
            or task.get("status") != "in_progress"
            or first_ack.get("pulled") is not True
            or first_ack.get("synced") is not True
            or first_ack.get("spec", "").rstrip("\n") != canonical(source)
        ):
            raise ValueError("ack")
        second_ack = rpc(workspace, "taskflow", ack_arguments)
        if (
            second_ack.get("ok") is not True
            or second_ack.get("idempotent") is not True
            or second_ack.get("action") != "ack_task"
            or second_ack.get("taskState") != "in_progress"
            or second_ack.get("taskId") != task_id
        ):
            raise ValueError("ack")

        stage = "execute-fixture"
        isolated = verify_execution_fixture(
            value["executionFixture"],
            source,
            result,
        )
        if (role == "devflow-tester") is not isolated:
            raise ValueError("fixture")

        stage = "write-artifacts"
        task_root = Path(workspace) / "shared" / "tasks" / task_id
        if (
            task_root.is_symlink()
            or task_root.resolve(strict=True) != task_root
            or Path(workspace).resolve(strict=True) not in task_root.parents
        ):
            raise ValueError("task-root")
        source_signature_path = task_root / "assignment.sig.json"
        result_path = task_root / "result.handoff.json"
        result_signature_path = task_root / "result.handoff.sig.json"
        markdown_path = task_root / "result.md"
        source_sidecar = {
            "schema": "devflow.detached-handoff-signature/v1",
            "algorithm": "Ed25519",
            "authority": "ephemeral-operator-driver",
            "envelopeSha256": digest(source),
            "publicKeyPem": value["signerPublicKeyPem"],
            "publicKeySha256": value["signerPublicKeySha256"],
            "signatureB64": value["sourceSignature"]["signatureB64"],
            "signatureSha256": value["sourceSignature"]["signatureSha256"],
            "verifiedByRole": role,
        }
        result_sidecar = {
            "schema": "devflow.detached-handoff-signature/v1",
            "algorithm": "Ed25519",
            "authority": "ephemeral-operator-driver",
            "envelopeSha256": digest(result),
            "publicKeyPem": value["signerPublicKeyPem"],
            "publicKeySha256": value["signerPublicKeySha256"],
            "signatureB64": value["resultSignature"]["signatureB64"],
            "signatureSha256": value["resultSignature"]["signatureSha256"],
            "verifiedByRole": role,
        }
        markdown = (
            "# DevFlow AgentTeams result\n\n"
            f"- Stage: `{value['stage']}`\n"
            f"- Task ID: `{task_id}`\n"
            f"- Skill: `{value['skill']}`\n"
            f"- Result status: `{value['resultStatus']}`\n"
            f"- Source route SHA-256: `{digest(source)}`\n"
            f"- Result handoff SHA-256: `{digest(result)}`\n"
            f"- Artifact SHA-256: `{result['artifact']['sha256']}`\n"
        ).encode("utf-8")
        atomic_write(source_signature_path, canonical(source_sidecar).encode("utf-8"))
        atomic_write(result_path, canonical(result).encode("utf-8"))
        atomic_write(result_signature_path, canonical(result_sidecar).encode("utf-8"))
        atomic_write(markdown_path, markdown)

        stage = "submit"
        submit_arguments = {
            "action": "submit_task",
            "payload": {
                "taskId": task_id,
                "status": value["resultStatus"],
                "summary": value["summary"],
                "deliverables": value["deliverables"],
            },
        }
        expected_submission = submission_digest(
            task_id,
            value["resultStatus"],
            value["summary"],
            value["deliverables"],
        )
        first_submit = rpc(workspace, "taskflow", submit_arguments)
        attestation = first_submit.get("skillValidation")
        first_task = first_submit.get("task")
        if (
            first_submit.get("ok") is not True
            or first_submit.get("action") != "submit_task"
            or not isinstance(first_task, dict)
            or first_task.get("task_id") != task_id
            or first_task.get("status") != "submitted"
            or first_task.get("result_status") != value["resultStatus"]
            or first_task.get("summary") != value["summary"]
            or first_task.get("deliverables") != value["deliverables"]
            or first_task.get("result_path") != f"shared/tasks/{task_id}/result.md"
            or first_submit.get("synced") is not True
            or not isinstance(attestation, dict)
            or attestation.get("schema") != "devflow.agentteams.skill-validation/v1"
            or attestation.get("taskId") != task_id
            or attestation.get("skill") != value["skill"]
            or attestation.get("sourceRouteSha256") != digest(source)
            or attestation.get("resultHandoffSha256") != digest(result)
            or attestation.get("artifactSha256") != result["artifact"]["sha256"]
            or DIGEST.fullmatch(str(attestation.get("validatorSha256") or "")) is None
        ):
            raise ValueError("submit")
        second_submit = rpc(workspace, "taskflow", submit_arguments)
        if (
            second_submit.get("ok") is not True
            or second_submit.get("idempotent") is not True
            or second_submit.get("action") != "submit_task"
            or second_submit.get("taskState") != "submitted"
            or second_submit.get("taskId") != task_id
            or second_submit.get("submissionDigest") != expected_submission
        ):
            raise ValueError("submit")
        conflict_arguments = load(canonical(submit_arguments))
        conflict_arguments["payload"]["summary"] = value["summary"] + " Conflict probe."
        expected_conflict = submission_digest(
            task_id,
            value["resultStatus"],
            conflict_arguments["payload"]["summary"],
            value["deliverables"],
        )
        conflict = rpc(workspace, "taskflow", conflict_arguments)
        if (
            conflict.get("ok") is not False
            or conflict.get("error") != "submit_result_conflict"
            or conflict.get("action") != "submit_task"
            or conflict.get("taskId") != task_id
            or conflict.get("currentDigest") != expected_submission
            or conflict.get("requestedDigest") != expected_conflict
        ):
            raise ValueError("conflict")
        print(canonical({
            "ok": True,
            "taskId": task_id,
            "stage": value["stage"],
            "role": role,
            "skill": value["skill"],
            "resultStatus": value["resultStatus"],
            "deliverables": value["deliverables"],
            "sourceRouteSha256": digest(source),
            "resultHandoffSha256": digest(result),
            "artifactSha256": result["artifact"]["sha256"],
            "validatorSha256": attestation["validatorSha256"],
            "signerPublicKeySha256": value["signerPublicKeySha256"],
            "sourceSignatureSha256": value["sourceSignature"]["signatureSha256"],
            "resultSignatureSha256": value["resultSignature"]["signatureSha256"],
            "submissionSha256": expected_submission,
            "conflictRequestedSha256": expected_conflict,
            "sourceSignatureVerified": True,
            "resultSignatureVerified": True,
            "ackIdempotentRetry": True,
            "firstSubmit": True,
            "idempotentRetry": True,
            "conflictRetry": True,
            "isolatedExecutionVerified": isolated,
        }))
    except Exception:
        print(canonical({
            "ok": False,
            "code": "worker_execution_failed",
            "stage": stage if isinstance(stage, str) else "unknown",
        }))
    return 0

raise SystemExit(main())
""".strip()


REMOTE_PREFLIGHT_HELPER = _REMOTE_COMMON + "\n\n" + _REMOTE_PREFLIGHT_MAIN
REMOTE_LEADER_HELPER = _REMOTE_COMMON + "\n\n" + _REMOTE_LEADER_MAIN
REMOTE_WORKER_HELPER = _REMOTE_COMMON + "\n\n" + _REMOTE_WORKER_MAIN

HOST_PREFLIGHT_TIMEOUT_SECONDS = 240
HOST_LEADER_TIMEOUT_SECONDS = 240
HOST_WORKER_TIMEOUT_SECONDS = 540


class KubernetesBackend:
    """Production backend for the fixed six-role AgentTeams deployment."""

    def __init__(self, kubectl: str = "kubectl") -> None:
        if (
            not isinstance(kubectl, str)
            or not kubectl
            or len(kubectl.encode("utf-8")) > 260
            or CONTROL.search(kubectl) is not None
        ):
            raise DriverError("kubectl_invalid", "input")
        self.kubectl = kubectl
        self.runner = _CommandRunner()
        self._targets: dict[str, Target] = {}

    def _kubectl(self, *arguments: str) -> list[str]:
        return [self.kubectl, "--namespace", NAMESPACE, *arguments]

    def _exec(
        self,
        target: Target,
        helper: str,
        helper_arguments: list[str],
        *,
        input_data: bytes | None = None,
        timeout_seconds: int,
    ) -> str:
        command = self._kubectl("exec")
        command.append("--stdin")
        command.extend(
            [
                target.pod_name,
                "--container",
                CONTAINER_NAME,
                "--",
                "python3",
                "-c",
                REMOTE_STDIN_BOOTSTRAP,
                *helper_arguments,
            ]
        )
        encoded = [item.encode("utf-8") for item in command]
        if (
            any(len(item) > MAX_KUBECTL_ARGUMENT_BYTES for item in encoded)
            or sum(len(item) + 1 for item in encoded) > MAX_KUBECTL_ARGV_BYTES
        ):
            raise DriverError("kubectl_argv_too_large", "transport")
        return self.runner.run(
            command,
            input_data=_remote_frame(helper, input_data),
            timeout=timeout_seconds,
        )

    @staticmethod
    def _json_object(text: str, stage: str) -> dict[str, Any]:
        try:
            value = _strict_loads(text)
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise DriverError("remote_summary_invalid", stage) from exc
        if not isinstance(value, dict):
            raise DriverError("remote_summary_invalid", stage)
        return value

    def preflight(self) -> RuntimeContext:
        self.runner.run([self.kubectl, "version", "--request-timeout=10s"], timeout=20)
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
            targets = discover_targets(team, pods)
        except (ReconcileError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DriverError("runtime_discovery_failed", "runtime-preflight") from exc
        by_role = {target.role_name: target for target in targets}
        if set(by_role) != set(ALL_ROLES) or len(by_role) != len(targets):
            raise DriverError("runtime_set_invalid", "runtime-preflight")
        expected_skills = {
            LEADER_ROLE: [],
            TRIAGE_ROLE: ["issue-classifier"],
            LOCATOR_ROLE: ["code-root-cause", "github-evidence"],
            CODER_ROLE: ["patch-generator"],
            TESTER_ROLE: ["test-runner"],
            REVIEWER_ROLE: ["experience-distiller", "pr-reviewer"],
        }
        for role in ALL_ROLES:
            target = by_role[role]
            report = self._json_object(
                self._exec(
                    target,
                    REMOTE_PREFLIGHT_HELPER,
                    [role, target.workspace],
                    timeout_seconds=HOST_PREFLIGHT_TIMEOUT_SECONDS,
                ),
                "runtime-preflight",
            )
            expected_tools = (
                [
                    "artifact",
                    "filesync",
                    "health",
                    "message",
                    "projectflow",
                    "roomflow",
                    "taskflow",
                ]
                if role == LEADER_ROLE
                else ["health", "taskflow"]
            )
            if report != {
                "ok": True,
                "role": role,
                "visibleTools": expected_tools,
                "skillNames": expected_skills[role],
            }:
                raise DriverError("runtime_attestation_failed", "runtime-preflight")
        self._targets = by_role
        return RuntimeContext(
            leader_matrix_user_id=by_role[LEADER_ROLE].matrix_user_id,
            worker_matrix_user_ids=tuple(
                (role, by_role[role].matrix_user_id) for role in WORKER_ROLES
            ),
        )

    def _target(self, role: str) -> Target:
        target = self._targets.get(role)
        if target is None:
            raise DriverError("preflight_required", "transport")
        return target

    def leader_call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        target = self._target(LEADER_ROLE)
        action = arguments.get("action")
        if not isinstance(action, str):
            raise DriverError("action_invalid", "transport")
        response = self._exec(
            target,
            REMOTE_LEADER_HELPER,
            [target.role_name, target.workspace, tool, action],
            input_data=_canonical_bytes(arguments),
            timeout_seconds=HOST_LEADER_TIMEOUT_SECONDS,
        )
        return self._json_object(response, "transport")

    @staticmethod
    def _material_payload(material: StageMaterial) -> dict[str, Any]:
        fixture = material.execution_fixture
        return {
            "stage": material.stage,
            "role": material.role,
            "skill": material.skill,
            "taskId": material.task_id,
            "sourceEnvelope": material.source_envelope,
            "resultEnvelope": material.result_envelope,
            "sourceSignature": {
                "signatureB64": material.source_signature.signature_b64,
                "signatureSha256": material.source_signature.signature_sha256,
            },
            "resultSignature": {
                "signatureB64": material.result_signature.signature_b64,
                "signatureSha256": material.result_signature.signature_sha256,
            },
            "signerPublicKeyPem": material.signer_public_key_pem,
            "signerPublicKeySha256": material.signer_public_key_sha256,
            "resultStatus": material.result_status,
            "summary": material.summary,
            "deliverables": material.deliverables,
            "executionFixture": (
                None
                if fixture is None
                else {
                    "sourcePath": fixture.source_path,
                    "testPath": fixture.test_path,
                    "originalSource": fixture.original_source,
                    "testSource": fixture.test_source,
                    "expectedCandidatePassed": fixture.expected_candidate_passed,
                    "command": list(fixture.command),
                    "publicBinding": fixture.public_binding(),
                }
            ),
        }

    def worker_execute(self, material: StageMaterial) -> dict[str, Any]:
        target = self._target(material.role)
        response = self._exec(
            target,
            REMOTE_WORKER_HELPER,
            [target.role_name, target.workspace],
            input_data=_canonical_bytes(self._material_payload(material)),
            timeout_seconds=HOST_WORKER_TIMEOUT_SECONDS,
        )
        value = self._json_object(response, f"worker-{material.stage}")
        if value.get("ok") is not True:
            remote_stage = value.get("stage")
            allowed_stages = {
                "bootstrap",
                "verify-signatures",
                "ack",
                "execute-fixture",
                "write-artifacts",
                "submit",
            }
            if (
                set(value) != {"ok", "code", "stage"}
                or value.get("ok") is not False
                or value.get("code") != "worker_execution_failed"
                or remote_stage not in allowed_stages
            ):
                raise DriverError("remote_summary_invalid", f"worker-{material.stage}")
            raise DriverError(
                "worker_execution_failed",
                f"worker-{material.stage}-{remote_stage}",
            )
        return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Plan or explicitly execute one deterministic AgentTeams/TeamHarness "
            "conformance fixture."
        )
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="contact the fixed cluster and create state; omitted means no-contact plan",
    )
    parser.add_argument(
        "--project-id",
        help=f"fresh id beginning with {PROJECT_PREFIX!r}; required with --execute",
    )
    parser.add_argument(
        "--confirm",
        help="fixed confirmation phrase; required with --execute",
    )
    parser.add_argument("--kubectl", default="kubectl", help="kubectl executable")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not args.execute:
            if args.project_id is not None or args.confirm is not None:
                raise DriverError("execute_flag_required", "input")
            result = plan_report()
        else:
            if args.project_id is None or args.confirm is None:
                raise DriverError("execute_arguments_required", "input")
            # Reject unsafe input before constructing a backend or contacting
            # the cluster.
            _validate_project_id(args.project_id)
            if args.confirm != CONFIRMATION:
                raise DriverError("confirmation_required", "input")
            result = execute_finals_flow(
                KubernetesBackend(args.kubectl),
                project_id=args.project_id,
                confirmation=args.confirm,
            )
    except DriverError as exc:
        print(
            _canonical_text(
                {
                    "ok": False,
                    "code": exc.code,
                    "stage": exc.stage,
                }
            )
        )
        return 1
    print(_canonical_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
