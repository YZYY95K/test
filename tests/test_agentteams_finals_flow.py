"""High-value fail-closed tests for the AgentTeams finals flow driver."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import shutil
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import scripts.run_agentteams_finals_flow as driver
from devflow.security.secrets import contains_secret
from scripts.run_agentteams_finals_flow import (
    CODER_ROLE,
    CONFIRMATION,
    DIGEST,
    LEADER_ROLE,
    LOCATOR_ROLE,
    MAX_FIXTURE_GENERATION_ATTEMPTS,
    REMOTE_LEADER_HELPER,
    REMOTE_PREFLIGHT_HELPER,
    REMOTE_WORKER_HELPER,
    REVIEWER_ROLE,
    RISK_TIER,
    SOURCE,
    STAGE_ORDER,
    TESTER_ROLE,
    TRIAGE_ROLE,
    WORKER_ROLES,
    DriverError,
    EnvelopeSigner,
    FixtureGenerationBudget,
    RuntimeContext,
    StageMaterial,
    TestReceiptSigner,
    _canonical_bytes,
    _digest,
    _submission_digest,
    _validate_project_id,
    build_stage_materials,
    execute_finals_flow,
    main,
    plan_report,
    validate_stage_materials,
)

PROJECT_ID = "devflow-finals-20260729a"
ROOM_ID = "!" + "devflow-finals-room" + ":matrix.example"
LEADER_MATRIX_ID = f"@{LEADER_ROLE}:matrix.example"
WORKER_MATRIX_IDS = tuple((role, f"@{role}:matrix.example") for role in WORKER_ROLES)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _openssl() -> Path:
    discovered = shutil.which("openssl")
    candidates = (
        Path(discovered) if discovered else None,
        Path(r"C:\Program Files\Git\usr\bin\openssl.exe"),
        Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe"),
        Path("/usr/bin/openssl"),
    )
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate.resolve()
    pytest.skip("OpenSSL with Ed25519 support is unavailable")


def _receipt_trust(
    tmp_path: Path,
    signer: TestReceiptSigner,
) -> tuple[dict[str, Any], Path, Path]:
    public_key = tmp_path / "test-receipt-ed25519.pub"
    policy_path = tmp_path / "test-receipt-policy.json"
    ledger_path = tmp_path / "test-receipt-ledger.json"
    manifest_path = tmp_path / "install-manifest.json"
    public_key.write_bytes(signer.public_key_pem_bytes)
    public_key.chmod(0o444)
    ledger_path.write_bytes(
        _canonical_bytes(
            {
                "schemaVersion": GUARD.TEST_RECEIPT_LEDGER_SCHEMA,
                "reservations": {},
            }
        )
    )
    ledger_path.chmod(0o600)
    policy = {
        "schemaVersion": "1.0",
        "algorithm": GUARD.TEST_RECEIPT_ALGORITHM,
        "audience": GUARD.TEST_RECEIPT_AUDIENCE,
        "issuer": GUARD.TEST_RECEIPT_ISSUER,
        "signatureDomain": GUARD.TEST_RECEIPT_SCHEMA,
        "publicKeyPath": str(public_key),
        "publicKeyFileSha256": hashlib.sha256(
            signer.public_key_pem_bytes
        ).hexdigest(),
        "publicKeySha256": signer.public_key_sha256,
        "policyAttestationPath": str(policy_path),
        "opensslPath": str(_openssl()),
        "replayLedgerPath": str(ledger_path),
        "replayScope": GUARD.TEST_RECEIPT_REPLAY_SCOPE,
        "replayLedgerPersistentAcrossPodReplacement": (
            GUARD.TEST_RECEIPT_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
        ),
        "receiptLifetimeSeconds": GUARD.TEST_RECEIPT_LIFETIME_SECONDS,
        "maxReceiptLifetimeSeconds": GUARD.TEST_RECEIPT_LIFETIME_SECONDS,
        "maxClockSkewSeconds": 5,
        "ciServerSha256": driver.TEST_CI_SERVER_SHA256,
        "ciPolicySha256": driver.TEST_CI_POLICY_SHA256,
        "repositoryArchiveSha256": driver.TEST_REPOSITORY_ARCHIVE_SHA256,
        "repositoryManifestSha256": driver.TEST_REPOSITORY_MANIFEST_SHA256,
        "repositoryRevision": driver.REPOSITORY_REVISION,
        "remainingThreat": (
            "Temporary test-only key; host root and kernel remain threats. The "
            "replay ledger is Pod-local; Leader Pod replacement can lose replay "
            "history for the 120-second receipt lifetime."
        ),
    }
    policy_path.write_bytes(_canonical_bytes(policy))
    policy_path.chmod(0o444)
    manifest_path.write_bytes(
        _canonical_bytes(
            {
                "sourcePolicy": "test-only",
                "testExecutionReceiptPolicy": policy,
            }
        )
    )
    manifest_path.chmod(0o444)
    return policy, manifest_path, ledger_path


def _guard_module() -> ModuleType:
    path = driver.ROOT / "agentteams" / "teamharness" / "guarded_server.py"
    spec = importlib.util.spec_from_file_location("devflow_finals_guard", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    upstream = ModuleType("server")
    upstream.handle_request = lambda _request: None  # type: ignore[attr-defined]
    previous_upstream = sys.modules.get("server")
    sys.modules["server"] = upstream
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous_upstream is None:
            del sys.modules["server"]
        else:
            sys.modules["server"] = previous_upstream
    return module


GUARD = _guard_module()


class FakeBackend:
    """Stateful TeamHarness-shaped backend with no external contact."""

    def __init__(self) -> None:
        self.preflight_calls = 0
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.worker_calls: list[str] = []
        self.project: dict[str, Any] | None = None
        self.tasks: dict[str, dict[str, Any]] = {}
        self.message_counter = 0
        self.binding = {
            "schema": "devflow.project-binding/v2",
            "audience": "devflow.agentteams.projectflow.approval/v1",
            "approvalDomain": _hash("approval-domain"),
            "policyKeySha256": _hash("policy-key"),
            "riskTierAuthority": "root-only-approval-ledger",
            "sourceAuthority": "persistent-project-state",
            "incarnationAuthority": "guard-generated-root-only-approval-ledger",
            "projectBindingDigest": _hash("project-binding"),
        }

    def preflight(self) -> RuntimeContext:
        self.preflight_calls += 1
        return RuntimeContext(
            leader_matrix_user_id=LEADER_MATRIX_ID,
            worker_matrix_user_ids=WORKER_MATRIX_IDS,
        )

    def _response(self, tool: str, action: str, **values: Any) -> dict[str, Any]:
        response = {"ok": True, "tool": tool, "action": action, **values}
        if tool == "projectflow" and "project" in response:
            response["binding"] = deepcopy(self.binding)
            response["project"]["binding"] = deepcopy(self.binding)
        return response

    def _loop_task(self, task_id: str) -> dict[str, Any]:
        assert self.project is not None
        loop = self.project["loop"]
        return next(task for task in loop["tasks"] if task["task_id"] == task_id)

    def _notification(
        self,
        event: str,
        summary: str,
        *,
        target_room: str | None = None,
    ) -> dict[str, Any]:
        assert self.project is not None
        value: dict[str, Any] = {
            "event": event,
            "projectId": self.project["project_id"],
            "summary": summary,
        }
        if target_room is not None:
            value["targetRoom"] = target_room
        return value

    def leader_call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        action = str(arguments.get("action") or "")
        self.calls.append((tool, action, deepcopy(arguments)))
        payload = arguments.get("payload", {})
        assert isinstance(payload, dict)

        if (tool, action) == ("projectflow", "resolve_project"):
            project_id = payload["projectId"]
            if self.project is None or self.project["project_id"] != project_id:
                return {
                    "ok": False,
                    "tool": tool,
                    "action": action,
                    "error": "project not found",
                }
            return self._response(tool, action, project=deepcopy(self.project))

        if (tool, action) == ("taskflow", "check_task"):
            task_id = payload["taskId"]
            task = self.tasks.get(task_id)
            if task is None:
                return {
                    "ok": False,
                    "tool": tool,
                    "action": action,
                    "error": "task not found",
                }
            deliverables = list(task.get("deliverables", []))
            return self._response(
                tool,
                action,
                task=deepcopy(task),
                result={
                    "status": task["result_status"],
                    "summary": task["summary"],
                    "deliverables": deliverables,
                },
                validationErrors=[],
                effective=task["status"] == "submitted",
                pulled=True,
            )

        if (tool, action) == ("projectflow", "create_project"):
            self.project = {
                "project_id": payload["projectId"],
                "title": payload["title"],
                "source": payload["source"],
                "status": "active",
                "tasks": [],
                "risk_tier": arguments["riskTier"],
            }
            return self._response(
                tool,
                action,
                project=deepcopy(self.project),
                notificationNeeded=self._notification(
                    action,
                    f"{action}: {self.project['title']}",
                ),
            )

        if (tool, action) == ("projectflow", "plan_loop"):
            assert self.project is not None
            previous_loop = self.project.get("loop", {})
            history = deepcopy(previous_loop.get("history", []))
            tasks = [
                {
                    "task_id": raw["taskId"],
                    "title": raw["title"],
                    "assigned_to": raw["assignedTo"],
                    "depends_on": list(raw["dependsOn"]),
                    "status": raw["status"],
                }
                for raw in payload["tasks"]
            ]
            loop = {
                "goal": payload["goal"],
                "stop_condition": payload["stopCondition"],
                "iteration_template": payload["iterationTemplate"],
                "max_iterations": payload["maxIterations"],
                "current_iteration": payload["currentIteration"],
                "status": payload["status"],
                "tasks": tasks,
                "history": history,
            }
            self.project["plan_type"] = "loop"
            self.project["loop"] = loop
            return self._response(
                tool,
                action,
                project=deepcopy(self.project),
                loop=deepcopy(loop),
                readyLoopNodes=[],
                notificationNeeded=self._notification(
                    action,
                    f"{action}: {self.project['title']}",
                ),
            )

        if (tool, action) == ("roomflow", "create_task_room"):
            assert self.project is not None
            invite = list(payload["invite"])
            return self._response(
                tool,
                action,
                roomId=ROOM_ID,
                reused=False,
                private=True,
                joinRule="invite",
                membershipStateVerified=True,
                membershipProjection="non-creator-requested-worker-invitees",
                creator=LEADER_MATRIX_ID,
                invite=invite,
                members=invite,
                authorizedMemberCount=6,
                authorizedMembersSha256=_hash("room-members"),
                binding=deepcopy(self.binding),
            )

        if (tool, action) == ("taskflow", "delegate_task"):
            assert self.project is not None
            task_id = payload["taskId"]
            node = self._loop_task(task_id)
            statuses = {task["task_id"]: task["status"] for task in self.project["loop"]["tasks"]}
            assert node["status"] == "planned"
            assert all(statuses[dependency] == "completed" for dependency in node["depends_on"])
            node["status"] = "assigned"
            task = {
                "task_id": task_id,
                "project_id": payload["projectId"],
                "room_id": payload["roomId"],
                "status": "assigned",
                "spec_path": f"shared/tasks/{task_id}/spec.md",
                "assigned_to": payload["assignedTo"],
                "task_title": node["title"],
            }
            self.tasks[task_id] = task
            return self._response(
                tool,
                action,
                task=deepcopy(task),
                synced=True,
                notificationNeeded=self._notification(
                    action,
                    f"{action}: {task_id} assigned to {payload['assignedTo']}",
                    target_room=payload["roomId"],
                ),
            )

        if (tool, action) == ("projectflow", "accept_task_result"):
            assert self.project is not None
            task_id = payload["taskId"]
            task = self.tasks[task_id]
            assert task["result_status"] == "SUCCESS"
            node = self._loop_task(task_id)
            node["status"] = "completed"
            self.project["requester_report"] = {
                "pending": True,
                "reason": "task_result_accepted",
                "task_id": task_id,
                "result_status": "SUCCESS",
                "summary": payload["summary"],
                "report_path": (f"shared/projects/{self.project['project_id']}/result.md"),
            }
            return self._response(
                tool,
                action,
                project=deepcopy(self.project),
                taskId=task_id,
                nodeStatus="completed",
                accepted=True,
                publishedArtifacts=[],
                notificationNeeded=self._notification(
                    action,
                    f"{action}: {task_id} -> completed",
                ),
            )

        if (tool, action) == ("projectflow", "record_loop_iteration"):
            assert self.project is not None
            loop = self.project["loop"]
            loop["current_iteration"] = payload["iteration"]
            loop["status"] = {
                "replan": "running",
                "stop_success": "completed",
            }[payload["decision"]]
            loop["history"].append(
                {
                    "iteration": payload["iteration"],
                    "decision": payload["decision"],
                    "summary": payload["summary"],
                    "next_action": payload["nextAction"],
                }
            )
            return self._response(
                tool,
                action,
                project=deepcopy(self.project),
                loop=deepcopy(loop),
                readyLoopNodes=[],
                notificationNeeded=self._notification(
                    action,
                    (f"{action}: iteration {payload['iteration']} -> {payload['decision']}"),
                ),
            )

        if (tool, action) == ("projectflow", "complete_project"):
            assert self.project is not None
            self.project["status"] = "completed"
            self.project["loop"]["status"] = "completed"
            return self._response(
                tool,
                action,
                project=deepcopy(self.project),
                notificationNeeded=self._notification(
                    action,
                    f"{action}: {self.project['title']}",
                ),
            )

        if (tool, action) == ("projectflow", "mark_requester_report_sent"):
            assert self.project is not None
            self.project["requester_report"]["pending"] = False
            self.project["requester_report"]["sent_at"] = "2026-07-29T12:00:00Z"
            return self._response(tool, action, project=deepcopy(self.project))

        if (tool, action) == ("message", "send"):
            assert arguments["channel"] == "matrix"
            assert arguments["target"] == f"room:{ROOM_ID}"
            text = arguments["message"]
            assert isinstance(text, str) and text
            mentions = [matrix_id for _, matrix_id in WORKER_MATRIX_IDS if matrix_id in text]
            content: dict[str, Any] = {
                "msgtype": "m.text",
                "body": text,
                "format": "org.matrix.custom.html",
                "formatted_body": f"<p>{text}</p>",
            }
            if mentions:
                content["m.mentions"] = {"user_ids": mentions}
            self.message_counter += 1
            return self._response(
                tool,
                action,
                channel="matrix",
                target=f"room:{ROOM_ID}",
                targetKind="room",
                mentions=mentions,
                content=content,
                messageId=f"$fake-message-{self.message_counter}",
                sessionRecorded=True,
            )

        if tool == "filesync":
            path = arguments["path"]
            base = {
                "kind": "shared",
                "path": path,
                "localPath": (f"/root/hiclaw-fs/agents/{LEADER_ROLE}/{path.rstrip('/')}"),
                "workspaceBindingSha256": _digest(f"/root/hiclaw-fs/agents/{LEADER_ROLE}".encode()),
            }
            if action == "push":
                return self._response(
                    tool,
                    action,
                    **base,
                    expectedObjectCount=2,
                    verifiedObjectCount=2,
                    localTreeSha256=_hash("project-tree"),
                )
            if action == "stat":
                return self._response(tool, action, **base, exists=True)

        raise AssertionError((tool, action, arguments))

    def worker_execute(self, material: StageMaterial) -> dict[str, Any]:
        self.worker_calls.append(material.stage)
        task = self.tasks[material.task_id]
        assert task["assigned_to"] == material.role
        public = serialization.load_pem_public_key(material.signer_public_key_pem.encode("ascii"))
        assert isinstance(public, Ed25519PublicKey)
        public.verify(
            base64.b64decode(material.source_signature.signature_b64, validate=True),
            _canonical_bytes(material.source_envelope),
        )
        public.verify(
            base64.b64decode(material.result_signature.signature_b64, validate=True),
            _canonical_bytes(material.result_envelope),
        )
        task.update(
            {
                "status": "submitted",
                "result_status": material.result_status,
                "summary": material.summary,
                "deliverables": material.deliverables,
                "submitted_by_role": "worker",
                "result_path": f"shared/tasks/{material.task_id}/result.md",
            }
        )
        self._loop_task(material.task_id)["status"] = "submitted"
        return {
            "ok": True,
            "taskId": material.task_id,
            "stage": material.stage,
            "role": material.role,
            "skill": material.skill,
            "resultStatus": material.result_status,
            "deliverables": material.deliverables,
            "sourceRouteSha256": material.source_route_sha256,
            "resultHandoffSha256": material.result_handoff_sha256,
            "artifactSha256": material.artifact_sha256,
            "validatorSha256": _hash("validator-" + material.skill),
            "signerPublicKeySha256": material.signer_public_key_sha256,
            "sourceSignatureSha256": material.source_signature.signature_sha256,
            "resultSignatureSha256": material.result_signature.signature_sha256,
            "submissionSha256": _submission_digest(
                material.task_id,
                material.result_status,
                material.summary,
                material.deliverables,
            ),
            "conflictRequestedSha256": _submission_digest(
                material.task_id,
                material.result_status,
                material.summary + " Conflict probe.",
                material.deliverables,
            ),
            "sourceSignatureVerified": True,
            "resultSignatureVerified": True,
            "ackIdempotentRetry": True,
            "firstSubmit": True,
            "idempotentRetry": True,
            "conflictRetry": True,
            "isolatedExecutionVerified": material.execution_fixture is not None,
        }


def test_default_plan_is_no_contact_and_names_real_claim_boundary() -> None:
    report = plan_report()

    assert report["mode"] == "plan"
    assert report["writes"] is False
    assert report["executionMode"] == ("operator-driven-deterministic-conformance-fixture")
    assert report["framework"] == "AgentTeams v1.2.0-beta.1 TeamHarness"
    assert report["logicalStages"] == [
        "Triage",
        "Locator",
        "Coder",
        "Tester",
        "Reviewer",
        "Experience",
    ]
    assert report["recovery"] == {
        "firstTesterResult": "FAILED",
        "firstTesterArtifact": "TestEvidence",
        "firstTesterEnvelopeStatus": "retry",
        "projectNode": "revision",
        "route": "Tester -> TeamLeader -> Coder candidate 2 -> Tester",
        "maxFixtureGenerationAttempts": 3,
    }
    assert report["failureContract"] == {
        "executionFailureArtifact": "SkillFailure",
        "executionFailureEnvelopeStatus": "failed",
        "routeTo": "TeamLeader",
        "workerDirectHumanEscalation": False,
        "stageSkillPoliciesModeled": 6,
        "localSourceBoundContractProbes": 4,
        "submittedInSuccessFixture": False,
    }
    assert report["reviewBoundary"] == {
        "candidateOnly": True,
        "pullRequestUrl": None,
        "repositoryMutation": False,
    }
    assert len(report["stages"]) == 25
    assert report["claims"] == {
        "autonomousInference": False,
        "actualModelCalls": 0,
        "runtimeRepositoryCheckout": False,
        "actualGitHubMcpCalls": 0,
        "liveBrokerReceiptVerification": False,
        "reviewerRepositoryMutation": False,
        "realRepositoryBenchmark": False,
        "fixtureArtifactsPreGeneratedByOperator": True,
    }
    assert report["fixtureSourceMetadata"]["embeddedSourceAndTests"] is True
    assert report["fixtureSourceMetadata"]["runtimeRepositoryCheckout"] is False
    assert report["fixtureSourceMetadata"]["actualGitHubMcpCalls"] == 0
    assert report["fixtureSourceMetadata"]["liveBrokerReceiptVerification"] is False
    assert "zero model calls" in report["claimBoundary"]
    assert "no GitHub MCP or live Broker receipt" in report["claimBoundary"]
    assert "no repository benchmark claim" in report["claimBoundary"]


def test_main_plan_never_constructs_a_backend(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden_backend(_kubectl: str) -> None:
        raise AssertionError("plan mode constructed a backend")

    monkeypatch.setattr(driver, "KubernetesBackend", forbidden_backend)

    assert main([]) == 0
    assert '"mode":"plan"' in capsys.readouterr().out


@pytest.mark.parametrize(
    ("confirmation", "project_id", "code"),
    [
        ("wrong", PROJECT_ID, "confirmation_required"),
        (CONFIRMATION, "unsafe", "project_id_invalid"),
    ],
)
def test_input_failure_happens_before_preflight(
    confirmation: str,
    project_id: str,
    code: str,
) -> None:
    backend = FakeBackend()

    with pytest.raises(DriverError) as raised:
        execute_finals_flow(
            backend,
            project_id=project_id,
            confirmation=confirmation,
        )

    assert raised.value.code == code
    assert backend.preflight_calls == 0
    assert backend.calls == []


def test_materials_are_signed_causal_and_validator_accepted() -> None:
    signer = EnvelopeSigner()
    task_ids = _validate_project_id(PROJECT_ID)
    materials = build_stage_materials(
        project_id=PROJECT_ID,
        task_ids=task_ids,
        signer=signer,
    )

    validate_stage_materials(materials, signer)

    assert tuple(material.stage for material in materials) == STAGE_ORDER
    assert materials[3].result_status == "FAILED"
    assert materials[3].result_envelope["artifact"]["type"] == "TestEvidence"
    assert materials[3].result_envelope["status"] == "retry"
    assert materials[4].source_envelope["status"] == "retry"
    assert (
        materials[4].source_envelope["parent_handoff_sha256"] == materials[3].result_handoff_sha256
    )
    # This is a required packaged-skill schema field.  The driver explicitly
    # interprets it as a fixture ordinal, never as proof of a model call.
    assert materials[4].result_envelope["artifact"]["inline"]["model_call_attempt"] == 2
    assert (
        materials[4].result_envelope["artifact"]["inline"]["revision_of"]
        == (materials[3].source_envelope["artifact"]["inline"]["candidate_digest"])
    )

    locator_source = materials[1].source_envelope
    assert locator_source["producer"] == "TeamLeader"
    assert locator_source["artifact"]["type"] == "SkillInvocation"
    locator_input = locator_source["artifact"]["inline"]
    assert set(locator_input) == {
        "issue_id",
        "repository_revision",
        "classified_issue",
        "github_evidence",
    }
    github_evidence = locator_input["github_evidence"]
    assert github_evidence["revision"] == driver.REPOSITORY_REVISION
    assert github_evidence["digest"] == _digest(
        {key: value for key, value in github_evidence.items() if key != "digest"}
    )
    assert {item["path"] for item in github_evidence["evidence"]} == {
        driver.SOURCE_PATH,
        driver.TEST_PATH,
    }

    review_source = materials[6].source_envelope["artifact"]["inline"]
    review_result = materials[6].result_envelope["artifact"]["inline"]
    assert review_source["candidate"] == materials[5].source_envelope["artifact"]["inline"]
    assert review_source["candidate_digest"] == review_source["candidate"]["candidate_digest"]
    security_scan = review_source["evidence"]["security_scan"]
    assert security_scan["report_sha256"] == _digest(
        {key: value for key, value in security_scan.items() if key != "report_sha256"}
    )
    assert review_result["review"]["pr_url"] is None

    experience_result = materials[7].result_envelope["artifact"]["inline"]
    persisted_prose = {
        "summary": experience_result["summary"],
        "reusable_lesson": experience_result["reusable_lesson"],
    }
    assert contains_secret(persisted_prose) is False
    assert experience_result["redaction"] == {
        "policy_version": "1.0",
        "secret_scan_passed": True,
        "pii_scan_passed": True,
    }


def test_experience_redaction_rejects_secret_shaped_persisted_prose() -> None:
    synthetic_secret = "".join(("ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"))

    with pytest.raises(DriverError) as raised:
        driver._experience_redaction_evidence(
            summary=f"Do not persist {synthetic_secret}",
            reusable_lesson="Keep only bounded evidence.",
        )

    assert raised.value.code == "redaction_gate_failed"
    assert raised.value.stage == "experience-output"
    assert synthetic_secret not in str(raised.value)


def test_experience_redaction_fails_closed_when_scanner_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(_value: object) -> bool:
        raise RuntimeError("scanner unavailable")

    monkeypatch.setattr(driver, "contains_secret", unavailable)

    with pytest.raises(DriverError) as raised:
        driver._experience_redaction_evidence(
            summary="Bounded summary.",
            reusable_lesson="Bounded lesson.",
        )

    assert raised.value.code == "redaction_scan_unavailable"
    assert raised.value.stage == "experience-output"


def test_experience_redaction_rejects_email_pii() -> None:
    with pytest.raises(DriverError) as raised:
        driver._experience_redaction_evidence(
            summary="Contact operator@example.invalid for the incident details.",
            reusable_lesson="Keep only bounded evidence.",
        )

    assert raised.value.code == "redaction_gate_failed"
    assert raised.value.stage == "experience-output"


def test_source_bound_validator_rejects_a_result_replayed_against_another_source() -> None:
    materials = build_stage_materials(
        project_id=PROJECT_ID,
        task_ids=_validate_project_id(PROJECT_ID),
        signer=EnvelopeSigner(),
    )
    triage = materials[0]
    result = triage.result_envelope["artifact"]["inline"]
    wrong_source = deepcopy(triage.source_envelope["artifact"]["inline"])
    wrong_source["title"] = "A different issue with the same repository identity"

    with pytest.raises(DriverError) as raised:
        driver._run_validator(
            triage.skill,
            "output",
            result,
            wrong_source,
        )

    assert raised.value.code == "packaged_validator_rejected_fixture"
    assert raised.value.stage == "local-contract"


def test_unified_skill_failure_is_source_bound_and_routes_only_to_leader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    materials = build_stage_materials(
        project_id=PROJECT_ID,
        task_ids=_validate_project_id(PROJECT_ID),
        signer=EnvelopeSigner(),
    )
    checked: set[str] = set()

    for material in materials:
        if material.skill not in driver.SKILL_FAILURE_PROBE_POLICIES:
            continue
        workspace = tmp_path / material.stage
        skill_root = workspace / "skills" / material.skill
        for relative in (
            "scripts/validate.py",
            "scripts/_contract.py",
            "references/contract.yaml",
        ):
            source = driver.ROOT / "skills" / material.skill / relative
            target = skill_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

        source_inline = material.source_envelope["artifact"]["inline"]
        failure = driver._skill_failure_probe(material.skill, source_inline)
        failed_result = deepcopy(material.result_envelope)
        failed_result["status"] = "failed"
        failed_result["artifact"] = driver._artifact(
            "SkillFailure",
            "1.0",
            failure,
        )
        task_root = workspace / "shared" / "tasks" / material.task_id
        task_root.mkdir(parents=True)
        spec_path = f"shared/tasks/{material.task_id}/spec.md"
        result_path = f"shared/tasks/{material.task_id}/result.handoff.json"
        (workspace / spec_path).write_bytes(_canonical_bytes(material.source_envelope))
        (workspace / result_path).write_bytes(_canonical_bytes(failed_result))
        task = {
            "task_id": material.task_id,
            "assigned_to": material.role,
            "status": "in_progress",
            "spec_path": spec_path,
            "deliverables": material.deliverables,
        }
        probe = {
            "task": task,
            "spec": json.dumps(
                material.source_envelope,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        }
        arguments = {
            "action": "submit_task",
            "payload": {
                "taskId": material.task_id,
                "status": "FAILED",
                "summary": failure["summary"],
                "deliverables": material.deliverables,
            },
        }
        identity = {
            "runtimeName": material.role,
            "matrixUserId": f"@{material.role}:matrix.example",
        }
        monkeypatch.setattr(GUARD, "_workspace_path", lambda root=workspace: root)

        attestation = GUARD._verify_skill_transition(
            arguments,
            probe,
            task,
            identity,
        )

        assert failure["route_to"] == "TeamLeader"
        assert failure["source_artifact_sha256"] == _digest(source_inline)
        assert attestation["skill"] == material.skill
        assert attestation["artifactSha256"] == _digest(failure)
        checked.add(material.skill)

    assert checked == set(driver.SKILL_FAILURE_PROBE_POLICIES)


def test_every_material_passes_the_real_teamharness_skill_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = EnvelopeSigner()
    receipt_signer = TestReceiptSigner()
    receipt_policy, manifest_path, ledger_path = _receipt_trust(
        tmp_path,
        receipt_signer,
    )
    materials = build_stage_materials(
        project_id=PROJECT_ID,
        task_ids=_validate_project_id(PROJECT_ID),
        signer=signer,
        receipt_signer=receipt_signer,
    )
    monkeypatch.setattr(GUARD, "INSTALL_MANIFEST", manifest_path)
    consumed_receipts = 0

    for material in materials:
        workspace = tmp_path / material.role
        skill_root = workspace / "skills" / material.skill
        for relative in (
            "scripts/validate.py",
            "scripts/_contract.py",
            "references/contract.yaml",
        ):
            source = driver.ROOT / "skills" / material.skill / relative
            target = skill_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        task_root = workspace / "shared" / "tasks" / material.task_id
        task_root.mkdir(parents=True)
        spec_path = f"shared/tasks/{material.task_id}/spec.md"
        result_path = f"shared/tasks/{material.task_id}/result.handoff.json"
        (workspace / spec_path).write_bytes(_canonical_bytes(material.source_envelope))
        (workspace / result_path).write_bytes(_canonical_bytes(material.result_envelope))
        task = {
            "task_id": material.task_id,
            "assigned_to": material.role,
            "status": "in_progress",
            "spec_path": spec_path,
            "deliverables": material.deliverables,
        }
        probe = {
            "task": task,
            "spec": json.dumps(
                material.source_envelope,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        }
        arguments = {
            "action": "submit_task",
            "payload": {
                "taskId": material.task_id,
                "status": material.result_status,
                "summary": material.summary,
                "deliverables": material.deliverables,
            },
        }
        identity = {
            "runtimeName": material.role,
            "matrixUserId": f"@{material.role}:matrix.example",
        }
        monkeypatch.setattr(GUARD, "_workspace_path", lambda root=workspace: root)

        attestation = GUARD._verify_skill_transition(
            arguments,
            probe,
            task,
            identity,
        )

        assert attestation["schema"] == "devflow.agentteams.skill-validation/v1"
        assert attestation["taskId"] == material.task_id
        assert attestation["skill"] == material.skill
        assert attestation["sourceRouteSha256"] == material.source_route_sha256
        assert attestation["resultHandoffSha256"] == material.result_handoff_sha256
        assert attestation["artifactSha256"] == material.artifact_sha256
        assert all(
            DIGEST.fullmatch(attestation[field])
            for field in (
                "sourceRouteSha256",
                "resultHandoffSha256",
                "artifactSha256",
                "validatorSha256",
            )
        )
        if material.skill == "test-runner":
            assert attestation["testExecutionReceiptJti"] == material.result_envelope[
                "artifact"
            ]["inline"]["test_execution_receipt"]["jti"]
            verified = GUARD._verify_test_execution_receipt(
                receipt_policy,
                material.source_envelope,
                material.result_envelope["artifact"]["inline"],
                now=datetime.now(timezone.utc),
            )
            GUARD._consume_test_execution_receipt(
                receipt_policy,
                material.source_envelope,
                verified,
                now=datetime.now(timezone.utc),
            )
            with pytest.raises(GUARD.GuardPolicyError, match="test_receipt_replayed"):
                GUARD._consume_test_execution_receipt(
                    receipt_policy,
                    material.source_envelope,
                    verified,
                    now=datetime.now(timezone.utc),
                )
            consumed_receipts += 1

    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert consumed_receipts == 2
    assert len(ledger["reservations"]) == 2


def test_tampered_detached_signature_is_rejected() -> None:
    signer = EnvelopeSigner()
    materials = list(
        build_stage_materials(
            project_id=PROJECT_ID,
            task_ids=_validate_project_id(PROJECT_ID),
            signer=signer,
        )
    )
    first = materials[0]
    materials[0] = StageMaterial(
        **{
            **first.__dict__,
            "source_signature": driver.DetachedSignature(
                signature_b64=base64.b64encode(b"\x00" * 64).decode("ascii"),
                signature_sha256=_digest(b"\x00" * 64),
            ),
        }
    )

    with pytest.raises(DriverError, match="envelope_signature_invalid"):
        validate_stage_materials(tuple(materials), signer)


def test_fixture_generation_budget_is_global_sequential_and_caps_at_three() -> None:
    budget = FixtureGenerationBudget()

    budget.consume(1)
    budget.consume(2)
    budget.consume(3)

    assert budget.consumed == (1, 2, 3)
    with pytest.raises(
        DriverError,
        match="fixture_generation_budget_exhausted",
    ):
        budget.consume(4)


def test_full_flow_preserves_failed_tester_and_closes_same_project() -> None:
    backend = FakeBackend()

    result = execute_finals_flow(
        backend,
        project_id=PROJECT_ID,
        confirmation=CONFIRMATION,
    )

    assert result["ok"] is True
    assert result["projectStatus"] == "completed"
    assert result["loopStatus"] == "completed"
    assert result["taskNodeCounts"] == {"completed": 7, "revision": 1}
    assert result["failedTester"] == {
        "transportStatus": "FAILED",
        "artifactType": "TestEvidence",
        "envelopeStatus": "retry",
        "executionFailureArtifact": False,
        "projectNodeStatus": "revision",
        "leaderCheckEffective": True,
        "replanRecorded": True,
    }
    assert result["failureContract"] == {
        "executionFailureArtifact": "SkillFailure",
        "executionFailureEnvelopeStatus": "failed",
        "routeTo": "TeamLeader",
        "workerDirectHumanEscalation": False,
        "stageSkillPoliciesModeled": 6,
        "localSourceBoundContractProbesPassed": 4,
        "submittedInSuccessFixture": False,
    }
    assert result["reviewBoundary"] == {
        "candidateOnly": True,
        "pullRequestUrl": None,
        "repositoryMutation": False,
    }
    assert result["fixtureGenerationBudget"] == {
        "maxAttempts": MAX_FIXTURE_GENERATION_ATTEMPTS,
        "consumedAttempts": [1, 2],
        "remainingAttempts": 1,
        "fourthAttemptRejected": True,
    }
    assert result["claims"] == {
        "autonomousInference": False,
        "actualModelCalls": 0,
        "runtimeRepositoryCheckout": False,
        "actualGitHubMcpCalls": 0,
        "liveBrokerReceiptVerification": False,
        "reviewerRepositoryMutation": False,
        "realRepositoryBenchmark": False,
        "fixtureArtifactsPreGeneratedByOperator": True,
    }
    messaging = result["teamRoomMessaging"]
    assert messaging["deliveryVerified"] is True
    assert messaging["notificationHintsHandled"] == 21
    assert messaging["messageCount"] == 21
    assert messaging["kindCounts"] == {
        "assignment": 8,
        "failure": 1,
        "final": 1,
        "status": 11,
    }
    assert messaging["eventCounts"] == {
        "accept_task_result": 7,
        "complete_project": 1,
        "create_project": 1,
        "delegate_task": 8,
        "plan_loop": 2,
        "record_loop_iteration": 2,
    }
    assert messaging["hintTargetCount"] == 8
    assert messaging["fallbackTargetCount"] == 13
    assert messaging["finalMessageBeforeRequesterReportMark"] is True
    assert len(messaging["receipts"]) == 21
    assert all(
        set(receipt)
        == {
            "event",
            "kind",
            "targetMode",
            "messageSha256",
            "messageIdSha256",
            "sessionRecorded",
        }
        for receipt in messaging["receipts"]
    )
    assert result["signing"]["signedEnvelopeCount"] == 16
    assert result["signing"]["remoteVerificationCount"] == 16
    assert result["filesync"]["verifiedObjectCount"] == 18
    assert result["proofs"] == {
        "stageOrder": list(STAGE_ORDER),
        "packagedValidatorsPassed": 8,
        "idempotentAckCount": 8,
        "idempotentSubmitCount": 8,
        "conflictRejectedCount": 8,
        "isolatedTestRunCount": 2,
        "terminalReadbackVerified": True,
        "driverEnvelopeCausalChainVerified": True,
        "sourceBoundValidatorCount": 8,
    }
    assert backend.worker_calls == list(STAGE_ORDER)
    assert backend.project is not None
    assert backend.project["project_id"] == PROJECT_ID
    assert backend.project["status"] == "completed"
    assert backend.project["loop"]["history"] == [
        {
            "iteration": 1,
            "decision": "replan",
            "summary": "Candidate one failed; route bounded evidence through Leader.",
            "next_action": "Generate and test candidate two.",
        },
        {
            "iteration": 2,
            "decision": "stop_success",
            "summary": "Candidate two is green, approved, and distilled.",
            "next_action": "Complete and publish sanitized state evidence.",
        },
    ]

    accepted_task_ids = [
        call[2]["payload"]["taskId"]
        for call in backend.calls
        if call[:2] == ("projectflow", "accept_task_result")
    ]
    tester_one_id = _validate_project_id(PROJECT_ID)["tester-1"]
    assert tester_one_id not in accepted_task_ids
    assert len(accepted_task_ids) == 7

    message_calls = [
        (index, arguments)
        for index, (tool, action, arguments) in enumerate(backend.calls)
        if (tool, action) == ("message", "send")
    ]
    assert len(message_calls) == 21
    final_index, final_arguments = next(
        (index, arguments)
        for index, arguments in message_calls
        if "[FINAL]" in arguments["message"]
    )
    mark_index = next(
        index
        for index, call in enumerate(backend.calls)
        if call[:2] == ("projectflow", "mark_requester_report_sent")
    )
    assert final_index < mark_index
    assert "actual model calls=0" in final_arguments["message"]
    assert "repository benchmark=false" in final_arguments["message"]


def test_recovery_plan_keeps_graph_and_signed_causality_distinct() -> None:
    backend = FakeBackend()

    execute_finals_flow(
        backend,
        project_id=PROJECT_ID,
        confirmation=CONFIRMATION,
    )

    loop_plans = [
        arguments["payload"]
        for tool, action, arguments in backend.calls
        if (tool, action) == ("projectflow", "plan_loop")
    ]
    assert len(loop_plans) == 2
    recovery = {task["taskId"]: task for task in loop_plans[1]["tasks"]}
    ids = _validate_project_id(PROJECT_ID)
    assert recovery[ids["tester-1"]]["status"] == "revision"
    assert recovery[ids["coder-2"]]["dependsOn"] == [ids["coder-1"]]

    signer = EnvelopeSigner()
    material_by_stage = {
        item.stage: item
        for item in build_stage_materials(
            project_id=PROJECT_ID,
            task_ids=ids,
            signer=signer,
        )
    }
    assert material_by_stage["coder-2"].source_envelope["parent_task_id"] == (ids["tester-1"])


def test_conflict_proof_is_mandatory() -> None:
    class TamperedBackend(FakeBackend):
        def worker_execute(self, material: StageMaterial) -> dict[str, Any]:
            proof = super().worker_execute(material)
            if material.stage == "coder-2":
                proof["conflictRetry"] = False
            return proof

    with pytest.raises(DriverError) as raised:
        execute_finals_flow(
            TamperedBackend(),
            project_id=PROJECT_ID,
            confirmation=CONFIRMATION,
        )

    assert raised.value.code == "worker_proof_invalid"
    assert raised.value.stage == "worker-coder-2"


def test_tampered_notification_hint_fails_before_the_assignment_message() -> None:
    class TamperedNotificationBackend(FakeBackend):
        def leader_call(
            self,
            tool: str,
            arguments: dict[str, Any],
        ) -> dict[str, Any]:
            response = super().leader_call(tool, arguments)
            payload = arguments.get("payload", {})
            if (tool, arguments.get("action")) == ("taskflow", "delegate_task") and payload.get(
                "taskId", ""
            ).endswith("-triage"):
                response["notificationNeeded"]["targetRoom"] = (
                    "!" + "untrusted" + ":matrix.example"
                )
            return response

    backend = TamperedNotificationBackend()
    with pytest.raises(DriverError) as raised:
        execute_finals_flow(
            backend,
            project_id=PROJECT_ID,
            confirmation=CONFIRMATION,
        )

    assert raised.value.code == "notification_hint_invalid"
    assert raised.value.stage == "delegate-triage-notification"
    assert not any(
        tool == "message" and "[ASSIGNMENT]" in arguments.get("message", "")
        for tool, _action, arguments in backend.calls
    )


def test_failed_final_room_delivery_never_marks_requester_report_sent() -> None:
    class FailedFinalMessageBackend(FakeBackend):
        def leader_call(
            self,
            tool: str,
            arguments: dict[str, Any],
        ) -> dict[str, Any]:
            response = super().leader_call(tool, arguments)
            if (tool, arguments.get("action")) == (
                "message",
                "send",
            ) and "[FINAL]" in arguments.get("message", ""):
                response["ok"] = False
                response["error"] = "bounded Matrix delivery failure"
            return response

    backend = FailedFinalMessageBackend()
    with pytest.raises(DriverError) as raised:
        execute_finals_flow(
            backend,
            project_id=PROJECT_ID,
            confirmation=CONFIRMATION,
        )

    assert raised.value.code == "remote_action_failed"
    assert raised.value.stage == "complete-project-final-message"
    assert not any(
        call[:2] == ("projectflow", "mark_requester_report_sent") for call in backend.calls
    )
    assert backend.project is not None
    assert backend.project["requester_report"]["pending"] is True


def test_remote_helpers_are_bounded_compilable_and_contain_real_gates() -> None:
    for name, helper in (
        ("preflight", REMOTE_PREFLIGHT_HELPER),
        ("leader", REMOTE_LEADER_HELPER),
        ("worker", REMOTE_WORKER_HELPER),
    ):
        compile(helper, f"<{name}>", "exec")
        assert 1 <= len(helper.encode("utf-8")) <= 400_000

    assert "/usr/bin/openssl" in REMOTE_WORKER_HELPER
    assert '"unittest", "discover"' in REMOTE_WORKER_HELPER
    assert "submit_result_conflict" in REMOTE_WORKER_HELPER
    assert "record_loop_iteration" in REMOTE_LEADER_HELPER
    assert '"message": {"send"}' in REMOTE_LEADER_HELPER


def test_material_transport_never_contains_a_private_key() -> None:
    signer = EnvelopeSigner()
    material = build_stage_materials(
        project_id=PROJECT_ID,
        task_ids=_validate_project_id(PROJECT_ID),
        signer=signer,
    )[0]

    payload = driver.KubernetesBackend._material_payload(material)
    encoded = _canonical_bytes(payload)

    assert b"PRIVATE KEY" not in encoded
    assert b"BEGIN PUBLIC KEY" in encoded
    assert payload["signerPublicKeySha256"] == _digest(
        payload["signerPublicKeyPem"].encode("ascii")
    )


def test_role_and_risk_scope_are_exact() -> None:
    assert WORKER_ROLES == (
        TRIAGE_ROLE,
        LOCATOR_ROLE,
        CODER_ROLE,
        TESTER_ROLE,
        REVIEWER_ROLE,
    )
    assert RISK_TIER == "T2"
    assert SOURCE == "operator-driven"
