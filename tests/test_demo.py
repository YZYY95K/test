"""End-to-end acceptance test for the credential-free demo."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from devflow.demo import run_demo
from devflow.exceptions import SkillError
from devflow.skills.contracts import HandoffEnvelope
from devflow.skills.experience_distiller import ExperienceDistillerSkill

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "prelim_sample"


class RecordingStore:
    """Test sink proving security checks happen before persistence."""

    def __init__(self) -> None:
        self.records: list[str] = []

    async def store(
        self, pattern_id: str, summary: str, metadata: dict[str, Any]
    ) -> None:
        self.records.append(pattern_id)


@pytest.mark.asyncio
async def test_demo_proves_baseline_fix_and_review(tmp_path: Path) -> None:
    report, report_path = await run_demo(tmp_path)

    request = json.loads((SAMPLE / "sample_input.json").read_text(encoding="utf-8"))
    expected = json.loads(
        (SAMPLE / "expected_output.json").read_text(encoding="utf-8")
    )
    assert request["schema"] == "devflow.demo-request/v1"
    assert request["mode"] == report["mode"]
    assert request["scenario"] == report["scenario"]
    for key, value in request["issue"].items():
        assert report["issue"][key] == value
    for dotted_path, value in expected["assertions"].items():
        observed: Any = report
        for part in dotted_path.split("."):
            observed = observed[part]
        assert observed == value
    assert set(expected["required_events"]) <= {
        event["event_type"] for event in report["events"]
    }
    assert set(expected["required_successful_tools"]) == {
        f'{entry["server"]}:{entry["tool"]}'
        for entry in report["mcp_audit"]
        if entry["outcome"] == "succeeded"
    }

    assert report_path.exists()
    assert report["classification"]["complexity_level"] == "T2"
    assert report["located_context"]["root_cause"]["file"] == "calculator.py"
    assert report["test_result"]["passed"] == 1
    assert report["test_result"]["baseline_comparison"]["baseline_passed"] == 0
    assert report["test_result"]["baseline_comparison"]["fixed_tests"]
    assert report["review"]["decision"] == "approved"
    assert report["experience"]["stored"] is True
    assert report["experience"]["provenance"]["candidate_digest"]
    assert report["terminal_state"] == "verified"
    ledger = report["collaboration_ledger"]
    assert ledger["snapshot"] == {
        "pending": 0,
        "leased": 0,
        "succeeded": 6,
        "failed": 0,
        "expired_leases": 0,
        "audit_entries": 18,
    }
    assert ledger["audit_chain"]["valid"] is True
    assert ledger["audit_chain"]["entries"] == 18
    assert len(ledger["audit_chain"]["head_sha256"]) == 64
    assert (report_path.parent / ledger["file"]).is_file()
    assert [
        (item["agent"], item["skill"])
        for item in report["plan"]
    ] == [
        ("TriageAgent", "issue-classifier"),
        ("LocatorAgent", "code-root-cause"),
        ("CoderAgent", "patch-generator"),
        ("TesterAgent", "test-runner"),
        ("ReviewerAgent", "pr-reviewer"),
        ("ReviewerAgent", "experience-distiller"),
    ]
    assert {entry["outcome"] for entry in report["mcp_audit"]} == {
        "authorized",
        "succeeded",
    }
    assert {
        (entry["agent"], entry["skill"], entry["server"], entry["tool"])
        for entry in report["mcp_audit"]
        if entry["outcome"] == "succeeded"
    } == {
        ("TesterAgent", "test-runner", "devflow-cicd-portable", "run_tests"),
    }
    assert {event["event_type"] for event in report["events"]} >= {
        "triage.completed",
        "locator.completed",
        "coder.patch_ready",
        "test.passed",
        "review.approved",
        "experience.stored",
        "experience.completed",
        "workflow.completed",
    }
    handoff_events = {
        "triage.completed",
        "locator.completed",
        "coder.patch_ready",
        "test.passed",
        "review.approved",
        "experience.completed",
    }
    result_handoffs: list[HandoffEnvelope] = []
    for event in report["events"]:
        if event["event_type"] not in handoff_events:
            continue
        envelope = HandoffEnvelope.model_validate(event["payload"])
        assert envelope.artifact.verify_integrity()
        assert envelope.consumer == "TeamLeader"
        assert envelope.parent_task_id is not None
        assert envelope.parent_handoff_sha256 is not None
        result_handoffs.append(envelope)
    assert len(result_handoffs) == 6
    assert len({item.idempotency_key for item in result_handoffs}) == 6
    receipts = [
        event["payload"]
        for event in report["events"]
        if event["event_type"] == "workflow.completed"
    ]
    assert len(receipts) == 1
    assert receipts[0]["terminal_state"] == "verified"
    assert receipts[0]["memory_status"] == "stored"


@pytest.mark.asyncio
async def test_distiller_blocks_secret_before_store(tmp_path: Path) -> None:
    report, _ = await run_demo(tmp_path)
    issue = dict(report["issue"])
    issue["title"] = "leaked " + "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
    store = RecordingStore()
    distiller = ExperienceDistillerSkill(store=store)

    with pytest.raises(SkillError, match="redaction gates"):
        await distiller.run(
            issue=issue,
            tier="T2",
            repository_revision="demo-fixture-v1",
            located_context=report["located_context"],
            patch=report["patch"],
            test_result=report["test_result"],
            review=report["review"],
            trace_id="secret-test",
            terminal_receipt=report["terminal_receipt"],
        )

    assert store.records == []


@pytest.mark.asyncio
async def test_distiller_rejects_nonterminal_or_tampered_evidence(
    tmp_path: Path,
) -> None:
    report, _ = await run_demo(tmp_path)

    rejected_review = copy.deepcopy(report["review"])
    rejected_review["decision"] = "changes_requested"
    failed_tests = copy.deepcopy(report["test_result"])
    failed_tests["baseline_comparison"]["regression"] = True
    failed_tests["baseline_comparison"]["new_failures"] = ["hidden_regression"]
    tampered_receipt = copy.deepcopy(report["terminal_receipt"])
    tampered_receipt["receipt_sha256"] = "0" * 64

    cases = (
        {"review": rejected_review},
        {"test_result": failed_tests},
        {"terminal_receipt": tampered_receipt},
    )
    for replacement in cases:
        store = RecordingStore()
        distiller = ExperienceDistillerSkill(store=store)
        arguments = {
            "issue": report["issue"],
            "tier": "T2",
            "repository_revision": "demo-fixture-v1",
            "located_context": report["located_context"],
            "patch": report["patch"],
            "test_result": report["test_result"],
            "review": report["review"],
            "trace_id": "terminal-gate-test",
            "terminal_receipt": report["terminal_receipt"],
            **replacement,
        }
        with pytest.raises(SkillError):
            await distiller.run(**arguments)
        assert store.records == []
