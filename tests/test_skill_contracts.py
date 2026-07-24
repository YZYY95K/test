"""Executable quality gates for Skill contracts and collaboration."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from devflow.agents.coder_agent import CoderAgent
from devflow.exceptions import BoundaryViolationError
from devflow.skills.catalog import load_catalog
from devflow.skills.contracts import HandoffArtifact, HandoffEnvelope
from scripts.evaluate_skills import evaluate
from scripts.run_behavior_evals import Decision, ExpectedDecision, load_cases, score, validate_cases

ROOT = Path(__file__).resolve().parents[1]


def test_every_skill_clears_90_point_quality_gate() -> None:
    results = [
        evaluate(skill_dir)
        for skill_dir in sorted((ROOT / "skills").iterdir())
        if (skill_dir / "SKILL.md").exists()
    ]

    assert len(results) == 6
    assert all(result.qualified for result in results)
    assert min(result.score for result in results) >= 90


def test_handoff_envelope_detects_tampering() -> None:
    envelope = HandoffEnvelope.create(
        run_id="run-1",
        issue_id=7,
        task_id="7-1-locator",
        producer="TeamLeader",
        consumer="LocatorAgent",
        skill="code-root-cause",
        artifact_type="ClassifiedIssue",
        payload={"tier": "T2"},
    )

    assert envelope.artifact.verify_integrity()
    assert envelope.artifact.inline is not None
    envelope.artifact.inline["tier"] = "T5"
    assert not envelope.artifact.verify_integrity()


def test_handoff_requires_exactly_one_payload_location() -> None:
    digest = HandoffArtifact.digest({"ok": True})

    with pytest.raises(ValueError, match="exactly one"):
        HandoffArtifact(
            type="Evidence",
            schema_version="1.0",
            inline={"ok": True},
            ref="shared://artifact",
            sha256=digest,
        )


def test_agent_accepts_only_integral_handoff_for_owned_skill() -> None:
    envelope = HandoffEnvelope.create(
        run_id="run-1",
        issue_id=7,
        task_id="7-coder",
        producer="TeamLeader",
        consumer="CoderAgent",
        skill="patch-generator",
        artifact_type="SkillInvocation",
        payload={"input": {"issue_id": 7, "bounded": True}},
    )
    agent = CoderAgent()

    assert agent._unwrap_handoff(envelope) == {"issue_id": 7, "bounded": True}

    wrong_consumer = envelope.model_copy(update={"consumer": "ReviewerAgent"})
    with pytest.raises(BoundaryViolationError, match="does not match"):
        agent._unwrap_handoff(wrong_consumer)

    wrong_skill = envelope.model_copy(update={"skill": "pr-reviewer"})
    with pytest.raises(BoundaryViolationError, match="does not own Skill"):
        agent._unwrap_handoff(wrong_skill)

    assert envelope.artifact.inline is not None
    envelope.artifact.inline["input"]["bounded"] = False
    with pytest.raises(BoundaryViolationError, match="integrity"):
        agent._unwrap_handoff(envelope)


def test_each_skill_validator_accepts_contract_shape(tmp_path: Path) -> None:
    catalog = load_catalog(ROOT / "skills")

    for name, contract in catalog.items():
        artifact = {field: "evidence" for field in contract.output.required_fields}
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(artifact), encoding="utf-8")
        process = subprocess.run(
            [
                sys.executable,
                str(ROOT / "skills" / name / "scripts" / "validate.py"),
                "output",
                str(path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert process.returncode == 0, process.stderr
        assert json.loads(process.stdout)["valid"] is True


def test_skill_validator_rejects_missing_contract_fields(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text("{}", encoding="utf-8")
    process = subprocess.run(
        [
            sys.executable,
            str(
                ROOT
                / "skills"
                / "patch-generator"
                / "scripts"
                / "validate.py"
            ),
            "output",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert process.returncode != 0
    assert "missing required fields" in process.stderr


def test_behavior_suite_covers_every_skill_and_contract_route() -> None:
    cases = load_cases(ROOT / "evals" / "skill_behavior" / "cases.yaml")

    assert len(cases) == 12
    assert {case.skill for case in cases} == set(load_catalog(ROOT / "skills"))
    assert not validate_cases(ROOT, cases)


def test_behavior_score_is_exact_and_penalizes_unsafe_invocation() -> None:
    expected = ExpectedDecision(
        invoke=False,
        action="refuse",
        next_event="boundary.violation",
        consumer="TeamLeader",
    )
    exact = Decision(
        invoke=False,
        action="refuse",
        next_event="boundary.violation",
        consumer="TeamLeader",
        reason="The requested action is outside the declared boundary.",
    )
    unsafe = exact.model_copy(update={"invoke": True})

    assert score(expected, exact) == 1.0
    assert score(expected, unsafe) == 0.75
