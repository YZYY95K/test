"""Deterministic routing and repository-repair benchmark tests."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from benchmarks.repository_repair.prepare_mutation_fixtures import _bounded_summary
from scripts.run_repository_benchmark import (
    AcceptanceCommand,
    BenchmarkManifest,
    CommandEvidence,
    Decision,
    ExecutionEvidence,
    ExpectedDecision,
    RepairBenchmarkManifest,
    RepairBenchmarkReport,
    RepairTaskResult,
    _command_sha256,
    _parse_decision,
    _repair_summary,
    _self_digest,
    _validate_fixture_evidence,
    build_unexecuted_repair_report,
    load_repair_manifest,
    repair_manifest_sha256,
    score,
    validate_repair_manifest,
    validate_repair_report,
)

ROOT = Path(__file__).resolve().parents[1]
REPAIR_MANIFEST = ROOT / "benchmarks" / "repository_repair" / "tasks.yaml"


def test_repository_benchmark_scores_exact_fields() -> None:
    expected = ExpectedDecision(
        skill="test-runner",
        invoke=True,
        action="produce",
        next_event="test.passed",
        consumer="ReviewerAgent",
    )
    actual = Decision(
        **expected.model_dump(),
        reason="Isolated evidence is green.",
    )
    assert score(expected, actual) == 1.0
    assert score(expected, actual.model_copy(update={"consumer": "TeamLeader"})) == 0.8


def test_repository_benchmark_parses_fenced_json() -> None:
    decision = _parse_decision(
        '```json\n{"skill":"pr-reviewer","invoke":true,"action":"block",'
        '"next_event":"approval.required","consumer":"HumanReviewer",'
        '"reason":"T4 requires approval."}\n```'
    )
    assert decision.consumer == "HumanReviewer"


def test_routing_manifest_is_explicitly_not_patch_resolution() -> None:
    manifest = BenchmarkManifest.model_validate(
        {
            "schema_version": "1.0",
            "benchmark": "routing-only",
            "evaluation_kind": "routing_boundary",
            "repositories": {},
            "cases": [
                {
                    "id": f"case-{index}",
                    "repository": "fixture",
                    "path": "README.md",
                    "scenario": "This is a routing-only scenario with enough bounded detail.",
                    "expected": {
                        "skill": "issue-classifier",
                        "invoke": True,
                        "action": "produce",
                        "next_event": "triage.completed",
                        "consumer": "TeamLeader",
                    },
                }
                for index in range(20)
            ],
        }
    )
    assert manifest.evaluation_kind == "routing_boundary"


def test_repair_manifest_has_three_fixed_sources_and_twenty_one_verified_mutations() -> None:
    manifest = load_repair_manifest(REPAIR_MANIFEST)

    assert manifest.evaluation_kind == "repository_patch_resolution"
    assert len(manifest.repositories) == 3
    assert len(manifest.tasks) == 21
    assert {repository.license.spdx for repository in manifest.repositories.values()} == {
        "Apache-2.0",
        "BSD-3-Clause",
        "MIT",
    }
    assert all(task.execution_ready and task.readiness_blocker is None for task in manifest.tasks)
    assert all(task.origin == "deterministic-mutation" for task in manifest.tasks)
    assert all(task.mutation.path in task.target_paths for task in manifest.tasks)
    assert all(
        command.argv[:3] == ["python", "-m", "pytest"]
        for task in manifest.tasks
        for command in task.acceptance
    )


def test_mutation_prevalidation_covers_every_task_and_fixed_checkout() -> None:
    manifest = load_repair_manifest(REPAIR_MANIFEST)
    repos_root = ROOT / ".devflow" / "benchmark-repos"

    if not repos_root.is_dir():
        pytest.skip("fixed benchmark checkouts are not available")

    assert validate_repair_manifest(manifest, repos_root) == []


def test_checked_in_mutation_evidence_is_hash_bound_and_complete() -> None:
    manifest = load_repair_manifest(REPAIR_MANIFEST)

    assert _validate_fixture_evidence(manifest) == []


def test_mutation_prevalidation_summary_redacts_credential_shapes() -> None:
    url_userinfo = b"example-user:" + b"example-password"
    summary = _bounded_summary(
        b"FAILED https://" + url_userinfo + b"@example.test/path\n",
        b"Authorization: Bearer "
        b"abcdefgh.ijklmnop.qrstuvwx\n"
        b"api_key="
        b"abcdefghijklmnopqrstuvwxyz012345\n",
    )

    assert "FAILED" in summary
    assert "https://[REDACTED]@example.test/path" in summary
    assert "Bearer [REDACTED]" in summary
    assert "api_key=[REDACTED]" in summary
    assert "example-password" not in summary


def test_unexecuted_repair_template_has_no_success_or_rate() -> None:
    manifest = load_repair_manifest(REPAIR_MANIFEST)
    report = build_unexecuted_repair_report(
        manifest,
        generated_at="2026-07-28T00:00:00+00:00",
    )

    assert report.manifest_sha256 == repair_manifest_sha256(manifest)
    assert report.schema_version == "1.1"
    assert report.summary.attempted == 0
    assert report.summary.executed == 0
    assert report.summary.unexecuted == 21
    assert report.summary.successes == 0
    assert report.summary.success_rate is None
    assert report.summary.safety_rate is None
    assert report.summary.safety_evaluated == 0
    assert report.summary.human_intervention_rate is None
    assert report.summary.latency_ms_p50 is None
    assert report.summary.estimated_cost_usd is None
    assert all(not result.success and result.evidence is None for result in report.results)
    assert validate_repair_report(report, manifest) == []


def test_fixture_prevalidation_is_not_counted_as_agent_execution() -> None:
    manifest = load_repair_manifest(REPAIR_MANIFEST)
    report = build_unexecuted_repair_report(
        manifest,
        generated_at="2026-07-28T00:00:00+00:00",
    )

    assert all(task.execution_ready for task in manifest.tasks)
    assert report.summary.attempted == 0
    assert report.summary.executed == 0
    assert report.summary.success_rate is None


def test_unexecuted_task_cannot_be_labeled_successful() -> None:
    manifest = load_repair_manifest(REPAIR_MANIFEST)
    report = build_unexecuted_repair_report(
        manifest,
        generated_at="2026-07-28T00:00:00+00:00",
    )
    value = report.results[0].model_dump(mode="json")
    value["success"] = True

    with pytest.raises(ValidationError, match="cannot succeed"):
        type(report.results[0]).model_validate(value)


def test_executed_task_requires_execution_evidence() -> None:
    manifest = load_repair_manifest(REPAIR_MANIFEST)
    report = build_unexecuted_repair_report(
        manifest,
        generated_at="2026-07-28T00:00:00+00:00",
    )
    value = report.results[0].model_dump(mode="json")
    value["execution_status"] = "executed"

    with pytest.raises(ValidationError, match="requires execution evidence"):
        type(report.results[0]).model_validate(value)


def test_report_tampering_breaks_result_and_report_digests() -> None:
    manifest = load_repair_manifest(REPAIR_MANIFEST)
    report = build_unexecuted_repair_report(
        manifest,
        generated_at="2026-07-28T00:00:00+00:00",
    )
    changed = report.results[0].model_copy(update={"execution_status": "blocked"})
    tampered = report.model_copy(update={"results": [changed, *report.results[1:]]})

    errors = validate_repair_report(tampered, manifest)

    assert any("result self digest" in error for error in errors)
    assert "report self digest does not match" in errors
    assert "report summary is not derived from its task results" in errors


def test_report_rejects_wrong_manifest_binding() -> None:
    manifest = load_repair_manifest(REPAIR_MANIFEST)
    report = build_unexecuted_repair_report(
        manifest,
        generated_at="2026-07-28T00:00:00+00:00",
    ).model_copy(update={"manifest_sha256": "0" * 64})

    assert "report manifest digest does not match" in validate_repair_report(report, manifest)


def test_repair_manifest_rejects_duplicate_tasks_and_unknown_fields() -> None:
    value = load_repair_manifest(REPAIR_MANIFEST).model_dump(mode="json")
    value["tasks"][1]["id"] = value["tasks"][0]["id"]
    with pytest.raises(ValidationError, match="ids must be unique"):
        RepairBenchmarkManifest.model_validate(value)

    value = load_repair_manifest(REPAIR_MANIFEST).model_dump(mode="json")
    value["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        RepairBenchmarkManifest.model_validate(value)


def test_repair_manifest_rejects_mutation_digest_or_boundary_tampering() -> None:
    value = load_repair_manifest(REPAIR_MANIFEST).model_dump(mode="json")
    value["tasks"][0]["mutation"]["after"] += "# tampered\n"
    with pytest.raises(ValidationError, match="mutation digest"):
        RepairBenchmarkManifest.model_validate(value)

    value = load_repair_manifest(REPAIR_MANIFEST).model_dump(mode="json")
    value["tasks"][0]["target_paths"] = ["src/requests/models.py"]
    with pytest.raises(ValidationError, match="mutation path"):
        RepairBenchmarkManifest.model_validate(value)


def test_acceptance_command_rejects_shell_or_non_pytest_execution() -> None:
    with pytest.raises(ValidationError, match="pytest argument vector"):
        AcceptanceCommand(
            argv=["sh", "-c", "pytest", "tests/test_example.py"],
            timeout_seconds=60,
        )
    with pytest.raises(ValidationError, match="undeclared pytest option"):
        AcceptanceCommand(
            argv=["python", "-m", "pytest", "-p", "external_plugin", "tests/test_example.py"],
            timeout_seconds=60,
        )


def test_report_schema_rejects_extra_claim_fields() -> None:
    manifest = load_repair_manifest(REPAIR_MANIFEST)
    value = build_unexecuted_repair_report(
        manifest,
        generated_at="2026-07-28T00:00:00+00:00",
    ).model_dump(mode="json")
    value["claimed_patch_rate"] = 1.0

    with pytest.raises(ValidationError, match="Extra inputs"):
        RepairBenchmarkReport.model_validate(value)


def test_executed_result_rejects_an_unpinned_baseline_command() -> None:
    manifest = load_repair_manifest(REPAIR_MANIFEST)
    first = manifest.tasks[0]
    ready_manifest = manifest
    report = build_unexecuted_repair_report(
        ready_manifest,
        generated_at="2026-07-28T00:00:00+00:00",
    )
    output_digest = "0" * 64
    evidence = ExecutionEvidence(
        runner="devflow-repository-repair/v1",
        baseline=CommandEvidence(
            argv_sha256="1" * 64,
            completed=True,
            exit_code=1,
            duration_ms=10,
            stdout_sha256=output_digest,
            stderr_sha256=output_digest,
        ),
        patch_sha256="2" * 64,
        changed_paths=first.target_paths,
        acceptance=[
            CommandEvidence(
                argv_sha256=_command_sha256(first.acceptance[0]),
                completed=True,
                exit_code=0,
                duration_ms=10,
                stdout_sha256=output_digest,
                stderr_sha256=output_digest,
            )
        ],
        safety_pass=True,
    )
    result = RepairTaskResult(
        task_id=first.id,
        repository=first.repository,
        commit=ready_manifest.repositories[first.repository].commit,
        execution_status="executed",
        success=True,
        duration_ms=20,
        prompt_tokens=10,
        completion_tokens=5,
        estimated_cost_usd=None,
        human_intervention=False,
        evidence=evidence,
        error_code=None,
        result_sha256=output_digest,
    )
    result = result.model_copy(update={"result_sha256": _self_digest(result, "result_sha256")})
    results = [result, *report.results[1:]]
    claimed = report.model_copy(
        update={
            "summary": _repair_summary(results),
            "results": results,
            "report_sha256": output_digest,
        }
    )
    claimed = claimed.model_copy(update={"report_sha256": _self_digest(claimed, "report_sha256")})

    assert validate_repair_report(claimed, ready_manifest) == [
        f"{first.id}: baseline evidence does not match the manifest"
    ]
