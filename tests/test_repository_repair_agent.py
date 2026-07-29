"""Network-free tests for the formal repository-repair model adapter and CLI."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scripts.run_repository_repair_agent as agent_runner  # noqa: E402
from devflow.llm_client import CompletionResult  # noqa: E402
from scripts.repository_repair_executor import (  # noqa: E402
    PatchProviderError,
    PatchRequest,
    PatchSource,
    load_repair_report,
    write_repair_report,
)
from scripts.run_repository_benchmark import (  # noqa: E402
    RepairBenchmarkReport,
    _self_digest,
    build_unexecuted_repair_report,
    load_repair_manifest,
)


def _request() -> PatchRequest:
    content = "def value():\n    return 0\n"
    return PatchRequest(
        issue="Restore the expected public value behavior in this mutated source.",
        target_paths=["src/app.py"],
        mutated_sources={
            "src/app.py": PatchSource(
                content=content,
                sha256=hashlib.sha256(content.encode()).hexdigest(),
            )
        },
        failure_summary="one selected test failed",
    )


def _response_json(request: PatchRequest) -> str:
    source = request.mutated_sources["src/app.py"]
    return json.dumps(
        {
            "replacements": [
                {
                    "path": "src/app.py",
                    "expected_sha256": source.sha256,
                    "content": source.content.replace("return 0", "return 1"),
                }
            ]
        }
    )


class FakeClient:
    default_model: str | None = "glm-5.2"

    def __init__(self, outcomes: Sequence[CompletionResult | Exception | float]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[dict[str, object]] = []

    async def complete_with_usage(
        self,
        prompt: str,
        *,
        model: str | None = None,
        temperature: float = 0.2,
        system: str | None = None,
    ) -> CompletionResult:
        self.calls.append(
            {
                "prompt": prompt,
                "model": model,
                "temperature": temperature,
                "system": system,
            }
        )
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if isinstance(outcome, float):
            await asyncio.sleep(outcome)
            raise AssertionError("delayed fake should have been cancelled")
        return outcome


def _completion(
    content: str,
    *,
    prompt_tokens: int | None = 10,
    completion_tokens: int | None = 5,
    total_tokens: int | None = 15,
) -> CompletionResult:
    return CompletionResult(
        content=content,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
    )


def _explicit_pricing() -> agent_runner.PricingPolicy:
    return agent_runner.build_pricing_policy(
        root=ROOT,
        model="glm-5.2",
        pricing_lock=None,
        input_usd_per_million=1.4,
        output_usd_per_million=4.4,
    )


def test_model_provider_uses_server_usage_and_explicit_cost() -> None:
    request = _request()
    client = FakeClient([_completion(_response_json(request))])
    provider = agent_runner.LLMPatchProvider(
        client,
        pricing=_explicit_pricing(),
        model="glm-5.2",
        temperature=0,
        timeout_seconds=5,
        max_retries=0,
    )

    proposal = provider(request)

    assert proposal.prompt_tokens == 10
    assert proposal.completion_tokens == 5
    assert proposal.estimated_cost_usd == pytest.approx(0.000036)
    assert not proposal.human_intervention
    assert proposal.replacements[0].path == "src/app.py"
    call = client.calls[0]
    assert call["model"] == "glm-5.2"
    assert call["temperature"] == 0
    assert call["system"] == agent_runner.SYSTEM_PROMPT
    prompt = str(call["prompt"])
    assert set(json.loads(prompt)) == {
        "failure_summary",
        "issue",
        "mutated_sources",
        "target_paths",
    }
    assert "mutation.before" not in prompt and '"mutation"' not in prompt


@pytest.mark.parametrize(
    "content",
    [
        '```json\n{"replacements": []}\n```',
        '{"replacements": []} trailing prose',
        '{"replacements": [], "replacements": []}',
        '{"replacements": [], "prompt_tokens": 999999}',
    ],
)
def test_model_response_parser_rejects_fences_prose_duplicates_and_usage_claims(
    content: str,
) -> None:
    with pytest.raises(agent_runner.ModelResponseError):
        agent_runner.parse_model_patch(content)


def test_malformed_response_preserves_measured_usage_but_not_raw_content() -> None:
    sentinel = "MODEL_RESPONSE_SECRET_SENTINEL"
    client = FakeClient([_completion(f"not-json-{sentinel}")])
    provider = agent_runner.LLMPatchProvider(
        client,
        pricing=_explicit_pricing(),
        model="glm-5.2",
        temperature=0,
        timeout_seconds=5,
        max_retries=0,
    )

    with pytest.raises(PatchProviderError) as captured:
        provider(_request())

    assert captured.value.prompt_tokens == 10
    assert captured.value.completion_tokens == 5
    assert captured.value.estimated_cost_usd == pytest.approx(0.000036)
    assert sentinel not in str(captured.value)
    assert captured.value.__cause__ is None


def test_timeout_is_retried_without_exposing_provider_exception() -> None:
    request = _request()
    sentinel = "UPSTREAM_SECRET_SENTINEL"
    client = FakeClient(
        [
            2.0,
            _completion(
                _response_json(request),
                prompt_tokens=3,
                completion_tokens=2,
                total_tokens=5,
            ),
        ]
    )
    provider = agent_runner.LLMPatchProvider(
        client,
        pricing=agent_runner.build_pricing_policy(
            root=ROOT,
            model="glm-5.2",
            pricing_lock=None,
            input_usd_per_million=None,
            output_usd_per_million=None,
        ),
        model=None,
        temperature=0,
        timeout_seconds=1,
        max_retries=1,
    )

    proposal = provider(request)

    assert len(client.calls) == 2
    assert proposal.prompt_tokens == 3 and proposal.completion_tokens == 2
    assert proposal.estimated_cost_usd is None
    assert sentinel not in str(proposal)


def test_provider_failure_after_retries_is_generic() -> None:
    sentinel = "UPSTREAM_EXCEPTION_SECRET_SENTINEL"
    client = FakeClient([RuntimeError(sentinel), RuntimeError(sentinel)])
    provider = agent_runner.LLMPatchProvider(
        client,
        pricing=_explicit_pricing(),
        model=None,
        temperature=0,
        timeout_seconds=5,
        max_retries=1,
    )

    with pytest.raises(PatchProviderError) as captured:
        provider(_request())

    assert len(client.calls) == 2
    assert sentinel not in str(captured.value)
    assert captured.value.__cause__ is None


def test_missing_or_inconsistent_usage_is_rejected() -> None:
    request = _request()
    for completion in (
        _completion(_response_json(request), prompt_tokens=None),
        _completion(_response_json(request), total_tokens=99),
    ):
        provider = agent_runner.LLMPatchProvider(
            FakeClient([completion]),
            pricing=_explicit_pricing(),
            model=None,
            temperature=0,
            timeout_seconds=5,
            max_retries=0,
        )
        with pytest.raises(PatchProviderError, match="usage"):
            provider(request)


def test_pricing_lock_and_explicit_override_have_bounded_provenance() -> None:
    lock_path = ROOT / "benchmarks/repository_repair/pricing.lock.yaml"
    locked = agent_runner.build_pricing_policy(
        root=ROOT,
        model="glm-5.2",
        pricing_lock=lock_path,
        input_usd_per_million=None,
        output_usd_per_million=None,
    )

    assert locked.input_usd_per_million == 1.4
    assert locked.output_usd_per_million == 4.4
    assert locked.provenance.rate_source == "pricing-lock"
    assert locked.provenance.cached_input_usd_per_million == 0.26
    assert not locked.provenance.cached_input_tokens_reported
    assert locked.provenance.failed_call_usage_method == "unavailable-failed-calls-not-priced"
    assert locked.provenance.prompt_token_cost_method == "ordinary-input-rate-no-cached-breakdown"
    assert locked.provenance.billing_claim == "estimated-list-price-not-invoice"
    assert (
        locked.provenance.pricing_lock_sha256 == hashlib.sha256(lock_path.read_bytes()).hexdigest()
    )

    overridden = agent_runner.build_pricing_policy(
        root=ROOT,
        model="glm-5.2",
        pricing_lock=lock_path,
        input_usd_per_million=2.0,
        output_usd_per_million=6.0,
    )
    assert overridden.provenance.rate_source == "cli-override"
    assert overridden.estimate(10, 5) == pytest.approx(0.00005)

    with pytest.raises(agent_runner.SafeCLIError, match="model"):
        agent_runner.build_pricing_policy(
            root=ROOT,
            model="different-model",
            pricing_lock=lock_path,
            input_usd_per_million=None,
            output_usd_per_million=None,
        )


def _report_with_provenance(
    checkpoint: Path,
    provenance: Any,
) -> RepairBenchmarkReport:
    manifest = load_repair_manifest(ROOT / "benchmarks/repository_repair/tasks.yaml")
    template = build_unexecuted_repair_report(
        manifest,
        generated_at="2026-07-28T00:00:00+00:00",
    )
    payload = template.model_dump(mode="json")
    payload.update(
        {
            "cost_provenance": provenance.model_dump(mode="json"),
            "run_id": "agent-cli-test",
            "report_sha256": "0" * 64,
        }
    )
    report = RepairBenchmarkReport.model_validate(payload)
    report = report.model_copy(update={"report_sha256": _self_digest(report, "report_sha256")})
    write_repair_report(checkpoint, report)
    return report


def test_cli_rejects_missing_or_command_line_secret_without_echo(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sentinel = "COMMAND_LINE_SECRET_SENTINEL"
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    assert agent_runner.main([]) == 2
    assert "LLM_API_KEY" in capsys.readouterr().err

    assert agent_runner.main(["--api-key", sentinel]) == 2
    captured = capsys.readouterr()
    assert "environment-only" in captured.err
    assert sentinel not in captured.err and sentinel not in captured.out


def test_cli_passes_hash_bound_resume_and_never_logs_environment_secret(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    sentinel = "ENVIRONMENT_SECRET_SENTINEL"
    monkeypatch.setenv("LLM_API_KEY", sentinel)
    checkpoint = tmp_path / "repair-report.json"
    manifest_path = ROOT / "benchmarks/repository_repair/tasks.yaml"
    captured_resume: list[RepairBenchmarkReport | None] = []

    def client_factory(_model: str | None) -> FakeClient:
        return FakeClient([])

    def executor(
        _manifest: Any,
        **kwargs: Any,
    ) -> RepairBenchmarkReport:
        resume_value = kwargs["resume_report"]
        if resume_value is not None and not isinstance(resume_value, RepairBenchmarkReport):
            raise AssertionError("unexpected resume report type")
        resume: RepairBenchmarkReport | None = resume_value
        captured_resume.append(resume)
        if resume is not None:
            return resume
        return _report_with_provenance(checkpoint, kwargs["cost_provenance"])

    monkeypatch.setattr(agent_runner, "validate_repair_manifest", lambda *_args: [])
    arguments = [
        "--manifest",
        str(manifest_path),
        "--repos-root",
        str(tmp_path / "unused-repos"),
        "--checkpoint",
        str(checkpoint),
        "--model",
        "glm-5.2",
        "--task-id",
        "requests-default-hook-map",
    ]
    args = agent_runner.build_parser().parse_args(arguments)

    assert agent_runner.run_cli(args, client_factory=client_factory, executor=executor) == 0
    first_output = capsys.readouterr()
    assert sentinel not in first_output.out and sentinel not in first_output.err
    assert "report_sha256=" in first_output.out
    assert captured_resume == [None]

    resumed_args = agent_runner.build_parser().parse_args([*arguments, "--resume"])
    assert (
        agent_runner.run_cli(
            resumed_args,
            client_factory=client_factory,
            executor=executor,
        )
        == 0
    )
    resumed_output = capsys.readouterr()
    assert sentinel not in resumed_output.out and sentinel not in resumed_output.err
    assert captured_resume[1] == load_repair_report(checkpoint)
