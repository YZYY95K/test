"""Deterministic benchmark parser and oracle tests."""

from scripts.run_repository_benchmark import (
    Decision,
    ExpectedDecision,
    _parse_decision,
    score,
)


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
