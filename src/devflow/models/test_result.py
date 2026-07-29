"""Test result models for DevFlow.

Defines structures for representing individual test case results, aggregated
test run summaries, and baseline comparisons for regression detection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from devflow.models.test_integrity import TestIntegrityAttestation
from devflow.security.secrets import REDACTION_MARKER, contains_secret, redact_text

_MAX_FAILURE_NAMES = 128
_MAX_FAILURE_DIAGNOSTICS = 32
_MAX_TEST_NAME_LENGTH = 512
_MAX_ERROR_MESSAGE_LENGTH = 2_048
_MAX_TRACEBACK_LENGTH = 4_000
_MAX_TEST_RESULTS = 10_000
_MAX_BASELINE_NAMES = 10_000
_MAX_TEST_COUNT = 1_000_000
_MAX_TEST_DURATION_MS = 604_800_000
_REDACTED = REDACTION_MARKER

BoundedTestName = Annotated[
    str,
    Field(min_length=1, max_length=_MAX_TEST_NAME_LENGTH),
]
BoundedErrorMessage = Annotated[
    str,
    Field(max_length=_MAX_ERROR_MESSAGE_LENGTH),
]
BoundedTraceback = Annotated[
    str,
    Field(max_length=_MAX_TRACEBACK_LENGTH),
]


class TestStatus(str, Enum):
    """Status of a single test case execution."""

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


class TestCaseResult(BaseModel):
    """Result of a single test case execution."""

    model_config = ConfigDict(extra="forbid", revalidate_instances="always")

    name: BoundedTestName = Field(description="Name of the test case")
    status: TestStatus = Field(
        ..., description="Execution status of the test case"
    )
    duration_ms: int = Field(
        ...,
        ge=0,
        le=_MAX_TEST_DURATION_MS,
        description="Execution duration in milliseconds",
    )
    error_message: BoundedErrorMessage | None = Field(
        default=None,
        description="Error message produced when the test failed or errored",
    )
    traceback: BoundedTraceback | None = Field(
        default=None,
        description="Stack traceback produced when the test failed or errored",
    )


class BaselineComparison(BaseModel):
    """Comparison between a current test run and a stored baseline."""

    model_config = ConfigDict(extra="forbid", revalidate_instances="always")

    baseline_passed: int = Field(
        ...,
        ge=0,
        le=_MAX_TEST_COUNT,
        description="Number of passing tests in the baseline run",
    )
    current_passed: int = Field(
        ...,
        ge=0,
        le=_MAX_TEST_COUNT,
        description="Number of passing tests in the current run",
    )
    new_failures: list[BoundedTestName] = Field(
        default_factory=list,
        max_length=_MAX_BASELINE_NAMES,
        description="Names of tests that pass in the baseline but fail now",
    )
    fixed_tests: list[BoundedTestName] = Field(
        default_factory=list,
        max_length=_MAX_BASELINE_NAMES,
        description="Names of tests that failed in the baseline but pass now",
    )
    regression: bool = Field(
        default=False,
        description="Whether a regression was detected relative to the baseline",
    )


class TestRunResult(BaseModel):
    """Aggregated result of a full test run."""

    model_config = ConfigDict(extra="forbid", revalidate_instances="always")

    total: int = Field(
        ...,
        ge=0,
        le=_MAX_TEST_COUNT,
        description="Total number of tests in the run",
    )
    passed: int = Field(
        ..., ge=0, le=_MAX_TEST_COUNT, description="Number of passing tests"
    )
    failed: int = Field(
        ..., ge=0, le=_MAX_TEST_COUNT, description="Number of failing tests"
    )
    errors: int = Field(
        ..., ge=0, le=_MAX_TEST_COUNT, description="Number of tests that errored"
    )
    skipped: int = Field(
        ..., ge=0, le=_MAX_TEST_COUNT, description="Number of skipped tests"
    )
    duration_ms: int = Field(
        ...,
        ge=0,
        le=_MAX_TEST_DURATION_MS,
        description="Total test run duration in milliseconds",
    )
    results: list[TestCaseResult] = Field(
        default_factory=list,
        max_length=_MAX_TEST_RESULTS,
        description="Detailed results for each test case",
    )
    baseline_comparison: BaselineComparison | None = Field(
        default=None,
        description="Comparison against the baseline, if a baseline is available",
    )
    integrity_attestation: TestIntegrityAttestation | None = Field(
        default=None,
        description=(
            "CI/CD MCP evidence that repository-owned tests were immutable; "
            "absence means integrity was not attested"
        ),
    )

    @model_validator(mode="after")
    def _require_consistent_aggregates(self) -> TestRunResult:
        aggregate_total = self.passed + self.failed + self.errors + self.skipped
        if self.total != aggregate_total:
            raise ValueError("test totals do not add up to total")

        if self.results:
            if len(self.results) != self.total:
                raise ValueError("detailed test count does not match total")
            status_counts = {
                TestStatus.PASSED: 0,
                TestStatus.FAILED: 0,
                TestStatus.ERROR: 0,
                TestStatus.SKIPPED: 0,
            }
            for case in self.results:
                status_counts[case.status] += 1
            expected_counts = {
                TestStatus.PASSED: self.passed,
                TestStatus.FAILED: self.failed,
                TestStatus.ERROR: self.errors,
                TestStatus.SKIPPED: self.skipped,
            }
            if status_counts != expected_counts:
                raise ValueError("detailed test statuses do not match aggregates")

        comparison = self.baseline_comparison
        if comparison is not None and comparison.current_passed != self.passed:
            raise ValueError("baseline current_passed does not match passed")
        return self


class TestFailureReason(str, Enum):
    """Deterministic reasons why a test result cannot pass the gate."""

    BASELINE_MISSING = "baseline_missing"
    TEST_FAILURES = "test_failures"
    TEST_ERRORS = "test_errors"
    REGRESSION = "regression"
    NEW_FAILURES = "new_failures"


class TestFailureDiagnostic(BaseModel):
    """A bounded diagnostic excerpt for one failed or errored test case."""

    model_config = ConfigDict(extra="forbid")

    name: BoundedTestName
    status: TestStatus
    error_message: BoundedErrorMessage | None = None
    traceback: BoundedTraceback | None = None

    @field_validator("status")
    @classmethod
    def _require_failure_status(cls, value: TestStatus) -> TestStatus:
        if value not in {TestStatus.FAILED, TestStatus.ERROR}:
            raise ValueError("failure diagnostics require failed or error status")
        return value


class TestFailureEvidence(BaseModel):
    """Bounded, digest-verifiable evidence for a non-passing candidate.

    ``candidate_digest`` binds the evidence to the exact prior ``Patch`` while
    ``test_result_digest`` binds it to the complete sanitized
    :class:`TestRunResult` that actually crosses the Tester boundary. Raw test
    output remains local to Tester. Human-readable diagnostics are deliberately
    capped before they reach Coder.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.2"] = "1.2"
    issue_id: int = Field(ge=1)
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    test_result_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    baseline_present: bool
    failed: int = Field(ge=0)
    errors: int = Field(ge=0)
    regression: bool
    reasons: list[TestFailureReason] = Field(min_length=1, max_length=5)
    failing_tests: list[BoundedTestName] = Field(
        default_factory=list,
        max_length=_MAX_FAILURE_NAMES,
    )
    new_failures: list[BoundedTestName] = Field(
        default_factory=list,
        max_length=_MAX_FAILURE_NAMES,
    )
    diagnostics: list[TestFailureDiagnostic] = Field(
        default_factory=list,
        max_length=_MAX_FAILURE_DIAGNOSTICS,
    )
    redacted: bool = False
    truncated: bool = False

    @model_validator(mode="after")
    def _require_exact_reasons(self) -> TestFailureEvidence:
        expected = self._reasons_for(
            baseline_present=self.baseline_present,
            failed=self.failed,
            errors=self.errors,
            regression=self.regression,
            new_failures=self.new_failures,
        )
        if self.reasons != expected:
            raise ValueError("failure reasons do not match the test gate facts")
        if _evidence_contains_secret(self):
            raise ValueError("failure evidence contains unredacted secret-shaped data")
        if self.redacted != _evidence_contains_redaction_marker(self):
            raise ValueError(
                "redacted must exactly report use of the redaction marker"
            )
        return self

    @classmethod
    def from_test_result(
        cls,
        *,
        issue_id: int,
        candidate: BaseModel | dict[str, Any],
        result: TestRunResult,
    ) -> TestFailureEvidence:
        """Create a canonical bounded view while digest-binding full inputs."""

        sanitized_result, _ = redact_test_result_for_handoff(result)
        comparison = sanitized_result.baseline_comparison
        failing_cases = [
            case
            for case in sanitized_result.results
            if case.status in {TestStatus.FAILED, TestStatus.ERROR}
        ]
        raw_new_failures = comparison.new_failures if comparison is not None else []
        failing_tests, names_truncated = _bounded_unique_names(
            (case.name for case in failing_cases),
            limit=_MAX_FAILURE_NAMES,
        )
        new_failures, new_failures_truncated = _bounded_unique_names(
            iter(raw_new_failures),
            limit=_MAX_FAILURE_NAMES,
        )
        diagnostic_cases = failing_cases[:_MAX_FAILURE_DIAGNOSTICS]
        diagnostics = [
            TestFailureDiagnostic(
                name=_bounded_text(case.name, _MAX_TEST_NAME_LENGTH, fallback="unnamed-test"),
                status=case.status,
                error_message=_bounded_optional_text(
                    case.error_message,
                    _MAX_ERROR_MESSAGE_LENGTH,
                ),
                traceback=_bounded_optional_text(case.traceback, _MAX_TRACEBACK_LENGTH),
            )
            for case in diagnostic_cases
        ]
        redacted = _strings_contain_redaction_marker(
            [
                *failing_tests,
                *new_failures,
                *(
                    text
                    for diagnostic in diagnostics
                    for text in (
                        diagnostic.name,
                        diagnostic.error_message,
                        diagnostic.traceback,
                    )
                    if text is not None
                ),
            ]
        )
        regression = comparison.regression if comparison is not None else False
        reasons = cls._reasons_for(
            baseline_present=comparison is not None,
            failed=result.failed,
            errors=result.errors,
            regression=regression,
            new_failures=new_failures,
        )
        return cls(
            issue_id=issue_id,
            candidate_digest=canonical_artifact_digest(candidate),
            test_result_digest=canonical_artifact_digest(sanitized_result),
            baseline_present=comparison is not None,
            failed=sanitized_result.failed,
            errors=sanitized_result.errors,
            regression=regression,
            reasons=reasons,
            failing_tests=failing_tests,
            new_failures=new_failures,
            diagnostics=diagnostics,
            redacted=redacted,
            truncated=(
                names_truncated
                or new_failures_truncated
                or len(failing_cases) > _MAX_FAILURE_DIAGNOSTICS
                or any(
                    len(case.name) > _MAX_TEST_NAME_LENGTH
                    or (
                        case.error_message is not None
                        and len(case.error_message) > _MAX_ERROR_MESSAGE_LENGTH
                    )
                    or (
                        case.traceback is not None
                        and len(case.traceback) > _MAX_TRACEBACK_LENGTH
                    )
                    for case in diagnostic_cases
                )
            ),
        )

    def verifies_candidate(self, candidate: BaseModel | dict[str, Any]) -> bool:
        """Return whether this evidence belongs to the exact candidate."""

        return hmac.compare_digest(
            self.candidate_digest,
            canonical_artifact_digest(candidate),
        )

    def verifies_test_result(self, result: TestRunResult) -> bool:
        """Verify the sanitized boundary result and all bounded derived facts."""

        supplied_digest = canonical_artifact_digest(result)
        if not hmac.compare_digest(self.test_result_digest, supplied_digest):
            return False
        expected = self.from_test_result(
            issue_id=self.issue_id,
            candidate={"digest-placeholder": self.candidate_digest},
            result=result,
        ).model_copy(update={"candidate_digest": self.candidate_digest})
        return hmac.compare_digest(
            canonical_artifact_digest(self),
            canonical_artifact_digest(expected),
        )

    @staticmethod
    def _reasons_for(
        *,
        baseline_present: bool,
        failed: int,
        errors: int,
        regression: bool,
        new_failures: list[str],
    ) -> list[TestFailureReason]:
        reasons: list[TestFailureReason] = []
        if not baseline_present:
            reasons.append(TestFailureReason.BASELINE_MISSING)
        if failed:
            reasons.append(TestFailureReason.TEST_FAILURES)
        if errors:
            reasons.append(TestFailureReason.TEST_ERRORS)
        if regression:
            reasons.append(TestFailureReason.REGRESSION)
        if new_failures:
            reasons.append(TestFailureReason.NEW_FAILURES)
        if not reasons:
            raise ValueError("passing test results cannot produce failure evidence")
        return reasons


def canonical_artifact_digest(value: BaseModel | dict[str, Any]) -> str:
    """Return the canonical SHA-256 used to bind retry artifacts."""

    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def redact_test_result_for_handoff(
    result: TestRunResult,
) -> tuple[TestRunResult, bool]:
    """Return a deterministic secret-free copy for an agent hand-off.

    The original model is never mutated.  All human-controlled strings that a
    test runner can place on the boundary are scrubbed, including fixed test
    names even though only new failures are copied into failure evidence.
    """

    redacted = False
    sanitized_cases: list[TestCaseResult] = []
    for case in result.results:
        name, name_redacted = _redact_text(case.name)
        error_message, message_redacted = _redact_optional_text(case.error_message)
        traceback, traceback_redacted = _redact_optional_text(case.traceback)
        redacted = redacted or any(
            (name_redacted, message_redacted, traceback_redacted)
        )
        sanitized_cases.append(
            case.model_copy(
                update={
                    "name": name,
                    "error_message": error_message,
                    "traceback": traceback,
                }
            )
        )

    comparison = result.baseline_comparison
    sanitized_comparison: BaselineComparison | None = None
    if comparison is not None:
        new_failures, new_redacted = _redact_names(comparison.new_failures)
        fixed_tests, fixed_redacted = _redact_names(comparison.fixed_tests)
        redacted = redacted or new_redacted or fixed_redacted
        sanitized_comparison = comparison.model_copy(
            update={
                "new_failures": new_failures,
                "fixed_tests": fixed_tests,
            }
        )

    return (
        result.model_copy(
            update={
                "results": sanitized_cases,
                "baseline_comparison": sanitized_comparison,
            }
        ),
        redacted,
    )


def _bounded_optional_text(value: str | None, maximum: int) -> str | None:
    return None if value is None else value[:maximum]


def _bounded_text(value: str, maximum: int, *, fallback: str) -> str:
    bounded = value[:maximum]
    return bounded if bounded else fallback


def _bounded_unique_names(
    values: Any,
    *,
    limit: int,
) -> tuple[list[str], bool]:
    names: list[str] = []
    seen: set[str] = set()
    truncated = False
    for raw in values:
        name = _bounded_text(str(raw), _MAX_TEST_NAME_LENGTH, fallback="unnamed-test")
        if len(str(raw)) > _MAX_TEST_NAME_LENGTH:
            truncated = True
        if name in seen:
            continue
        seen.add(name)
        if len(names) >= limit:
            truncated = True
            continue
        names.append(name)
    return names, truncated


def _redact_optional_text(value: str | None) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    return _redact_text(value)


def _redact_text(value: str) -> tuple[str, bool]:
    return redact_text(value)


def _redact_names(values: list[str]) -> tuple[list[str], bool]:
    names: list[str] = []
    redacted = False
    for value in values:
        name, item_redacted = _redact_text(value)
        names.append(name)
        redacted = redacted or item_redacted
    return names, redacted


def _evidence_contains_secret(evidence: TestFailureEvidence) -> bool:
    values = [*evidence.failing_tests, *evidence.new_failures]
    for diagnostic in evidence.diagnostics:
        values.append(diagnostic.name)
        if diagnostic.error_message is not None:
            values.append(diagnostic.error_message)
        if diagnostic.traceback is not None:
            values.append(diagnostic.traceback)
    return contains_secret(values)


def _evidence_contains_redaction_marker(evidence: TestFailureEvidence) -> bool:
    values = [*evidence.failing_tests, *evidence.new_failures]
    for diagnostic in evidence.diagnostics:
        values.append(diagnostic.name)
        if diagnostic.error_message is not None:
            values.append(diagnostic.error_message)
        if diagnostic.traceback is not None:
            values.append(diagnostic.traceback)
    return _strings_contain_redaction_marker(values)


def _strings_contain_redaction_marker(values: list[str]) -> bool:
    return any(_REDACTED in value for value in values)


__all__ = [
    "BaselineComparison",
    "TestCaseResult",
    "TestFailureDiagnostic",
    "TestFailureEvidence",
    "TestFailureReason",
    "TestIntegrityAttestation",
    "TestRunResult",
    "TestStatus",
    "canonical_artifact_digest",
    "redact_test_result_for_handoff",
]
