"""Test result models for DevFlow.

Defines structures for representing individual test case results, aggregated
test run summaries, and baseline comparisons for regression detection.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class TestStatus(str, Enum):
    """Status of a single test case execution."""

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


class TestCaseResult(BaseModel):
    """Result of a single test case execution."""

    name: str = Field(
        ..., min_length=1, description="Name of the test case"
    )
    status: TestStatus = Field(
        ..., description="Execution status of the test case"
    )
    duration_ms: int = Field(
        ..., ge=0, description="Execution duration in milliseconds"
    )
    error_message: str | None = Field(
        default=None,
        description="Error message produced when the test failed or errored",
    )
    traceback: str | None = Field(
        default=None,
        description="Stack traceback produced when the test failed or errored",
    )


class BaselineComparison(BaseModel):
    """Comparison between a current test run and a stored baseline."""

    baseline_passed: int = Field(
        ..., ge=0, description="Number of passing tests in the baseline run"
    )
    current_passed: int = Field(
        ..., ge=0, description="Number of passing tests in the current run"
    )
    new_failures: list[str] = Field(
        default_factory=list,
        description="Names of tests that pass in the baseline but fail now",
    )
    fixed_tests: list[str] = Field(
        default_factory=list,
        description="Names of tests that failed in the baseline but pass now",
    )
    regression: bool = Field(
        default=False,
        description="Whether a regression was detected relative to the baseline",
    )


class TestRunResult(BaseModel):
    """Aggregated result of a full test run."""

    total: int = Field(
        ..., ge=0, description="Total number of tests in the run"
    )
    passed: int = Field(
        ..., ge=0, description="Number of passing tests"
    )
    failed: int = Field(
        ..., ge=0, description="Number of failing tests"
    )
    errors: int = Field(
        ..., ge=0, description="Number of tests that errored"
    )
    skipped: int = Field(
        ..., ge=0, description="Number of skipped tests"
    )
    duration_ms: int = Field(
        ..., ge=0, description="Total test run duration in milliseconds"
    )
    results: list[TestCaseResult] = Field(
        default_factory=list,
        description="Detailed results for each test case",
    )
    baseline_comparison: BaselineComparison | None = Field(
        default=None,
        description="Comparison against the baseline, if a baseline is available",
    )
