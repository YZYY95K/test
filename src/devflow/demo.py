"""Deterministic, offline end-to-end DevFlow demonstration.

The demo uses the real agent contracts and a real isolated test execution, but
replaces external LLM/GitHub services with deterministic local adapters. This
gives reviewers a reproducible proof of the collaboration loop without API
credentials. Production deployments inject the OpenAI-compatible and MCP
clients instead.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import BaseModel

from devflow.agents import (
    CoderAgent,
    LocatorAgent,
    ReviewerAgent,
    TeamLeader,
    TesterAgent,
    TriageAgent,
)
from devflow.agents.locator_agent import RootCause
from devflow.event_bus import clear, event_bus
from devflow.models.issue import (
    ComplexityLevel,
    IssueCategory,
    IssueClassification,
    IssueData,
    IssuePriority,
)
from devflow.models.patch import ChangeType, FileChange, Patch
from devflow.models.test_result import (
    BaselineComparison,
    TestCaseResult,
    TestRunResult,
    TestStatus,
)
from devflow.skills.experience_distiller import ExperienceDistillerSkill


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


class DemoLLM:
    """Deterministic structured outputs for the bundled calculator issue."""

    async def complete(self, prompt: str, **_: Any) -> str:
        return "RESOLUTION: proceed\nNEXT_AGENT: NONE"

    async def complete_structured(
        self,
        *,
        response_model: type[BaseModel],
        prompt: str,
        **_: Any,
    ) -> BaseModel:
        if response_model is IssueClassification:
            return IssueClassification(
                complexity_level=ComplexityLevel.T2,
                category=IssueCategory.BUG,
                priority=IssuePriority.HIGH,
                duplicate_of=None,
                estimated_effort_hours=1.0,
            )
        if response_model is RootCause:
            return RootCause(
                summary="add() subtracts the second operand instead of adding it.",
                file="calculator.py",
                start_line=5,
                end_line=6,
                confidence=0.99,
            )
        if response_model is Patch:
            original = (
                '"""Tiny calculator used by the reproducible DevFlow demo."""\n\n\n'
                "def add(a: int, b: int) -> int:\n"
                '    """Return the sum of two integers."""\n'
                "    return a - b\n"
            )
            updated = original.replace("return a - b", "return a + b")
            return Patch(
                branch_name="devflow/fix-calculator-add",
                changes=[
                    FileChange(
                        file_path="calculator.py",
                        change_type=ChangeType.MODIFY,
                        original_content=original,
                        new_content=updated,
                        diff=(
                            "--- a/calculator.py\n"
                            "+++ b/calculator.py\n"
                            "@@ -3,4 +3,4 @@\n"
                            " def add(a: int, b: int) -> int:\n"
                            '     """Return the sum of two integers."""\n'
                            "-    return a - b\n"
                            "+    return a + b\n"
                        ),
                    )
                ],
                commit_message="fix: add operands correctly",
                description=(
                    "Correct calculator.add and preserve the existing public API."
                ),
            )
        raise TypeError(f"DemoLLM has no fixture for {response_model.__name__}")


class DemoVectorStore:
    """Repository-local retrieval adapter for the fixture source."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo

    async def query(
        self, collection: str, query: str, n_results: int = 5
    ) -> list[dict[str, Any]]:
        if collection == "experience_store":
            return []
        content = (self.repo / "calculator.py").read_text(encoding="utf-8")
        return [
            {
                "file": "calculator.py",
                "start_line": 1,
                "end_line": len(content.splitlines()),
                "content": content,
                "score": 0.98,
            }
        ][:n_results]


class DemoMCPClient:
    """Confined file and CI adapter used by the offline demonstration."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo.resolve()

    async def call_tool(
        self, server: str, tool: str, arguments: dict[str, Any]
    ) -> Any:
        if (server, tool) == ("github", "get_file_contents"):
            path = self._safe_path(str(arguments["path"]))
            return {"content": path.read_text(encoding="utf-8")}
        if (server, tool) == ("cicd", "run_tests"):
            return await asyncio.to_thread(self._run_candidate, arguments["patch"])
        raise ValueError(f"Demo MCP tool is not available: {server}:{tool}")

    def _safe_path(self, relative: str) -> Path:
        path = PurePosixPath(relative.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"Unsafe repository path: {relative}")
        resolved = (self.repo / Path(*path.parts)).resolve()
        if self.repo not in resolved.parents and resolved != self.repo:
            raise ValueError(f"Path escapes demo repository: {relative}")
        return resolved

    def _execute_tests(self, repo: Path) -> tuple[int, str, int]:
        start = time.perf_counter()
        process = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        duration_ms = int((time.perf_counter() - start) * 1000)
        return process.returncode, process.stdout + process.stderr, duration_ms

    def _run_candidate(self, patch_payload: dict[str, Any]) -> dict[str, Any]:
        patch = Patch.model_validate(patch_payload)
        baseline_code, baseline_output, _ = self._execute_tests(self.repo)
        with tempfile.TemporaryDirectory(prefix="devflow-demo-") as temp_dir:
            candidate = Path(temp_dir) / "repo"
            shutil.copytree(self.repo, candidate)
            for change in patch.changes:
                relative = PurePosixPath(change.file_path.replace("\\", "/"))
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError(f"Unsafe patch path: {change.file_path}")
                target = candidate / Path(*relative.parts)
                if change.change_type is ChangeType.DELETE:
                    target.unlink()
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(change.new_content or "", encoding="utf-8")
            code, output, duration_ms = self._execute_tests(candidate)

        passed = int(code == 0)
        failed = int(code != 0)
        case = TestCaseResult(
            name="tests.test_calculator.CalculatorTests.test_add",
            status=TestStatus.PASSED if code == 0 else TestStatus.FAILED,
            duration_ms=duration_ms,
            error_message=None if code == 0 else "Candidate test suite failed.",
            traceback=None if code == 0 else output[-4000:],
        )
        return TestRunResult(
            total=1,
            passed=passed,
            failed=failed,
            errors=0,
            skipped=0,
            duration_ms=duration_ms,
            results=[case],
            baseline_comparison=BaselineComparison(
                baseline_passed=int(baseline_code == 0),
                current_passed=passed,
                new_failures=[],
                fixed_tests=(
                    [case.name] if baseline_code != 0 and code == 0 else []
                ),
                regression=baseline_code == 0 and code != 0,
            ),
        ).model_dump(mode="json")


class DemoExperienceStore:
    """In-memory evidence sink proving the terminal knowledge write."""

    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}

    async def store(
        self, pattern_id: str, summary: str, metadata: dict[str, Any]
    ) -> None:
        self.records[pattern_id] = {"summary": summary, "metadata": metadata}


async def run_demo(output_dir: Path | None = None) -> tuple[dict[str, Any], Path]:
    """Run all six agents and persist a JSON evidence report."""

    clear()
    repo = _root() / "examples" / "calculator_bug"
    output = output_dir or (_root() / ".devflow" / "runs")
    output.mkdir(parents=True, exist_ok=True)

    issue = IssueData(
        issue_number=1,
        title="calculator.add returns subtraction result",
        body="Calling add(2, 3) returns -1. It should return 5.",
        labels=["bug", "demo"],
        author="devflow-demo",
        created_at=datetime.now(timezone.utc),
        repo_owner="local",
        repo_name="calculator_bug",
    )
    llm = DemoLLM()
    vector_store = DemoVectorStore(repo)
    mcp = DemoMCPClient(repo)
    experience_store = DemoExperienceStore()

    leader = TeamLeader(llm_client=llm)
    triage = TriageAgent(llm_client=llm, vector_store=vector_store)
    locator = LocatorAgent(
        llm_client=llm, vector_store=vector_store, mcp_client=mcp
    )
    coder = CoderAgent(llm_client=llm)
    tester = TesterAgent(llm_client=llm, mcp_client=mcp)
    reviewer = ReviewerAgent(llm_client=llm, mcp_client=mcp)
    distiller = ExperienceDistillerSkill(store=experience_store)

    classification = await triage.execute(issue)
    tasks = await leader.decompose_task(issue, classification)
    located = await locator.execute(
        {
            "issue_id": issue.issue_number,
            "issue": issue.model_dump(mode="json"),
            "tier": classification.complexity_level.value,
        }
    )
    patch = await coder.execute(
        {
            "issue_id": issue.issue_number,
            "issue": issue.model_dump(mode="json"),
            "tier": classification.complexity_level.value,
            "located_context": located.model_dump(mode="json"),
        }
    )
    test_result = await tester.execute(
        {
            "issue_id": issue.issue_number,
            "tier": classification.complexity_level.value,
            "patch": patch.model_dump(mode="json"),
        }
    )
    review = await reviewer.execute(
        {
            "issue_id": issue.issue_number,
            "tier": classification.complexity_level.value,
            "patch": patch.model_dump(mode="json"),
            "test_result": test_result.model_dump(mode="json"),
            "create_pr": False,
        }
    )
    trace_id = f"demo-{issue.issue_number}"
    experience = await distiller.run(
        issue=issue.model_dump(mode="json"),
        tier=classification.complexity_level.value,
        repository_revision="demo-fixture-v1",
        located_context=located.model_dump(mode="json"),
        patch=patch.model_dump(mode="json"),
        test_result=test_result.model_dump(mode="json"),
        review=review.model_dump(mode="json"),
        trace_id=trace_id,
    )

    report = {
        "schema_version": "1.0",
        "mode": "offline-deterministic",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scenario": "calculator_bug",
        "issue": issue.model_dump(mode="json"),
        "classification": classification.model_dump(mode="json"),
        "plan": [
            {
                "task_id": task.task_id,
                "agent": task.agent,
                "skill": task.skill,
                "depends_on": task.depends_on,
            }
            for task in tasks
        ],
        "located_context": located.model_dump(mode="json"),
        "patch": patch.model_dump(mode="json"),
        "test_result": test_result.model_dump(mode="json"),
        "review": review.model_dump(mode="json"),
        "experience": experience,
        "events": [
            {
                "event_type": record.event_type,
                "timestamp": record.timestamp.isoformat(),
                "payload": record.payload,
            }
            for record in event_bus.history()
        ],
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = output / f"demo-{stamp}.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return report, report_path
