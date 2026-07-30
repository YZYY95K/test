"""Deterministic, offline end-to-end DevFlow demonstration.

The demo uses the real agent contracts and a real isolated test execution, but
replaces external LLM/GitHub services with deterministic local adapters. This
gives reviewers a reproducible proof of the collaboration loop without API
credentials. Production deployments inject the OpenAI-compatible and MCP
clients instead.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
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
from devflow.agents.locator_agent import LocatedContext, RootCause
from devflow.collaboration import DurableRouteLedger
from devflow.event_bus import LocalAgentEventRuntime, clear, event_bus, publish
from devflow.local_runtime import LocalAgentTaskRouter
from devflow.mcp.cicd import PORTABLE_CICD_SERVER, IsolatedTestService
from devflow.mcp.context_auth import HMACContextAuthority
from devflow.mcp.contracts import MCPCallContext
from devflow.mcp.policy import MCPPolicy, MemoryAuditSink, PolicyEnforcedMCPClient
from devflow.models.issue import (
    ComplexityLevel,
    IssueCategory,
    IssueClassification,
    IssueData,
    IssuePriority,
)
from devflow.models.patch import ChangeType, FileChange, Patch
from devflow.models.review import ReviewResult
from devflow.models.test_result import TestRunResult
from devflow.skills.contracts import HandoffEnvelope


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
                "    return a - b\n\n"
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
                description=("Correct calculator.add and preserve the existing public API."),
            )
        raise TypeError(f"DemoLLM has no fixture for {response_model.__name__}")


class DemoVectorStore:
    """Repository-local retrieval adapter for the fixture source."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo

    async def query(self, collection: str, query: str, n_results: int = 5) -> list[dict[str, Any]]:
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
    """Confined CI adapter used by the offline demonstration."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo.resolve()

    async def call_tool(self, server: str, tool: str, arguments: dict[str, Any]) -> Any:
        if (server, tool) == (PORTABLE_CICD_SERVER, "run_tests"):
            patch = Patch.model_validate(arguments["patch"])
            context = MCPCallContext.model_validate(arguments["devflow_context"])
            if context.risk_tier is None:
                raise ValueError("portable demo CI requires a signed risk tier")
            service = IsolatedTestService(
                self.repo,
                (
                    sys.executable,
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "tests",
                    "-p",
                    "test_calculator.py",
                    "-v",
                ),
                (sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"),
                timeout_seconds=30,
            )
            result = await service.run_tests(
                patch,
                risk_tier=context.risk_tier,
            )
            return result.model_dump(mode="json")
        raise ValueError(f"Demo MCP tool is not available: {server}:{tool}")

class DemoExperienceStore:
    """In-memory evidence sink proving the terminal knowledge write."""

    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}

    async def store(self, pattern_id: str, summary: str, metadata: dict[str, Any]) -> None:
        self.records[pattern_id] = {"summary": summary, "metadata": metadata}


async def run_demo(output_dir: Path | None = None) -> tuple[dict[str, Any], Path]:
    """Run all six agents and persist a JSON evidence report."""

    clear()
    repo = _root() / "examples" / "calculator_bug"
    output = output_dir or (_root() / ".devflow" / "runs")
    output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    ledger_path = output / f"demo-{stamp}.routes.sqlite3"
    route_ledger = DurableRouteLedger(
        ledger_path,
        owner_id=f"offline-demo-{stamp}",
    )

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
    mcp_audit = MemoryAuditSink()
    context_authority = HMACContextAuthority(b"devflow-offline-demo-context-key-only")
    mcp = PolicyEnforcedMCPClient(
        DemoMCPClient(repo),
        MCPPolicy.from_file(_root() / "config" / "mcp_servers.portable.yaml"),
        mcp_audit,
        context_signer=context_authority,
    )
    experience_store = DemoExperienceStore()

    leader = TeamLeader(llm_client=llm, execution_ledger=route_ledger)
    triage = TriageAgent(llm_client=llm, vector_store=vector_store)
    locator = LocatorAgent(llm_client=llm, vector_store=vector_store, mcp_client=mcp)
    coder = CoderAgent(llm_client=llm)
    tester = TesterAgent(llm_client=llm, mcp_client=mcp)
    reviewer = ReviewerAgent(
        llm_client=llm,
        mcp_client=mcp,
        experience_store=experience_store,
    )
    router = LocalAgentTaskRouter(
        leader,
        triage,
        locator,
        coder,
        tester,
        reviewer,
    )
    runtime = LocalAgentEventRuntime(leader, router).start()
    try:
        await publish(
            "issue.created",
            {
                "issue": issue.model_dump(mode="json"),
                "repository_revision": "demo-fixture-v1",
                "create_pr": False,
            },
        )
    finally:
        runtime.stop()

    context = leader.issue_snapshot(issue.issue_number)
    classification = IssueClassification.model_validate(context["classification"])
    located = LocatedContext.model_validate(context["located_context"])
    patch = Patch.model_validate(context["previous_patch"])
    test_result = TestRunResult.model_validate(context["test_result"])
    review = ReviewResult.model_validate(context["review"])
    experience = context["experience"]
    route_envelopes = [
        HandoffEnvelope.model_validate(record.payload)
        for record in event_bus.history()
        if record.event_type.startswith("task.route.")
    ]
    ledger_snapshot = route_ledger.snapshot()
    audit_verification = route_ledger.verify_audit_chain()

    report = {
        "schema_version": "1.0",
        "mode": "offline-deterministic",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scenario": "calculator_bug",
        "issue": issue.model_dump(mode="json"),
        "classification": classification.model_dump(mode="json"),
        "plan": [
            {
                "task_id": route.task_id,
                "agent": route.consumer,
                "skill": route.skill,
                "depends_on": (
                    route.artifact.inline.get("depends_on", [])
                    if route.artifact.inline is not None
                    else []
                ),
            }
            for route in route_envelopes
        ],
        "located_context": located.model_dump(mode="json"),
        "patch": patch.model_dump(mode="json"),
        "test_result": test_result.model_dump(mode="json"),
        "review": review.model_dump(mode="json"),
        "experience": experience,
        "terminal_receipt": context["terminal_receipt"],
        "terminal_state": leader.get_lifecycle(issue.issue_number).value,
        "collaboration_ledger": {
            "schema_version": "devflow.collaboration-ledger-evidence/v1",
            "file": ledger_path.name,
            "snapshot": asdict(ledger_snapshot),
            "audit_chain": asdict(audit_verification),
        },
        "mcp_audit": [entry.model_dump(mode="json") for entry in mcp_audit.records],
        "events": [
            {
                "event_type": record.event_type,
                "timestamp": record.timestamp.isoformat(),
                "payload": record.payload,
            }
            for record in event_bus.history()
        ],
    }
    report_path = output / f"demo-{stamp}.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return report, report_path
