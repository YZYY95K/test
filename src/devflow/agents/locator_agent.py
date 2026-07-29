"""LocatorAgent — code root-cause analysis and impact assessment.

Uses retrieval-augmented generation over the indexed codebase (ChromaDB) to
pinpoint the likely root-cause file(s)/function(s), fetches the exact file
contents via the GitHub MCP, and assembles a token-budgeted context payload
that the :class:`~devflow.agents.coder_agent.CoderAgent` consumes to generate
a patch.

It owns the ``code-root-cause`` skill and emits ``locator.completed``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from devflow.agents.base import AgentIdentity, BaseAgent
from devflow.exceptions import AgentError
from devflow.models.issue import ComplexityLevel, IssueData
from devflow.models.patch import ImpactAnalysis, RiskLevel
from devflow.observability import logger

#: ChromaDB collection holding the indexed codebase for RAG retrieval.
_CODEBASE_COLLECTION = "codebase_index"
#: Hard token budget for the assembled context payload.
_MAX_CONTEXT_TOKENS = 8000
#: Broaden the RAG query this many times before giving up (per skills.yaml).
_MAX_BROADEN_ATTEMPTS = 2


class RootCause(BaseModel):
    """The located root cause of a bug."""

    summary: str = Field(..., description="Concise description of the root cause")
    file: str = Field(..., description="Repository-relative path of the faulty file")
    start_line: int = Field(..., ge=1, description="Start line of the faulty region")
    end_line: int = Field(..., ge=1, description="End line of the faulty region")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence in the localization (0-1)"
    )


class AffectedFile(BaseModel):
    """A file affected by or relevant to the fix."""

    path: str = Field(..., description="Repository-relative file path")
    reason: str = Field(..., description="Why this file is affected")
    change_type: str = Field(
        ..., description="One of: edit, review, test"
    )


class LocatedContext(BaseModel):
    """The contract produced by LocatorAgent and consumed by CoderAgent.

    This bundles the root cause, the token-budgeted context payload, the
    impact analysis and the related test files into a single structured object.
    """

    root_cause: RootCause
    affected_files: list[AffectedFile] = Field(default_factory=list)
    context_payload: str = Field(
        ..., description="Packed code snippets + signatures within token budget"
    )
    related_tests: list[str] = Field(default_factory=list)
    impact_analysis: ImpactAnalysis


class LocatorAgent(BaseAgent):
    """Performs code root-cause analysis and impact assessment via RAG."""

    _IDENTITY = AgentIdentity(
        role="Locator Agent",
        description=(
            "Performs code root cause analysis and impact assessment using RAG "
            "over the indexed repository, producing a located-context payload "
            "for the CoderAgent."
        ),
        model="glm-5.2",
        temperature=0.4,  # slightly higher to explore candidate locations
    )
    _CAPABILITIES = (
        "code_root_cause",
        "impact_assessment",
        "rag_retrieval",
        "context_packaging",
    )
    _BOUNDARIES = (
        "Cannot write or modify source files",
        "Cannot execute repository code",
        "Context payload must stay under the CoderAgent input token budget",
    )
    # Task execution is accepted only from TeamLeader routes. Repository index
    # refreshes are infrastructure notifications, not peer-to-peer work.
    _WATCHES = ("codebase.indexed",)
    _OWNED_SKILLS = ("code-root-cause", "github-evidence")
    _HANDOFF_PRODUCERS = {
        "code-root-cause": frozenset({"TeamLeader"}),
        "github-evidence": frozenset({"TeamLeader"}),
    }
    _FORBIDDEN_ACTIONS = {
        "write_source_files": "Cannot write or modify source files",
        "execute_code": "Cannot execute repository code",
    }

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.register_event_handler("codebase.indexed", self._on_codebase_indexed)

    # ------------------------------------------------------------------ #
    # Event handlers
    # ------------------------------------------------------------------ #
    async def _on_codebase_indexed(self, payload: dict[str, Any]) -> None:
        logger.info(
            "locator.codebase_reindexed",
            collection=payload.get("collection", _CODEBASE_COLLECTION),
        )
        # No immediate action — subsequent locator runs will use the fresh index.

    # ------------------------------------------------------------------ #
    # Core logic
    # ------------------------------------------------------------------ #
    async def run(self, input_data: Any) -> LocatedContext:
        """Locate the root cause and assemble the context payload.

        Args:
            input_data: A dict with ``issue`` (serialised IssueData) and
                ``tier`` (a T1-T5 string).

        Returns:
            The :class:`LocatedContext` for the CoderAgent.
        """
        issue, tier = self._parse_input(input_data)
        async with self._trace_span(
            "code-root-cause", issue_id=issue.issue_number, tier=tier.value
        ):
            # 1. RAG retrieval — broadens the query if results are empty.
            snippets = await self._retrieve_with_broadening(issue)

            # 2. Fetch exact file contents for the top candidates via GitHub MCP.
            file_contents = await self._fetch_file_contents(snippets, issue)

            # 3. LLM-backed root-cause reasoning over the retrieved context.
            root_cause = await self._identify_root_cause(issue, tier, snippets, file_contents)

            # 4. Impact analysis (affected files, risk level, breaking changes).
            impact = await self._assess_impact(issue, root_cause, snippets)

            # 5. Package the token-budgeted context payload for the Coder.
            context_payload = self._package_context(
                root_cause, snippets, file_contents
            )

            located = LocatedContext(
                root_cause=root_cause,
                affected_files=[
                    AffectedFile(path=f.path, reason=f.reason, change_type=f.change_type)
                    for f in impact_files(impact, root_cause)
                ],
                context_payload=context_payload,
                related_tests=impact.test_files_needed,
                impact_analysis=impact,
            )
            logger.info(
                "locator.completed",
                issue_id=issue.issue_number,
                root_file=root_cause.file,
                confidence=root_cause.confidence,
                affected=len(located.affected_files),
            )
            await self._emit_handoff(
                "locator.completed",
                issue_id=issue.issue_number,
                consumer="TeamLeader",
                skill="code-root-cause",
                artifact_type="LocatedContext",
                payload={
                    "issue_id": issue.issue_number,
                    "tier": tier.value,
                    "located_context": located.model_dump(mode="json"),
                },
            )
            return located

    @staticmethod
    def _parse_input(input_data: Any) -> tuple[IssueData, ComplexityLevel]:
        if not isinstance(input_data, dict):
            raise AgentError(
                "LocatorAgent expects a dict with 'issue' and 'tier' keys."
            )
        issue_raw = input_data.get("issue")
        issue_id_raw = input_data.get("issue_id")
        tier_raw = input_data.get("tier")
        if (
            issue_raw is None
            or issue_id_raw is None
            or tier_raw is None
            or set(input_data) != {"issue_id", "issue", "tier"}
        ):
            raise AgentError(
                "LocatorAgent input requires exact issue_id, issue, and tier fields."
            )
        issue = issue_raw if isinstance(issue_raw, IssueData) else IssueData(**issue_raw)
        if isinstance(issue_id_raw, bool) or int(issue_id_raw) != issue.issue_number:
            raise AgentError("LocatorAgent issue_id does not match the issue artifact.")
        tier = ComplexityLevel(tier_raw) if not isinstance(tier_raw, ComplexityLevel) else tier_raw
        return issue, tier

    # ------------------------------------------------------------------ #
    # RAG retrieval with query broadening
    # ------------------------------------------------------------------ #
    async def _retrieve_with_broadening(
        self, issue: IssueData
    ) -> list[dict[str, Any]]:
        """Query the codebase index, broadening the query on empty results.

        Per ``skills.yaml``: on ``on_retrieval_empty`` the action is
        ``broaden_query`` (up to 2 attempts), then ``return_low_confidence``.
        """
        query = f"{issue.title}\n{issue.body or ''}"
        snippets: list[dict[str, Any]] = []
        for attempt in range(_MAX_BROADEN_ATTEMPTS + 1):
            snippets = await self._query_vector_store(
                _CODEBASE_COLLECTION, query, n_results=5
            )
            if snippets:
                break
            # Broaden: drop trailing detail to widen the semantic match.
            query = issue.title
            logger.warning(
                "locator.retrieval_empty_broadening",
                issue_id=issue.issue_number,
                attempt=attempt + 1,
            )
        if not snippets:
            logger.warning(
                "locator.retrieval_empty",
                issue_id=issue.issue_number,
                action="return_low_confidence",
            )
        return snippets

    # ------------------------------------------------------------------ #
    # GitHub MCP — fetch exact file contents
    # ------------------------------------------------------------------ #
    async def _fetch_file_contents(
        self,
        snippets: list[dict[str, Any]],
        issue: IssueData,
    ) -> dict[str, str]:
        """Fetch exact file contents for the top candidate paths via GitHub MCP.

        Falls back to the snippet text baked into the RAG results when the MCP
        is unavailable, so localization still produces *something* useful.
        """
        contents: dict[str, str] = {}
        seen: set[str] = set()
        for snippet in snippets:
            path = snippet.get("file") or snippet.get("path")
            if not path or path in seen:
                continue
            seen.add(path)
            try:
                result = await self._call_mcp(
                    "github",
                    "get_file_contents",
                    {
                        "owner": issue.repo_owner,
                        "repo": issue.repo_name,
                        "path": path,
                    },
                    skill="code-root-cause",
                    issue_id=issue.issue_number,
                )
                contents[path] = _extract_content(result) or snippet.get("content", "")
            except Exception as exc:  # noqa: BLE001 — degrade to snippet
                logger.warning(
                    "locator.mcp_fetch_failed",
                    path=path,
                    error=str(exc),
                )
                contents[path] = snippet.get("content", "")
        return contents

    # ------------------------------------------------------------------ #
    # LLM root-cause identification
    # ------------------------------------------------------------------ #
    async def _identify_root_cause(
        self,
        issue: IssueData,
        tier: ComplexityLevel,
        snippets: list[dict[str, Any]],
        file_contents: dict[str, str],
    ) -> RootCause:
        prompt = self._build_root_cause_prompt(issue, tier, snippets, file_contents)
        try:
            root_cause = await self.llm.complete_structured(
                prompt=prompt,
                response_model=RootCause,
                model=self.identity.model,
                temperature=self.identity.temperature,
                system=self.system_prompt,
            )
        except Exception as exc:  # noqa: BLE001 — low-confidence fallback
            logger.warning(
                "locator.root_cause_failed",
                issue_id=issue.issue_number,
                error=str(exc),
            )
            # Best-effort: synthesize a low-confidence root cause from snippets.
            first = snippets[0] if snippets else {}
            root_cause = RootCause(
                summary="Root-cause identification failed; using best-effort location.",
                file=first.get("file", "unknown"),
                start_line=int(first.get("start_line", 1)),
                end_line=int(first.get("end_line", 1)),
                confidence=0.1,
            )
        return self._validate_output(root_cause, RootCause)

    def _build_root_cause_prompt(
        self,
        issue: IssueData,
        tier: ComplexityLevel,
        snippets: list[dict[str, Any]],
        file_contents: dict[str, str],
    ) -> str:
        snippet_text = "\n\n".join(
            f"# {s.get('file', '?')}:{s.get('start_line', '?')}\n{s.get('content', '')}"
            for s in snippets
        )
        file_text = "\n\n".join(
            f"# --- {path} ---\n{content[:2000]}" for path, content in file_contents.items()
        )
        return (
            "You are locating the root cause of a bug in a codebase.\n\n"
            f"Issue #{issue.issue_number} ({tier.value}): {issue.title}\n"
            f"{issue.body or '(no body)'}\n\n"
            "Retrieved code snippets:\n"
            f"{snippet_text or '(none)'}\n\n"
            "Fetched file contents:\n"
            f"{file_text or '(none)'}\n\n"
            "Identify the single most likely root-cause location. Return the "
            "result matching the RootCause schema."
        )

    # ------------------------------------------------------------------ #
    # Impact analysis
    # ------------------------------------------------------------------ #
    async def _assess_impact(
        self,
        issue: IssueData,
        root_cause: RootCause,
        snippets: list[dict[str, Any]],
    ) -> ImpactAnalysis:
        affected_files = self._collect_affected_files(root_cause, snippets)
        risk = self._derive_risk_level(root_cause, len(affected_files))
        return ImpactAnalysis(
            affected_files=affected_files,
            affected_modules=self._derive_modules(affected_files),
            risk_level=risk,
            breaking_changes=risk in (RiskLevel.HIGH, RiskLevel.CRITICAL),
            test_files_needed=self._derive_test_files(affected_files),
        )

    @staticmethod
    def _collect_affected_files(
        root_cause: RootCause, snippets: list[dict[str, Any]]
    ) -> list[str]:
        files: list[str] = [root_cause.file]
        for snippet in snippets:
            path = snippet.get("file") or snippet.get("path")
            if path and path not in files:
                files.append(path)
        return files

    @staticmethod
    def _derive_modules(file_paths: list[str]) -> list[str]:
        modules: list[str] = []
        for path in file_paths:
            parts = path.replace("\\", "/").split("/")
            if len(parts) > 1:
                module = parts[-2]
                if module not in modules:
                    modules.append(module)
        return modules

    @staticmethod
    def _derive_risk_level(root_cause: RootCause, affected_count: int) -> RiskLevel:
        if root_cause.confidence < 0.3 or affected_count > 5:
            return RiskLevel.CRITICAL
        if affected_count > 2:
            return RiskLevel.HIGH
        if affected_count > 1:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _derive_test_files(file_paths: list[str]) -> list[str]:
        test_files: list[str] = []
        for path in file_paths:
            normalized = path.replace("\\", "/")
            base = normalized.rsplit("/", 1)[-1]
            if base.endswith(".py"):
                name = base[:-3]
                test_files.append(f"tests/test_{name}.py")
        return test_files

    # ------------------------------------------------------------------ #
    # Context packaging (token-budgeted)
    # ------------------------------------------------------------------ #
    def _package_context(
        self,
        root_cause: RootCause,
        snippets: list[dict[str, Any]],
        file_contents: dict[str, str],
    ) -> str:
        """Assemble a token-budgeted context payload for the CoderAgent.

        Truncates the oldest snippets first when the payload would exceed the
        hard token limit (per ``skills.yaml`` ``on_context_overflow``).
        """
        header = (
            f"Root cause: {root_cause.summary}\n"
            f"File: {root_cause.file}:{root_cause.start_line}-{root_cause.end_line}\n"
            f"Confidence: {root_cause.confidence:.2f}\n\n"
        )
        sections: list[str] = [header]
        # Newest (highest-index) snippets first, so oldest are dropped on overflow.
        for path, content in file_contents.items():
            sections.append(f"# --- {path} ---\n{content}\n")
        for snippet in snippets:
            path = snippet.get("file", "?")
            sections.append(
                f"# snippet {path}:{snippet.get('start_line', '?')}\n{snippet.get('content', '')}\n"
            )
        payload = ""
        for section in sections:
            if _estimate_tokens(payload + section) > _MAX_CONTEXT_TOKENS:
                logger.warning(
                    "locator.context_truncated",
                    dropped_section=section.splitlines()[0] if section else "",
                )
                break
            payload += section
        return payload


def impact_files(impact: ImpactAnalysis, root_cause: RootCause) -> list[AffectedFile]:
    """Build :class:`AffectedFile` entries from an impact analysis."""
    entries: list[AffectedFile] = []
    for path in impact.affected_files:
        if path == root_cause.file:
            change_type = "edit"
            reason = "Contains the identified root cause."
        elif path.startswith("tests") or path.startswith("test"):
            change_type = "test"
            reason = "Test file covering the affected code."
        else:
            change_type = "review"
            reason = "Referenced by the root-cause region; review for impact."
        entries.append(AffectedFile(path=path, reason=reason, change_type=change_type))
    return entries


def _extract_content(result: Any) -> str:
    """Extract textual content from a GitHub MCP ``get_file_contents`` result."""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        return result.get("content") or result.get("text") or ""
    return getattr(result, "content", "") or ""


def _estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token) for budget enforcement."""
    return len(text) // 4


__all__ = ["AffectedFile", "LocatedContext", "LocatorAgent", "RootCause"]
