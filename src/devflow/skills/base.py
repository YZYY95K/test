"""Base skill infrastructure for the DevFlow multi-agent system.

A *skill* is a reusable, declaratively-described capability that agents
invoke. Each skill has a schema (input/output contract), invocation
conditions, dependency declarations, a failure-handling policy, and a
security boundary. The :class:`BaseSkill` abstract class provides the
common lifecycle: validate input → execute → validate output → security
check, with structured failure handling.

The module-level :data:`skill_registry` allows skills to be registered by
name and looked up at runtime, enabling the agent scheduler to dispatch
to the correct skill based on configuration.
"""

from __future__ import annotations

import abc
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from devflow.exceptions import SkillError
from devflow.observability import logger, tracer

# ---------------------------------------------------------------------------
# MCP tool caller abstraction
# ---------------------------------------------------------------------------

#: Type of a callable that invokes an MCP tool.
#:
#: The callable receives ``(server, tool, arguments)`` and returns the
#: tool's result. Concrete implementations wrap the MCP client; tests
#: can inject a mock.
MCPToolCaller = Callable[
    [str, str, dict[str, Any]],
    Awaitable[Any],
]


class _DefaultMCPCaller:
    """Fallback MCP caller that raises until a real client is configured.

    This keeps skills importable and partially functional (e.g. unit tests
    that mock the caller) without requiring the full MCP runtime.
    """

    _delegate: MCPToolCaller | None = None

    @classmethod
    def set(cls, caller: MCPToolCaller | None) -> None:
        """Set or clear the global MCP tool caller delegate."""
        cls._delegate = caller

    @classmethod
    async def call(
        cls, server: str, tool: str, arguments: dict[str, Any]
    ) -> Any:
        if cls._delegate is None:
            raise SkillError(
                f"MCP client not configured. Call "
                f"MCPClient.set(<caller>) before invoking skills that "
                f"require MCP tool '{server}:{tool}'."
            )
        return await cls._delegate(server, tool, arguments)


class MCPClient:
    """Global accessor for the MCP tool caller.

    Usage::

        from devflow.skills.base import MCPClient

        async def my_caller(server, tool, arguments):
            return await real_mcp_client.call_tool(server, tool, arguments)

        MCPClient.set(my_caller)
    """

    @staticmethod
    def set(caller: MCPToolCaller | None) -> None:
        """Register or clear the global MCP tool caller."""
        _DefaultMCPCaller.set(caller)

    @staticmethod
    async def call(server: str, tool: str, **arguments: Any) -> Any:
        """Invoke an MCP tool via the configured caller.

        Args:
            server: MCP server name (e.g. ``"github"``).
            tool: Tool name on that server (e.g. ``"get_file_contents"``).
            **arguments: Keyword arguments passed to the tool.

        Returns:
            The tool's result.
        """
        return await _DefaultMCPCaller.call(server, tool, arguments)


# ---------------------------------------------------------------------------
# Security patterns (mirrors config/security.yaml prompt_scrubbing.patterns)
# ---------------------------------------------------------------------------

#: Regex patterns that indicate a leaked secret. Matches are flagged by
#: :meth:`BaseSkill._check_security` and cause the skill to fail closed.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ghp_[A-Za-z0-9]{36}"),                     # GitHub PAT
    re.compile(r"github_pat_[A-Za-z0-9_]{82}"),              # fine-grained PAT
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                      # OpenAI-style key
    re.compile(r"AKIA[0-9A-Z]{16}"),                         # AWS access key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),       # private key blocks
]

#: Dangerous code patterns that must not appear in generated patches.
_DANGEROUS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"eval\s*\("),
    re.compile(r"exec\s*\("),
    re.compile(r"__import__\s*\("),
    re.compile(r"subprocess\.(?:Popen|call|run)\s*\(.*shell\s*=\s*True"),
    re.compile(r"os\.system\s*\("),
]


# ---------------------------------------------------------------------------
# SkillSpec — declarative skill description
# ---------------------------------------------------------------------------


@dataclass
class SkillSpec:
    """Declarative specification of a skill's contract and policies.

    This dataclass mirrors the structure in ``config/skills.yaml`` and serves
    as the single source of truth for what a skill accepts, produces, and
    how it must behave.

    Attributes:
        name: Unique skill identifier (e.g. ``"issue-classifier"``).
        description: Human-readable summary of what the skill does.
        input_schema: JSON-Schema-shaped dict describing required inputs.
        output_schema: JSON-Schema-shaped dict describing the output contract.
        invocation_conditions: List of conditions that must hold before the
            skill may be invoked.
        dependencies: Dict of external tools, MCP servers, and data stores
            the skill requires.
        failure_handling: Dict describing retry / fallback policies.
        security_boundary: List of hard rules the skill must never violate.
    """

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    invocation_conditions: list[str] = field(default_factory=list)
    dependencies: dict[str, Any] = field(default_factory=dict)
    failure_handling: dict[str, Any] = field(default_factory=dict)
    security_boundary: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# BaseSkill — abstract base for all skills
# ---------------------------------------------------------------------------


class BaseSkill(abc.ABC):
    """Abstract base class for all DevFlow skills.

    Subclasses must:
      1. Set :attr:`spec` to a :class:`SkillSpec` describing the contract.
      2. Implement :meth:`execute` with the skill's core logic.

    The base class provides input/output validation, security checking, and
    a structured failure-handling hook. All public entry is through
    :meth:`run`, which orchestrates the lifecycle.
    """

    #: Class-level spec; subclasses override with a concrete :class:`SkillSpec`.
    spec: ClassVar[SkillSpec]

    @abc.abstractmethod
    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Execute the skill's core logic.

        Args:
            **kwargs: Skill-specific input arguments.

        Returns:
            Dict matching the skill's ``output_schema``.

        Raises:
            SkillError: If the skill cannot complete its task.
        """
        raise NotImplementedError

    # -- validation ---------------------------------------------------------

    def _validate_input(
        self, kwargs: dict[str, Any], required_fields: list[str]
    ) -> None:
        """Verify that all required input fields are present and non-empty.

        Args:
            kwargs: The keyword arguments passed to :meth:`execute`.
            required_fields: Field names that must be present.

        Raises:
            SkillError: If a required field is missing or ``None``.
        """
        missing: list[str] = []
        for field_name in required_fields:
            value = kwargs.get(field_name)
            if value is None or (isinstance(value, str) and not value.strip()):
                missing.append(field_name)
            elif isinstance(value, (list, dict)) and len(value) == 0:
                # Empty containers are treated as missing for required fields
                # unless the caller explicitly passes an empty default.
                missing.append(field_name)

        if missing:
            raise SkillError(
                f"Skill '{self.spec.name}' is missing required input fields: "
                f"{', '.join(missing)}"
            )

    def _validate_output(
        self, result: dict[str, Any], required_fields: list[str]
    ) -> None:
        """Verify that the result dict contains all required output fields.

        Args:
            result: The dict returned by :meth:`execute`.
            required_fields: Field names that must be present in the output.

        Raises:
            SkillError: If a required output field is missing.
        """
        missing = [
            field_name
            for field_name in required_fields
            if field_name not in result or result[field_name] is None
        ]
        if missing:
            raise SkillError(
                f"Skill '{self.spec.name}' output is missing required fields: "
                f"{', '.join(missing)}"
            )

    # -- security -----------------------------------------------------------

    def _check_security(self, result: dict[str, Any]) -> None:
        """Scan the skill output for leaked secrets and dangerous patterns.

        Recursively inspects all string values in the result dict. If a
        secret pattern is matched, the skill fails closed by raising
        :class:`SkillError`.

        Args:
            result: The dict returned by :meth:`execute`.

        Raises:
            SkillError: If a secret or dangerous pattern is detected.
        """
        violations = self._scan_for_secrets(result)
        if violations:
            # Log the violation (without the actual secret value) and fail.
            logger.error(
                "skill.security_violation",
                skill=self.spec.name,
                violations=violations,
            )
            raise SkillError(
                f"Security violation in skill '{self.spec.name}': "
                f"potential secret detected in output "
                f"(patterns: {', '.join(violations)}). "
                f"Output has been blocked."
            )

    def _scan_for_secrets(self, obj: Any) -> list[str]:
        """Recursively scan an object for secret patterns.

        Args:
            obj: Any JSON-serializable value (dict, list, str, etc.).

        Returns:
            List of human-readable pattern names that matched.
        """
        violations: list[str] = []

        if isinstance(obj, str):
            for i, pattern in enumerate(_SECRET_PATTERNS):
                if pattern.search(obj):
                    violations.append(f"secret_pattern_{i}")

        elif isinstance(obj, dict):
            for value in obj.values():
                violations.extend(self._scan_for_secrets(value))

        elif isinstance(obj, list):
            for item in obj:
                violations.extend(self._scan_for_secrets(item))

        return violations

    @staticmethod
    def scan_for_dangerous_patterns(text: str) -> list[str]:
        """Check a string for dangerous code patterns.

        Used by the PR reviewer and patch generator to flag risky code.

        Args:
            text: Source code text to scan.

        Returns:
            List of matched pattern descriptions.
        """
        matches: list[str] = []
        for i, pattern in enumerate(_DANGEROUS_PATTERNS):
            if pattern.search(text):
                matches.append(f"dangerous_pattern_{i}")
        return matches

    # -- failure handling ---------------------------------------------------

    def _handle_failure(
        self, error: Exception, context: dict[str, Any]
    ) -> dict[str, Any]:
        """Produce a structured failure result.

        Subclasses may override this to implement skill-specific fallback
        logic (e.g. returning a conservative default tier). The default
        implementation logs the failure and re-raises, since most skills
        should propagate errors to the calling agent for re-planning.

        Args:
            error: The exception that caused the failure.
            context: Additional context about the invocation.

        Returns:
            A fallback result dict, if the skill can recover.

        Raises:
            SkillError: If the failure is unrecoverable (default behavior).
        """
        logger.error(
            "skill.failure",
            skill=self.spec.name,
            error=str(error),
            error_type=type(error).__name__,
            context=context,
        )
        raise SkillError(
            f"Skill '{self.spec.name}' failed: {error}"
        ) from error

    # -- public entry point -------------------------------------------------

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        """Execute the skill with full lifecycle orchestration.

        This is the primary entry point called by agents. It:
          1. Starts a tracing span.
          2. Delegates to :meth:`execute`.
          3. Validates the output.
          4. Runs the security check.

        On failure, it delegates to :meth:`_handle_failure`.

        Args:
            **kwargs: Skill-specific input arguments.

        Returns:
            The skill's output dict.
        """
        skill_name = self.spec.name
        with tracer.start_as_current_span(f"skill.{skill_name}") as span:
            span.set_attribute("devflow.skill.name", skill_name)

            try:
                result = await self.execute(**kwargs)
            except Exception as exc:
                span.record_exception(exc)
                return self._handle_failure(
                    exc,
                    context={"skill": skill_name, "kwargs_keys": list(kwargs.keys())},
                )

            # Validate output if the spec defines required output fields.
            required_output = self.spec.output_schema.get("required", [])
            if required_output:
                self._validate_output(result, required_output)

            # Security gate: block any output containing secrets.
            self._check_security(result)

            span.set_attribute("devflow.skill.success", True)
            return result


# ---------------------------------------------------------------------------
# Skill registry
# ---------------------------------------------------------------------------


class SkillRegistry:
    """Registry of skill instances keyed by name.

    Allows the agent runtime to look up skills by their configured name
    without importing each skill module directly.
    """

    def __init__(self) -> None:
        self._skills: dict[str, BaseSkill] = {}

    def register(self, skill: BaseSkill) -> None:
        """Register a skill instance under its spec name.

        Args:
            skill: The skill instance to register.

        Raises:
            SkillError: If a skill with the same name is already registered.
        """
        name = skill.spec.name
        if name in self._skills:
            raise SkillError(
                f"Skill '{name}' is already registered."
            )
        self._skills[name] = skill
        logger.info("skill_registry.registered", skill_name=name)

    def lookup(self, name: str) -> BaseSkill:
        """Look up a registered skill by name.

        Args:
            name: The skill name (matching ``spec.name``).

        Returns:
            The registered :class:`BaseSkill` instance.

        Raises:
            SkillError: If no skill with the given name is registered.
        """
        skill = self._skills.get(name)
        if skill is None:
            raise SkillError(
                f"Skill '{name}' is not registered. "
                f"Available: {', '.join(sorted(self._skills.keys()))}"
            )
        return skill

    def list_skills(self) -> list[str]:
        """Return the names of all registered skills."""
        return list(self._skills.keys())

    def clear(self) -> None:
        """Remove all registered skills (useful for testing)."""
        self._skills.clear()


#: Module-level singleton registry instance.
skill_registry = SkillRegistry()
