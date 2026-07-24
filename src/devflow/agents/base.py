"""Base agent abstractions for the DevFlow multi-agent system.

This module defines the :class:`AgentState` lifecycle enum, the declarative
:class:`AgentIdentity` / :class:`AgentConfig` data classes, and the abstract
:class:`BaseAgent` that every worker agent inherits from.

``BaseAgent`` centralises the cross-cutting concerns shared by every agent so
that the concrete subclasses can focus on their domain logic:

* **Identity & boundaries** — loaded from ``config/agents.yaml`` (mirrored as
  class-level defaults) so an agent always knows what it may and may not do.
* **Observability** — every skill invocation is wrapped in a traced span with
  structured logging and metric recording.
* **Eventing** — agents subscribe to their watched events and emit
  completion/failure events through the shared event bus.
* **Failure tracking** — consecutive failures are counted; once the configured
  threshold is exceeded the agent yields control back to the TeamLeader.
* **Dependency injection** — the LLM client, MCP client and vector store are
  injectable to keep agents testable and decoupled from concrete backends.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, TypeVar, runtime_checkable

from devflow.event_bus import publish, subscribe
from devflow.exceptions import AgentError, BoundaryViolationError, MCPError
from devflow.models.trace import SpanStatus
from devflow.observability import logger, metrics, tracer

#: Type alias for an async event handler callable.
EventHandler = Callable[[dict[str, Any]], Awaitable[None]]
OutputT = TypeVar("OutputT")


class AgentState(str, Enum):
    """Lifecycle state of a single agent instance."""

    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class AgentIdentity:
    """The intentional identity of an agent.

    Identity is *first-class config*: the same underlying LLM behaves very
    differently under different role framing and sampling temperatures, so each
    field is treated as a deliberate configuration value rather than an
    incidental label (see ``config/agents.yaml``).
    """

    role: str
    description: str
    model: str
    temperature: float = 0.3
    system_prompt_ref: str | None = None
    #: Ordered fallback chain for the underlying model (e.g. codex -> glm-4).
    model_fallback: tuple[str, ...] = ()


@dataclass
class AgentConfig:
    """Runtime configuration for an agent.

    Defaults mirror the ``defaults`` section of ``config/agents.yaml`` so that
    an agent behaves correctly even when the settings loader is unavailable.
    """

    name: str
    identity: AgentIdentity
    capabilities: list[str] = field(default_factory=list)
    boundaries: list[str] = field(default_factory=list)
    watches: list[str] = field(default_factory=list)
    max_consecutive_failures: int = 3
    timeout_seconds: int = 600
    max_tokens_per_invocation: int = 32000


@runtime_checkable
class MCPClient(Protocol):
    """Minimal contract for an MCP (Model Context Protocol) client."""

    async def call_tool(
        self, server: str, tool: str, arguments: dict[str, Any]
    ) -> Any:
        """Invoke ``tool`` on ``server`` with ``arguments`` and return the result."""
        ...


@runtime_checkable
class LLMClient(Protocol):
    """Small completion interface shared by real and deterministic clients."""

    async def complete(
        self,
        prompt: str,
        *,
        model: str | None = None,
        temperature: float = 0.2,
        system: str | None = None,
    ) -> str: ...

    async def complete_structured(
        self,
        *,
        prompt: str,
        response_model: type[Any],
        model: str | None = None,
        temperature: float = 0.2,
        system: str | None = None,
    ) -> Any: ...


@runtime_checkable
class VectorStore(Protocol):
    """Minimal contract for a vector store backing RAG / deduplication."""

    async def query(
        self,
        collection: str,
        query: str,
        n_results: int = 5,
    ) -> list[dict[str, Any]]:
        """Return the ``n_results`` nearest neighbours of ``query`` in ``collection``."""
        ...


def _utcnow() -> datetime:
    """Return the current UTC timestamp (isolated for testability)."""
    return datetime.now(timezone.utc)


class BaseAgent:
    """Abstract base class for every DevFlow agent.

    Subclasses implement :meth:`run` with their domain logic and optionally
    override :meth:`handle_event` to react to subscribed events. All cross
    cutting concerns — tracing, eventing, boundary enforcement and failure
    tracking — are handled here.
    """

    #: Declarative identity mirrored from ``config/agents.yaml``. Subclasses
    #: override this so an agent is self-describing even without the config
    #: loader.
    _IDENTITY: AgentIdentity = AgentIdentity(
        role="Agent",
        description="Unspecified DevFlow agent.",
        model="glm-4",
    )
    #: Capabilities this agent owns (mirrors ``agents.yaml``).
    _CAPABILITIES: tuple[str, ...] = ()
    #: Human-readable boundary descriptions (mirrors ``agents.yaml``).
    _BOUNDARIES: tuple[str, ...] = ()
    #: Events this agent subscribes to (mirrors ``agents.yaml``).
    _WATCHES: tuple[str, ...] = ()
    #: Action tokens explicitly forbidden by this agent's boundaries. Each
    #: forbidden action maps to the boundary description it would violate.
    _FORBIDDEN_ACTIONS: dict[str, str] = {}

    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        mcp_client: MCPClient | None = None,
        vector_store: VectorStore | None = None,
        config: AgentConfig | None = None,
    ) -> None:
        self._config = config or self._build_default_config()
        self._state: AgentState = AgentState.IDLE
        self._llm = llm_client or _resolve_llm_client()
        self._mcp: MCPClient | None = mcp_client
        self._vector_store: VectorStore | None = vector_store
        self._consecutive_failures: int = 0
        self._event_handlers: dict[str, EventHandler] = {}

    # ------------------------------------------------------------------ #
    # Public properties
    # ------------------------------------------------------------------ #
    @property
    def name(self) -> str:
        """Unique name of this agent."""
        return self._config.name

    @property
    def identity(self) -> AgentIdentity:
        """The agent's intentional identity (role, model, temperature)."""
        return self._config.identity

    @property
    def state(self) -> AgentState:
        """Current lifecycle state of the agent."""
        return self._state

    @property
    def capabilities(self) -> list[str]:
        """Capabilities this agent is permitted to exercise."""
        return list(self._config.capabilities)

    @property
    def boundaries(self) -> list[str]:
        """Hard boundaries enforced by the runtime."""
        return list(self._config.boundaries)

    @property
    def watches(self) -> list[str]:
        """Events this agent subscribes to via the event bus."""
        return list(self._config.watches)

    @property
    def max_consecutive_failures(self) -> int:
        """Soft limit on consecutive failures before yielding to TeamLeader."""
        return self._config.max_consecutive_failures

    @property
    def llm(self) -> LLMClient:
        """The LLM client used for reasoning.

        Raises:
            AgentError: if no LLM client was provided and none could be
                resolved from the runtime.
        """
        if self._llm is None:
            raise AgentError(
                f"Agent '{self.name}' has no LLM client configured."
            )
        return self._llm

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def run(self, input_data: Any) -> Any:
        """Execute the agent's domain logic.

        Concrete subclasses must implement this method. It is invoked by
        :meth:`execute`, which wraps it with state, tracing and failure
        handling.
        """
        raise NotImplementedError

    async def execute(self, input_data: Any) -> Any:
        """Public entry point wrapping :meth:`run` with lifecycle management.

        This sets the agent state, traces the invocation, records metrics,
        handles failures and emits ``agent.completed`` / ``agent.failed``
        events. Callers should always use this method rather than ``run``
        directly.
        """
        self._state = AgentState.RUNNING
        logger.info(
            "agent.start",
            agent=self.name,
            role=self.identity.role,
            model=self.identity.model,
        )
        try:
            async with self._trace_span("run"):
                result = await self.run(input_data)
        except Exception as exc:  # noqa: BLE001 — agent boundary
            await self._record_failure(exc)
            self._state = AgentState.FAILED
            await self._emit_event(
                "agent.failed",
                {
                    "agent": self.name,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "consecutive_failures": self._consecutive_failures,
                    "timestamp": _utcnow().isoformat(),
                },
            )
            raise
        else:
            self._record_success()
            self._state = AgentState.COMPLETED
            completion_payload: dict[str, Any] = {
                "agent": self.name,
                "timestamp": _utcnow().isoformat(),
            }
            issue_id = _extract_issue_id(input_data)
            if issue_id is not None:
                completion_payload["issue_id"] = issue_id
            await self._emit_event(
                "agent.completed",
                completion_payload,
            )
            return result

    # ------------------------------------------------------------------ #
    # Event handling
    # ------------------------------------------------------------------ #
    def subscribe_events(self) -> None:
        """Register :meth:`handle_event` for every event in :attr:`watches`."""
        for event_type in self.watches:
            subscribe(event_type, self._make_event_handler(event_type))

    def _make_event_handler(self, event_type: str) -> EventHandler:
        """Create an async handler bound to a specific event type."""

        async def _handler(payload: dict[str, Any]) -> None:
            await self.handle_event(event_type, payload)

        return _handler

    async def handle_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """React to a subscribed event.

        The default implementation dispatches to handlers registered via
        :meth:`register_event_handler`. Subclasses may override this for more
        control. Errors are caught and recorded so a failing handler never
        tears down the event bus.
        """
        handler = self._event_handlers.get(event_type)
        if handler is None:
            logger.debug("agent.event.unhandled", agent=self.name, event_type=event_type)
            return
        try:
            await handler(payload)
        except Exception as exc:  # noqa: BLE001 — handler boundary
            logger.error(
                "agent.event.handler_failed",
                agent=self.name,
                event_type=event_type,
                error=str(exc),
            )
            await self._record_failure(exc)

    def register_event_handler(self, event_type: str, handler: EventHandler) -> None:
        """Register a handler for ``event_type`` dispatched by :meth:`handle_event`."""
        self._event_handlers[event_type] = handler

    async def _emit_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """Publish an event and log it for auditability."""
        enriched = {"agent": self.name, **payload}
        logger.info("agent.emit_event", agent=self.name, event_type=event_type)
        await publish(event_type, enriched)

    # ------------------------------------------------------------------ #
    # Boundary enforcement
    # ------------------------------------------------------------------ #
    def _check_boundary(self, action: str) -> bool:
        """Return ``True`` if ``action`` is permitted within the agent's boundaries.

        Forbidden actions (derived from the agent's declarative boundaries)
        are audited as ``boundary.violation`` events and rejected. Unknown
        actions are allowed — an agent is free to do anything its boundaries
        do not explicitly forbid.
        """
        violation = self._FORBIDDEN_ACTIONS.get(action)
        if violation is None:
            return True
        logger.warning(
            "boundary.violation",
            agent=self.name,
            action=action,
            boundary=violation,
        )
        self._safe_metric(
            lambda: metrics.counter("devflow_boundary_violations_total").inc(
                labels={"agent": self.name, "action": action}
            )
        )
        # Audit via a fire-and-forget event is intentionally synchronous-log
        # here; the event is published by the caller that observes False.
        return False

    def _enforce_boundary(self, action: str) -> None:
        """Like :meth:`_check_boundary` but raise on violation.

        Use this for hard security checks where proceeding would be unsafe.
        """
        if not self._check_boundary(action):
            raise BoundaryViolationError(
                f"Agent '{self.name}' is not permitted to perform '{action}'."
            )

    # ------------------------------------------------------------------ #
    # Observability
    # ------------------------------------------------------------------ #
    @contextlib.asynccontextmanager
    async def _trace_span(
        self, skill_name: str, **attributes: Any
    ) -> AsyncIterator[None]:
        """Trace a skill invocation with structured logging and metrics.

        Wraps the body in an OpenTelemetry span (when a tracer is available),
        records duration and outcome, and emits a metric. Observability never
        blocks the critical path: telemetry failures are swallowed.
        """
        span_name = f"{self.name}.{skill_name}"
        attrs = {
            "devflow.agent.name": self.name,
            "devflow.skill.name": skill_name,
            **attributes,
        }
        start = time.perf_counter()
        status = SpanStatus.SUCCESS
        span_cm = self._safe_start_span(span_name)
        try:
            with span_cm as span:
                self._set_span_attributes(span, attrs)
                yield
        except BaseException:
            status = SpanStatus.FAILURE
            raise
        finally:
            duration_ms = int((time.perf_counter() - start) * 1000)
            self._safe_metric(
                lambda: metrics.histogram("devflow_agent_duration_seconds").observe(
                    duration_ms / 1000, labels={"agent": self.name}
                )
            )
            logger.debug(
                "trace.span.complete",
                agent=self.name,
                skill=skill_name,
                duration_ms=duration_ms,
                status=status.value,
            )

    def _safe_start_span(self, span_name: str) -> Any:
        """Return a no-op context manager if the tracer is unavailable."""
        try:
            return tracer.start_as_current_span(span_name)
        except Exception:  # noqa: BLE001 — observability must not break flow
            return contextlib.nullcontext()

    @staticmethod
    def _set_span_attributes(span: Any, attrs: dict[str, Any]) -> None:
        """Best-effort attribute population on a trace span."""
        for key, value in attrs.items():
            with contextlib.suppress(Exception):
                span.set_attribute(key, value)

    @staticmethod
    def _safe_metric(fn: Callable[[], Any]) -> None:
        """Invoke a metric call, swallowing telemetry errors."""
        with contextlib.suppress(Exception):
            fn()

    # ------------------------------------------------------------------ #
    # Output validation
    # ------------------------------------------------------------------ #
    def _validate_output(
        self, result: Any, expected_type: type[OutputT]
    ) -> OutputT:
        """Validate that ``result`` is an instance of ``expected_type``.

        Returns the validated result on success; raises :class:`AgentError`
        otherwise. Used by subclasses to enforce the skill output contract.
        """
        if not isinstance(result, expected_type):
            raise AgentError(
                f"Agent '{self.name}' produced an invalid output: "
                f"expected {expected_type.__name__}, got {type(result).__name__}."
            )
        return result

    # ------------------------------------------------------------------ #
    # Failure tracking
    # ------------------------------------------------------------------ #
    def _record_success(self) -> None:
        """Reset the consecutive failure counter after a successful invocation."""
        if self._consecutive_failures:
            logger.info(
                "agent.failures_reset",
                agent=self.name,
                previous_failures=self._consecutive_failures,
            )
        self._consecutive_failures = 0

    async def _record_failure(self, error: BaseException) -> None:
        """Record a failure, escalating to TeamLeader once the threshold is exceeded."""
        self._consecutive_failures += 1
        logger.warning(
            "agent.failure",
            agent=self.name,
            error=str(error),
            error_type=type(error).__name__,
            consecutive_failures=self._consecutive_failures,
            max=self.max_consecutive_failures,
        )
        self._safe_metric(
            lambda: metrics.counter("devflow_agent_invocations_total").inc(
                labels={"agent": self.name, "result": "failure"}
            )
        )
        if self._consecutive_failures >= self.max_consecutive_failures:
            await self._yield_to_leader(error)

    async def _yield_to_leader(self, error: BaseException) -> None:
        """Yield control to the TeamLeader after exhausting failure retries.

        Emits an ``agent.yield_to_leader`` event carrying enough context for the
        TeamLeader to re-plan, re-assign or escalate.
        """
        self._state = AgentState.WAITING
        logger.error(
            "agent.yield_to_leader",
            agent=self.name,
            error=str(error),
            consecutive_failures=self._consecutive_failures,
        )
        await self._emit_event(
            "agent.yield_to_leader",
            {
                "agent": self.name,
                "reason": "max_consecutive_failures_exceeded",
                "error": str(error),
                "error_type": type(error).__name__,
                "consecutive_failures": self._consecutive_failures,
                "timestamp": _utcnow().isoformat(),
            },
        )

    # ------------------------------------------------------------------ #
    # External service helpers (MCP / vector store)
    # ------------------------------------------------------------------ #
    async def _call_mcp(
        self, server: str, tool: str, arguments: dict[str, Any]
    ) -> Any:
        """Invoke an MCP tool, failing closed if no client is wired.

        Per ``config/mcp_servers.yaml`` the client policy is
        ``on_server_unavailable: fail_closed`` — safety over availability for
        write operations — so a missing client raises rather than silently
        no-ops.
        """
        if self._mcp is None:
            raise MCPError(
                f"Agent '{self.name}' cannot call MCP '{server}:{tool}': "
                "no MCP client is configured."
            )
        self._safe_metric(
            lambda: metrics.counter("devflow_mcp_tool_calls_total").inc(
                labels={"server": server, "tool": tool, "status": "invoked"}
            )
        )
        try:
            result = await self._mcp.call_tool(server, tool, arguments)
        except Exception as exc:  # noqa: BLE001 — MCP boundary
            self._safe_metric(
                lambda: metrics.counter("devflow_mcp_tool_calls_total").inc(
                    labels={"server": server, "tool": tool, "status": "error"}
                )
            )
            raise MCPError(
                f"MCP call '{server}:{tool}' failed for '{self.name}': {exc}"
            ) from exc
        self._safe_metric(
            lambda: metrics.counter("devflow_mcp_tool_calls_total").inc(
                labels={"server": server, "tool": tool, "status": "ok"}
            )
        )
        return result

    async def _query_vector_store(
        self, collection: str, query: str, n_results: int = 5
    ) -> list[dict[str, Any]]:
        """Query the vector store, returning an empty list when unavailable.

        For deduplication the configured behaviour on an unavailable store is
        ``proceed_without_dedup`` (see ``skills.yaml``), so a missing store
        degrades gracefully rather than raising.
        """
        if self._vector_store is None:
            logger.warning(
                "vector_store.unavailable",
                agent=self.name,
                collection=collection,
                action="proceed_without_dedup",
            )
            return []
        try:
            return await self._vector_store.query(collection, query, n_results)
        except Exception as exc:  # noqa: BLE001 — degrade gracefully
            logger.warning(
                "vector_store.query_failed",
                agent=self.name,
                collection=collection,
                error=str(exc),
            )
            return []

    # ------------------------------------------------------------------ #
    # Configuration resolution
    # ------------------------------------------------------------------ #
    @classmethod
    def _build_default_config(cls) -> AgentConfig:
        """Build the default config from class-level declarative attributes.

        Attempts to enrich the class-level defaults with values from the
        runtime settings (``get_settings()``) so that ``agents.yaml`` remains
        the single source of truth at runtime; falls back gracefully when the
        settings loader is unavailable.
        """
        defaults = _load_settings_defaults()
        config = AgentConfig(
            name=cls.__name__,
            identity=cls._IDENTITY,
            capabilities=list(cls._CAPABILITIES),
            boundaries=list(cls._BOUNDARIES),
            watches=list(cls._WATCHES),
            max_consecutive_failures=defaults.get(
                "max_consecutive_failures", 3
            ),
            timeout_seconds=defaults.get("timeout_seconds", 600),
            max_tokens_per_invocation=defaults.get(
                "max_tokens_per_invocation", 32000
            ),
        )
        _enrich_config_from_settings(config)
        return config


# ---------------------------------------------------------------------- #
# Module-level helpers for resilient settings / client resolution
# ---------------------------------------------------------------------- #
def _load_settings_defaults() -> dict[str, Any]:
    """Load the ``defaults`` section from runtime settings, if available."""
    try:
        from devflow.config import get_settings

        settings = get_settings()
        defaults = getattr(settings, "defaults", None)
        if isinstance(defaults, dict):
            return defaults
    except Exception:  # noqa: BLE001 — settings optional at import time
        return {}
    return {}


def _enrich_config_from_settings(config: AgentConfig) -> None:
    """Override a config's identity/boundaries from parsed ``agents.yaml``.

    Looks up the agent by name in the runtime settings and, when present,
    copies its declarative fields into ``config``. This keeps ``agents.yaml``
    authoritative at runtime while the class-level defaults remain a fallback.
    """
    try:
        from devflow.config import get_settings

        settings = get_settings()
        agents = getattr(settings, "agents", None)
        if not agents:
            return
        # ``agents`` may be a dict keyed by name or a list of dicts.
        entry: dict[str, Any] | None = None
        if isinstance(agents, dict):
            entry = agents.get(config.name)
        elif isinstance(agents, list):
            for item in agents:
                if isinstance(item, dict) and item.get("name") == config.name:
                    entry = item
                    break
        if not entry:
            return
        identity = entry.get("identity")
        if isinstance(identity, dict):
            fallback = identity.get("model_fallback")
            config.identity = AgentIdentity(
                role=identity.get("role", config.identity.role),
                description=identity.get(
                    "description", config.identity.description
                ),
                model=identity.get("model", config.identity.model),
                temperature=float(
                    identity.get("temperature", config.identity.temperature)
                ),
                system_prompt_ref=identity.get(
                    "system_prompt_ref", config.identity.system_prompt_ref
                ),
                model_fallback=tuple(fallback) if fallback else config.identity.model_fallback,
            )
        if isinstance(entry.get("capabilities"), list):
            config.capabilities = list(entry["capabilities"])
        if isinstance(entry.get("boundaries"), list):
            config.boundaries = list(entry["boundaries"])
        if isinstance(entry.get("watches"), list):
            config.watches = list(entry["watches"])
    except Exception:  # noqa: BLE001 — settings optional at runtime
        return


def _resolve_llm_client() -> LLMClient | None:
    """Resolve the shared LLM client from the runtime, if available."""
    try:
        from devflow.llm_client import get_llm_client

        return get_llm_client()
    except Exception:  # noqa: BLE001 — LLM client optional at construction
        return None


def _extract_issue_id(input_data: Any) -> int | None:
    """Best-effort extraction for event correlation."""

    if isinstance(input_data, dict):
        raw = input_data.get("issue_id")
        if raw is None and isinstance(input_data.get("issue"), dict):
            raw = input_data["issue"].get("issue_number")
        try:
            return int(raw) if raw is not None else None
        except (TypeError, ValueError):
            return None
    raw = getattr(input_data, "issue_number", None)
    return int(raw) if isinstance(raw, int) else None


__all__ = [
    "AgentConfig",
    "AgentIdentity",
    "AgentState",
    "BaseAgent",
    "MCPClient",
    "VectorStore",
]
