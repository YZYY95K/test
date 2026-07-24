"""Domain exceptions used across DevFlow."""


class DevFlowError(Exception):
    """Base class for all expected DevFlow failures."""


class ConfigError(DevFlowError):
    """Raised when configuration is missing or invalid."""


class AgentError(DevFlowError):
    """Raised when an agent cannot complete its task."""


class BoundaryViolationError(AgentError):
    """Raised when an agent attempts a forbidden action."""


class SkillError(DevFlowError):
    """Raised when a reusable skill fails."""


class LLMError(DevFlowError):
    """Raised when an LLM request or response fails."""


class MCPError(DevFlowError):
    """Raised when an MCP tool call fails."""


class MCPAuthorizationError(MCPError):
    """Raised when an MCP call violates the declared capability boundary."""
