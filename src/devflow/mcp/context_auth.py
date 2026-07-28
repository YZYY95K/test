"""Authentication for Agent/Skill context crossing an internal MCP transport."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Protocol

from devflow.mcp.contracts import MCPCallContext


class ContextSigner(Protocol):
    """Sign a trusted runtime context before it crosses a transport."""

    def sign(self, context: MCPCallContext) -> MCPCallContext: ...


class HMACContextAuthority:
    """Sign and verify internal MCP context with a server-held shared key."""

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 32:
            raise ValueError("MCP context signing key must contain at least 32 bytes")
        self._signing_key = signing_key

    def sign(self, context: MCPCallContext) -> MCPCallContext:
        unsigned = context.model_copy(update={"context_signature": None})
        return unsigned.model_copy(update={"context_signature": self._digest(unsigned)})

    def verify(self, context: MCPCallContext) -> bool:
        if context.context_signature is None:
            return False
        unsigned = context.model_copy(update={"context_signature": None})
        return hmac.compare_digest(context.context_signature, self._digest(unsigned))

    def _digest(self, context: MCPCallContext) -> str:
        serialized = json.dumps(
            context.model_dump(exclude={"context_signature"}),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=_json_default,
        )
        return hmac.new(
            self._signing_key,
            serialized.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    raise TypeError(f"unsupported MCP context field type: {type(value).__name__}")


__all__ = ["ContextSigner", "HMACContextAuthority"]
