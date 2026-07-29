"""Short-lived capability handles for server-side credential resolution."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field

from devflow.exceptions import MCPAuthorizationError

_RESERVED_PROVIDER_ENVIRONMENT = frozenset(
    {
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PATHEXT",
        "PYTHONPATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
)


class CapabilityHandle(BaseModel):
    """Signed authority reference that contains no provider credential."""

    handle_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    agent: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]+$")
    capability: str = Field(pattern=r"^[a-z0-9_.:-]+$")
    expires_at: datetime
    signature: str = Field(pattern=r"^[a-f0-9]{64}$")


class CredentialBroker:
    """Issue scoped handles and resolve secrets only inside trusted adapters."""

    def __init__(
        self,
        signing_key: bytes,
        *,
        agent_capabilities: Mapping[str, set[str]],
        capability_secrets: Mapping[str, str],
        environment: Mapping[str, str] | None = None,
        max_ttl: timedelta = timedelta(hours=1),
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("credential broker key must contain at least 32 bytes")
        self._key = signing_key
        self._agent_capabilities = {
            agent: frozenset(values) for agent, values in agent_capabilities.items()
        }
        self._capability_secrets = dict(capability_secrets)
        self._environment = environment if environment is not None else os.environ
        self._max_ttl = max_ttl

    def issue(
        self,
        *,
        agent: str,
        capability: str,
        ttl: timedelta = timedelta(minutes=15),
    ) -> CapabilityHandle:
        if capability not in self._agent_capabilities.get(agent, frozenset()):
            raise MCPAuthorizationError(
                f"Agent {agent} is not granted credential capability {capability}"
            )
        if ttl <= timedelta(0) or ttl > self._max_ttl:
            raise MCPAuthorizationError("credential handle TTL is outside policy")
        unsigned = {
            "handle_id": uuid.uuid4().hex,
            "agent": agent,
            "capability": capability,
            "expires_at": datetime.now(timezone.utc) + ttl,
        }
        return CapabilityHandle.model_validate({**unsigned, "signature": self._sign(unsigned)})

    def resolve(
        self,
        handle: CapabilityHandle,
        *,
        expected_agent: str,
        expected_capability: str,
    ) -> str:
        """Resolve the provider secret inside a trusted MCP/LLM adapter."""

        unsigned = handle.model_dump(exclude={"signature"})
        if not hmac.compare_digest(handle.signature, self._sign(unsigned)):
            raise MCPAuthorizationError("credential handle signature is invalid")
        if handle.expires_at.tzinfo is None or handle.expires_at <= datetime.now(timezone.utc):
            raise MCPAuthorizationError("credential handle is expired")
        if handle.agent != expected_agent or handle.capability != expected_capability:
            raise MCPAuthorizationError("credential handle scope does not match caller")
        if expected_capability not in self._agent_capabilities.get(expected_agent, frozenset()):
            raise MCPAuthorizationError("credential capability was revoked")
        variable = self._capability_secrets.get(expected_capability)
        if variable is None:
            raise MCPAuthorizationError("credential capability has no provider mapping")
        secret = self._environment.get(variable)
        if not secret:
            raise MCPAuthorizationError("provider credential is unavailable")
        return secret

    def _sign(self, payload: Mapping[str, object]) -> str:
        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            default=lambda value: (
                value.astimezone(timezone.utc).isoformat()
                if isinstance(value, datetime)
                else str(value)
            ),
        )
        return hmac.new(self._key, serialized.encode(), hashlib.sha256).hexdigest()


class CredentialEnvironmentProxy:
    """Resolve one scoped capability directly into a trusted provider env.

    The short-lived handle and provider credential never cross the agent/MCP
    argument boundary.  The returned mapping is intended only for immediate
    use by a server-owned subprocess adapter and must not be serialized.
    """

    def __init__(
        self,
        broker: CredentialBroker,
        *,
        capability: str,
        provider_variable: str,
    ) -> None:
        if re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", provider_variable) is None:
            raise ValueError("provider credential environment name is invalid")
        if provider_variable in _RESERVED_PROVIDER_ENVIRONMENT or provider_variable.startswith(
            "DEVFLOW_"
        ):
            raise ValueError("provider credential cannot replace a bootstrap variable")
        self._broker = broker
        self._capability = capability
        self._provider_variable = provider_variable

    def resolve_for_provider(self, *, agent: str) -> dict[str, str]:
        """Return the one exact provider variable after fresh scope checks."""

        handle = self._broker.issue(
            agent=agent,
            capability=self._capability,
            ttl=timedelta(minutes=1),
        )
        secret = self._broker.resolve(
            handle,
            expected_agent=agent,
            expected_capability=self._capability,
        )
        return {self._provider_variable: secret}


__all__ = ["CapabilityHandle", "CredentialBroker", "CredentialEnvironmentProxy"]
