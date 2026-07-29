"""Security services that remain outside Agent and prompt boundaries."""

from devflow.security.credentials import (
    CapabilityHandle,
    CredentialBroker,
    CredentialEnvironmentProxy,
)
from devflow.security.secrets import contains_secret, redact_text, secret_kinds

__all__ = [
    "CapabilityHandle",
    "CredentialBroker",
    "CredentialEnvironmentProxy",
    "contains_secret",
    "redact_text",
    "secret_kinds",
]
