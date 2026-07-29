"""Shared fail-closed detection and redaction for secret-shaped text."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from math import log2
from typing import Any

REDACTION_MARKER = "[REDACTED]"

_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?P<label>[A-Z ]*PRIVATE KEY)-----"
    r"[\s\S]*?"
    r"(?:-----END (?P=label)-----|\Z)",
    re.IGNORECASE,
)

_NAMED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "github_classic_token",
        re.compile(r"ghp_[A-Za-z0-9]{30,}", re.IGNORECASE),
    ),
    (
        "github_fine_grained_token",
        re.compile(r"github_pat_[A-Za-z0-9_]{30,}", re.IGNORECASE),
    ),
    (
        "openai_style_key",
        re.compile(
            r"sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,}",
            re.IGNORECASE,
        ),
    ),
    (
        "aws_access_key",
        re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}", re.IGNORECASE),
    ),
    (
        "bearer_token",
        re.compile(r"Bearer[ \t]+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE),
    ),
)

_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?P<prefix>(?P<key_quote>[\"']?)"
    r"(?P<name>[A-Za-z][A-Za-z0-9_.-]{0,63})"
    r"(?P=key_quote)\s*(?:=|:)\s*)"
    r'(?:"(?P<double>[^"\r\n]{1,4096})"'
    r"|'(?P<single>[^'\r\n]{1,4096})'"
    r"|(?P<bare>[^\s,;}\]\r\n]{1,4096}))",
)
_CREDENTIAL_FIELD_SUFFIXES = (
    "api_key",
    "apikey",
    "password",
    "passwd",
    "pwd",
    "access_token",
    "auth_token",
    "refresh_token",
    "token",
    "client_secret",
    "secret",
    "credential",
    "private_key",
)
_SAFE_BARE_PYTHON_CALL = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Za-z_][A-Za-z0-9_]*"
    r"\((?:[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)?\)"
)
_PLACEHOLDER_TERMS = (
    "changeme",
    "dummy",
    "example",
    "placeholder",
    "redacted",
    "sample",
    "your_api_key",
    "your_token",
)


def secret_kinds(value: Any) -> list[str]:
    """Return stable secret categories found recursively, without secret bytes."""

    found: set[str] = set()

    def visit(item: Any) -> None:
        if isinstance(item, str):
            for name, pattern in _NAMED_PATTERNS:
                if pattern.search(item) is not None:
                    found.add(name)
            if any(_is_secret_assignment(match) for match in _credential_matches(item)):
                found.add("named_credential")
            return
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if (
                    isinstance(key, str)
                    and isinstance(nested, str)
                    and _is_credential_field_name(key)
                    and _looks_high_entropy(nested)
                ):
                    found.add("named_credential")
                visit(nested)
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for nested in item:
                visit(nested)

    visit(value)
    return sorted(found)


def contains_secret(value: Any) -> bool:
    """Return whether any supported secret shape occurs recursively."""

    return bool(secret_kinds(value))


def redact_text(value: str) -> tuple[str, bool]:
    """Replace all supported secret shapes, including truncated PEM blocks."""

    sanitized, pem_count = _PEM_PRIVATE_KEY.subn(REDACTION_MARKER, value)
    replaced = bool(pem_count)
    for _name, pattern in _NAMED_PATTERNS:
        sanitized, count = pattern.subn(REDACTION_MARKER, sanitized)
        replaced = replaced or bool(count)
    sanitized, named_replaced = _redact_named_credentials(sanitized)
    replaced = replaced or named_replaced
    return sanitized, replaced or REDACTION_MARKER in value


def _credential_matches(value: str) -> list[re.Match[str]]:
    return list(_CREDENTIAL_ASSIGNMENT.finditer(value))


def _is_secret_assignment(match: re.Match[str]) -> bool:
    credential = match.group("double") or match.group("single") or match.group("bare")
    if match.group("bare") is not None and _SAFE_BARE_PYTHON_CALL.fullmatch(credential) is not None:
        return False
    return _is_credential_field_name(match.group("name")) and _looks_high_entropy(credential)


def _is_credential_field_name(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
    compact = normalized.replace("_", "")
    for suffix in _CREDENTIAL_FIELD_SUFFIXES:
        normalized_suffix = suffix.casefold()
        compact_suffix = normalized_suffix.replace("_", "")
        if (
            normalized == normalized_suffix
            or normalized.endswith(f"_{normalized_suffix}")
            or compact == compact_suffix
            or compact.endswith(compact_suffix)
        ):
            return True
    return False


def _looks_high_entropy(value: str) -> bool:
    candidate = value.strip()
    lowered = candidate.casefold()
    if len(candidate) < 12 or any(character.isspace() for character in candidate):
        return False
    if (
        candidate == REDACTION_MARKER
        or lowered.startswith(("http://", "https://"))
        or any(term in lowered for term in _PLACEHOLDER_TERMS)
        or re.fullmatch(r"(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%)", candidate)
        is not None
    ):
        return False

    distinct = len(set(candidate))
    if distinct < 8:
        return False
    if re.fullmatch(r"[A-Fa-f0-9]{24,}", candidate) is not None:
        return True

    classes = sum(
        (
            any(character.islower() for character in candidate),
            any(character.isupper() for character in candidate),
            any(character.isdigit() for character in candidate),
            any(not character.isalnum() for character in candidate),
        )
    )
    counts = Counter(candidate)
    entropy = -sum(
        (count / len(candidate)) * log2(count / len(candidate)) for count in counts.values()
    )
    return (classes >= 3 and entropy >= 3.2) or (
        len(candidate) >= 20 and classes >= 2 and entropy >= 3.75
    )


def _redact_named_credentials(value: str) -> tuple[str, bool]:
    replaced = False

    def replace(match: re.Match[str]) -> str:
        nonlocal replaced
        if not _is_secret_assignment(match):
            return match.group(0)
        replaced = True
        prefix = match.group("prefix")
        if match.group("double") is not None:
            return f'{prefix}"{REDACTION_MARKER}"'
        if match.group("single") is not None:
            return f"{prefix}'{REDACTION_MARKER}'"
        return f"{prefix}{REDACTION_MARKER}"

    return _CREDENTIAL_ASSIGNMENT.sub(replace, value), replaced


__all__ = [
    "REDACTION_MARKER",
    "contains_secret",
    "redact_text",
    "secret_kinds",
]
