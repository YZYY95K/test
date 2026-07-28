"""Skill-local contract reader with a stdlib-only YAML subset fallback."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_contract(path: Path) -> dict[str, Any]:
    """Load the contract with PyYAML when present, otherwise parse our subset."""
    text = path.read_text(encoding="utf-8")
    try:
        import yaml
    except ModuleNotFoundError:
        contract = _load_contract_subset(text)
    else:
        contract = yaml.safe_load(text)
    return _validate_contract(contract)


def _load_contract_subset(text: str) -> dict[str, Any]:
    name_match = re.search(r"(?m)^name:\s*([^\s#]+)\s*$", text)
    name = name_match.group(1).strip("'\"") if name_match else ""
    return {
        "name": name,
        "input": {"required_fields": _required_fields(text, "input")},
        "output": {"required_fields": _required_fields(text, "output")},
    }


def _required_fields(text: str, section: str) -> list[str]:
    section_match = re.search(
        rf"(?m)^{re.escape(section)}:\s*$\n((?:[ \t]+.*(?:\n|$))*)",
        text,
    )
    if not section_match:
        raise ValueError(f"contract must contain an object {section} section")
    fields_match = re.search(
        r"(?ms)^[ \t]+required_fields:\s*(\[[^\]]*\])",
        section_match.group(1),
    )
    if not fields_match:
        raise ValueError(f"contract {section}.required_fields is missing")
    return _parse_fields(fields_match.group(1))


def _parse_fields(value: str) -> list[str]:
    if not value.startswith("[") or "]" not in value:
        raise ValueError("required_fields must be an inline or folded flow sequence")
    content = value[1 : value.index("]")]
    fields = [item.strip().strip("'\"") for item in content.split(",")]
    fields = [field for field in fields if field]
    if not fields or any(not FIELD.fullmatch(field) for field in fields):
        raise ValueError("required_fields contains an invalid field name")
    return fields


def _validate_contract(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("name"), str):
        raise ValueError("contract must contain a string name")
    for mode in ("input", "output"):
        section = value.get(mode)
        if not isinstance(section, dict):
            raise ValueError(f"contract must contain an object {mode} section")
        fields = section.get("required_fields")
        if not isinstance(fields, list) or not fields:
            raise ValueError(f"contract {mode}.required_fields must be a non-empty list")
        if any(not isinstance(field, str) or not FIELD.fullmatch(field) for field in fields):
            raise ValueError(f"contract {mode}.required_fields contains an invalid field")
    return value
