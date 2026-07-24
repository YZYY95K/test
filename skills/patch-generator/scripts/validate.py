"""Validate one Skill input or output artifact; exit nonzero on violations."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in strings(child)]
    return []


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"input", "output"}:
        print("usage: validate.py <input|output> <artifact.json>", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    contract = yaml.safe_load(
        (root / "references" / "contract.yaml").read_text(encoding="utf-8")
    )
    artifact = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    if not isinstance(artifact, dict):
        raise ValueError("artifact root must be an object")
    required = contract[sys.argv[1]]["required_fields"]
    missing = [key for key in required if key not in artifact]
    if missing:
        raise ValueError(f"missing required fields: {', '.join(missing)}")
    if any(SECRET.search(text) for text in strings(artifact)):
        raise ValueError("artifact contains secret-shaped content")
    for key in ("file", "file_path", "path"):
        for value in _find_values(artifact, key):
            path = PurePosixPath(str(value).replace("\\", "/"))
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe repository path: {value}")
    print(json.dumps({"valid": True, "skill": contract["name"], "mode": sys.argv[1]}))
    return 0


def _find_values(value: Any, target: str) -> list[Any]:
    if isinstance(value, dict):
        found = [value[target]] if target in value else []
        return found + [
            item for child in value.values() for item in _find_values(child, target)
        ]
    if isinstance(value, list):
        return [item for child in value for item in _find_values(child, target)]
    return []


if __name__ == "__main__":
    raise SystemExit(main())
