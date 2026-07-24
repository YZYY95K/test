"""Validated YAML configuration loader with environment expansion."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

import yaml
from dotenv import load_dotenv

from devflow.exceptions import ConfigError

_ENV_PATTERN = re.compile(
    r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::-(?P<default>[^}]*))?\}"
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_PATTERN.sub(
            lambda match: os.getenv(
                match.group("name"),
                match.group("default") if match.group("default") is not None else "",
            ),
            value,
        )
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    return value


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        parsed = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Unable to load configuration {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ConfigError(f"Configuration root must be a mapping: {path}")
    return cast(dict[str, Any], _expand_env(parsed))


@dataclass
class Settings:
    """Combined runtime settings used by the agent base class."""

    root: Path
    defaults: dict[str, Any] = field(default_factory=dict)
    agents: list[dict[str, Any]] = field(default_factory=list)
    skills: dict[str, Any] = field(default_factory=dict)
    security: dict[str, Any] = field(default_factory=dict)
    mcp_servers: dict[str, Any] = field(default_factory=dict)
    observability: dict[str, Any] = field(default_factory=dict)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    root = _project_root()
    load_dotenv(root / ".env")
    config_dir = root / "config"
    agents_config = load_yaml(config_dir / "agents.yaml")
    return Settings(
        root=root,
        defaults=agents_config.get("defaults", {}),
        agents=agents_config.get("agents", []),
        skills=load_yaml(config_dir / "skills.yaml"),
        security=load_yaml(config_dir / "security.yaml"),
        mcp_servers=load_yaml(config_dir / "mcp_servers.yaml"),
        observability=load_yaml(config_dir / "observability.yaml"),
    )
