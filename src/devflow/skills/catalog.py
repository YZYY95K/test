"""Discovery and validation for distributable Skill packages."""

from __future__ import annotations

from pathlib import Path

import yaml

from devflow.exceptions import ConfigError
from devflow.skills.contracts import SkillContract


def load_contract(skill_dir: Path) -> SkillContract:
    """Load and validate one Skill's machine-readable contract."""

    path = skill_dir / "references" / "contract.yaml"
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return SkillContract.model_validate(raw)
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise ConfigError(f"Invalid Skill contract {path}: {exc}") from exc


def load_catalog(skills_dir: Path) -> dict[str, SkillContract]:
    """Load all Skills and reject duplicate names."""

    catalog: dict[str, SkillContract] = {}
    for skill_dir in sorted(path for path in skills_dir.iterdir() if path.is_dir()):
        if not (skill_dir / "SKILL.md").exists():
            continue
        contract = load_contract(skill_dir)
        if contract.name in catalog:
            raise ConfigError(f"Duplicate Skill contract: {contract.name}")
        if contract.name != skill_dir.name:
            raise ConfigError(
                f"Skill directory {skill_dir.name} does not match {contract.name}"
            )
        catalog[contract.name] = contract
    return catalog


def validate_collaboration(catalog: dict[str, SkillContract]) -> list[str]:
    """Return cross-Skill graph violations."""

    violations: list[str] = []
    owners = {contract.owner for contract in catalog.values()}
    allowed_consumers = owners | {"TeamLeader", "HumanReviewer"}
    produced = {contract.output.type for contract in catalog.values()}

    for contract in catalog.values():
        for handoff in contract.handoffs:
            if handoff.consumer not in allowed_consumers:
                violations.append(
                    f"{contract.name}: unknown consumer {handoff.consumer}"
                )
            if (
                handoff.on == "success"
                and handoff.consumer != "TeamLeader"
                and handoff.artifact_type != contract.output.type
            ):
                violations.append(
                    f"{contract.name}: success handoff artifact must equal output type"
                )
        if contract.input.type not in produced and contract.name != "issue-classifier":
            violations.append(
                f"{contract.name}: no Skill produces input {contract.input.type}"
            )
    return violations


__all__ = ["load_catalog", "load_contract", "validate_collaboration"]
