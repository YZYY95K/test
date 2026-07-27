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
    # These are explicit orchestration ingress artifacts, not hidden outputs
    # from another domain Skill. Every other input must be produced by the
    # declared Skill graph.
    external_inputs = {"IssueIntake", "SkillInvocation"}

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
        if contract.input.type not in produced | external_inputs:
            violations.append(
                f"{contract.name}: no Skill produces input {contract.input.type}"
            )
    return violations


def validate_mcp_alignment(
    catalog: dict[str, SkillContract], config_path: Path
) -> list[str]:
    """Require exact agreement between Skill tool contracts and MCP grants."""

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return [f"unable to load MCP policy: {exc}"]
    granted: dict[str, set[str]] = {name: set() for name in catalog}
    grant_agents: dict[tuple[str, str], set[str]] = {}
    servers = raw.get("servers", {})
    if not isinstance(servers, dict):
        return ["MCP policy servers must be a mapping"]
    for server_name, server in servers.items():
        if not isinstance(server, dict) or not server.get("enabled", False):
            continue
        for tool in server.get("tools", []):
            if not isinstance(tool, dict):
                continue
            identifier = f"{server_name}:{tool.get('name', '')}"
            agents = {str(value) for value in tool.get("allowed_agents", [])}
            for skill in tool.get("allowed_skills", []):
                skill_name = str(skill)
                if skill_name in granted:
                    granted[skill_name].add(identifier)
                    grant_agents[(skill_name, identifier)] = agents

    violations: list[str] = []
    for name, contract in catalog.items():
        expected = set(contract.mcp_tools)
        missing = expected - granted[name]
        extra = granted[name] - expected
        if missing:
            violations.append(f"{name}: MCP tools missing grants: {sorted(missing)}")
        if extra:
            violations.append(f"{name}: undeclared MCP grants: {sorted(extra)}")
        for identifier in expected & granted[name]:
            if contract.owner not in grant_agents[(name, identifier)]:
                violations.append(
                    f"{name}: owner {contract.owner} cannot call {identifier}"
                )
    return violations


def validate_agent_alignment(
    catalog: dict[str, SkillContract], config_path: Path
) -> list[str]:
    """Require every distributable Skill to have one matching configured owner."""

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return [f"unable to load Agent policy: {exc}"]
    agents = raw.get("agents")
    if not isinstance(agents, list):
        return ["Agent policy agents must be a list"]
    claimed_by: dict[str, list[str]] = {}
    known_agents: set[str] = set()
    for item in agents:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        agent = str(item["name"])
        known_agents.add(agent)
        for skill in item.get("depends_on_skills", []):
            claimed_by.setdefault(str(skill), []).append(agent)

    violations: list[str] = []
    for name, contract in catalog.items():
        claimants = claimed_by.get(name, [])
        if claimants != [contract.owner]:
            violations.append(
                f"{name}: configured owners {claimants} do not equal {contract.owner}"
            )
        if contract.owner not in known_agents:
            violations.append(f"{name}: owner {contract.owner} is not a configured Agent")
    for name, claimants in claimed_by.items():
        if name not in catalog:
            violations.append(f"unknown configured Skill {name}: {claimants}")
    return violations


__all__ = [
    "load_catalog",
    "load_contract",
    "validate_agent_alignment",
    "validate_collaboration",
    "validate_mcp_alignment",
]
