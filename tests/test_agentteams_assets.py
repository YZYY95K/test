"""Checks for competition-critical AgentTeams deployment assets."""

from __future__ import annotations

from pathlib import Path

import yaml

from devflow.skills.catalog import load_catalog, validate_collaboration

ROOT = Path(__file__).resolve().parents[1]


def test_team_manifest_maps_all_domain_workers() -> None:
    resource = yaml.safe_load(
        (ROOT / "agentteams" / "team.yaml").read_text(encoding="utf-8")
    )

    assert resource["apiVersion"] == "agentteams.io/v1beta1"
    assert resource["kind"] == "Team"
    assert resource["metadata"]["name"] == "devflow-swe"
    assert resource["spec"]["leader"]["name"] == "devflow-lead"
    assert {worker["name"] for worker in resource["spec"]["workers"]} == {
        "devflow-triage",
        "devflow-locator",
        "devflow-coder",
        "devflow-tester",
        "devflow-reviewer",
    }
    for worker in resource["spec"]["workers"]:
        for server in worker.get("mcpServers", []):
            assert set(server) >= {"name", "url"}


def test_all_declared_skills_are_distributable() -> None:
    configured = yaml.safe_load(
        (ROOT / "config" / "skills.yaml").read_text(encoding="utf-8")
    )
    configured_names = {skill["name"] for skill in configured["skills"]}
    skill_files = {
        path.parent.name: path
        for path in (ROOT / "skills").glob("*/SKILL.md")
    }

    assert configured_names == set(skill_files)
    for name, path in skill_files.items():
        text = path.read_text(encoding="utf-8")
        assert text.startswith("---\n")
        assert f"name: {name}\n" in text
        frontmatter = yaml.safe_load(text.split("---\n", 2)[1])
        assert set(frontmatter) == {"name", "description"}
        assert "Use when" in frontmatter["description"]
        skill_dir = path.parent
        assert (skill_dir / "agents" / "openai.yaml").exists()
        assert (skill_dir / "references" / "contract.yaml").exists()
        assert (skill_dir / "references" / "examples.md").exists()
        assert (skill_dir / "scripts" / "validate.py").exists()


def test_skill_contract_graph_has_no_violations() -> None:
    catalog = load_catalog(ROOT / "skills")

    assert len(catalog) == 6
    assert validate_collaboration(catalog) == []
    assert all(len(contract.forbidden_actions) >= 3 for contract in catalog.values())
    assert all(len(contract.verification) >= 3 for contract in catalog.values())
