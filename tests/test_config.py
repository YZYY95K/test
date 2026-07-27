"""Configuration completeness tests."""

import json
from pathlib import Path

import yaml

from devflow.config import get_settings

ROOT = Path(__file__).resolve().parents[1]


def test_config_declares_full_team_and_skills() -> None:
    settings = get_settings()

    assert {agent["name"] for agent in settings.agents} == {
        "TeamLeader",
        "TriageAgent",
        "LocatorAgent",
        "CoderAgent",
        "TesterAgent",
        "ReviewerAgent",
    }
    assert len(settings.skills["skills"]) == 7
    assert {"github", "cicd"} <= set(settings.mcp_servers["servers"])


def test_deployment_model_is_consistent_across_runtime_manifests() -> None:
    settings = get_settings()
    configured_models = {agent["identity"]["model"] for agent in settings.agents}
    team = yaml.safe_load((ROOT / "agentteams" / "team.yaml").read_text(encoding="utf-8"))
    worker_manifest = json.loads(
        (ROOT / "agentteams" / "worker-package" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    team_models = {team["spec"]["leader"]["model"]}
    team_models.update(worker["model"] for worker in team["spec"]["workers"])

    assert configured_models == {"glm-5.2"}
    locator = next(agent for agent in settings.agents if agent["name"] == "LocatorAgent")
    assert locator["resources"]["vector_store"]["embedding_model"] == "embedding-3"
    assert team_models == {"glm-5.2"}
    assert worker_manifest["worker"]["model"] == "glm-5.2"
