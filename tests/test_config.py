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
    assert {"github", "devflow-cicd"} <= set(settings.mcp_servers["servers"])


def test_agentteams_and_portable_cicd_profiles_have_distinct_names_and_protocols() -> None:
    canonical = yaml.safe_load(
        (ROOT / "config" / "mcp_servers.yaml").read_text(encoding="utf-8")
    )
    portable = yaml.safe_load(
        (ROOT / "config" / "mcp_servers.portable.yaml").read_text(encoding="utf-8")
    )
    canonical_server = canonical["servers"]["devflow-cicd"]
    portable_server = portable["servers"]["devflow-cicd-portable"]
    canonical_schema = canonical_server["tools"][0]["input_schema"]
    portable_schema = portable_server["tools"][0]["input_schema"]

    assert "devflow-cicd-portable" not in canonical["servers"]
    assert "devflow-cicd" not in portable["servers"]
    assert canonical_server["execution_profile"] == "agentteams-bwrap-tests/v1"
    assert portable_server["execution_profile"] == "portable-process-only/v1"
    assert canonical_server["policy_identity"] != portable_server["policy_identity"]
    assert canonical_schema["required"] == ["taskId", "revision", "workspaceBinding"]
    assert portable_schema["required"] == ["issue_id", "patch"]
    assert "full_suite" not in portable_schema["properties"]


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
