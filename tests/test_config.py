"""Configuration completeness tests."""

from devflow.config import get_settings


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
    assert len(settings.skills["skills"]) == 6
    assert {"github", "cicd"} <= set(settings.mcp_servers["servers"])

