"""Static safety checks for the AgentTeams beta compatibility asset."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "patch_agentteams_beta.sh"


def _python_heredocs() -> list[str]:
    return re.findall(r"<<'PY'\n(.*?)\nPY", SCRIPT.read_text(encoding="utf-8"), re.DOTALL)


def _run_embedded_python(program: str, source: Path, destination: Path) -> object:
    subprocess.run(
        [sys.executable, "-", str(source), str(destination)],
        input=program,
        text=True,
        check=True,
    )
    return json.loads(destination.read_text(encoding="utf-8"))


def test_beta_compatibility_script_is_fail_closed_and_credential_free() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "set -Eeuo pipefail" in text
    assert "set -x" not in text
    assert "ghp_" not in text
    assert "password:" not in text.lower()
    assert "AGENTTEAMS_FS_SECRET_KEY" in text
    assert '"$AGENTTEAMS_FS_SECRET_KEY"' in text
    assert "mc alias set" in text


def test_beta_compatibility_script_covers_required_cluster_repairs() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    required_markers = (
        "teams.agentteams.io",
        "leader/properties/runtime",
        "tlsroutes.gateway.networking.k8s.io",
        'version.get("name") == "v1alpha2"',
        "gateway.networking.x-k8s.io",
        "xlistenersets",
        "xbackendtrafficpolicies",
        "/usr/local/bin/hiclaw-controller",
        "AGENTTEAMS_STORAGE_PREFIX%%/*",
        "rollout status",
        "auth can-i",
    )
    for marker in required_markers:
        assert marker in text


def test_beta_compatibility_rbac_is_read_only() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert 'verbs: ["get", "list", "watch"]' in text
    for mutating_verb in ("create", "update", "patch", "delete", "impersonate"):
        assert f'"{mutating_verb}"' not in text.split("rules:", 1)[1].split("---", 1)[0]


def test_embedded_python_is_valid_and_team_schema_patch_is_idempotent(
    tmp_path: Path,
) -> None:
    programs = _python_heredocs()
    assert len(programs) == 5
    for program in programs:
        compile(program, "<agentteams-beta-heredoc>", "exec")

    runtime = {"type": "string", "enum": ["openclaw", "copaw", "hermes"]}
    crd: dict[str, Any] = {
        "spec": {
            "versions": [
                {
                    "name": "v1beta1",
                    "served": True,
                    "schema": {
                        "openAPIV3Schema": {
                            "properties": {
                                "spec": {
                                    "properties": {
                                        "leader": {"properties": {}},
                                        "workers": {
                                            "items": {"properties": {"runtime": runtime}}
                                        },
                                    }
                                }
                            }
                        }
                    },
                }
            ]
        }
    }
    source = tmp_path / "team.json"
    destination = tmp_path / "patch.json"
    source.write_text(json.dumps(crd), encoding="utf-8")

    patch = _run_embedded_python(programs[0], source, destination)
    assert patch == [
        {
            "op": "add",
            "path": (
                "/spec/versions/0/schema/openAPIV3Schema/properties/spec/"
                "properties/leader/properties/runtime"
            ),
            "value": runtime,
        }
    ]

    crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"][
        "properties"
    ]["leader"]["properties"]["runtime"] = runtime
    source.write_text(json.dumps(crd), encoding="utf-8")
    assert _run_embedded_python(programs[0], source, destination) == []


def test_tlsroute_and_controller_patch_generation(tmp_path: Path) -> None:
    programs = _python_heredocs()
    source = tmp_path / "source.json"
    destination = tmp_path / "patch.json"

    source.write_text(
        json.dumps(
            {
                "spec": {
                    "versions": [
                        {"name": "v1", "served": True},
                        {"name": "v1alpha2", "served": False},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    assert _run_embedded_python(programs[1], source, destination) == [
        {"op": "replace", "path": "/spec/versions/1/served", "value": True}
    ]

    source.write_text(
        json.dumps(
            {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {"name": "controller", "image": "example/controller:beta"}
                            ]
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    controller_patch = cast(
        dict[str, Any],
        _run_embedded_python(programs[2], source, destination),
    )
    container = controller_patch["spec"]["template"]["spec"]["containers"][0]
    assert container["command"] == ["/bin/sh", "-ec"]
    assert "exec /usr/local/bin/hiclaw-controller" in container["args"][0]
    assert "AGENTTEAMS_FS_SECRET_KEY" in container["args"][0]
