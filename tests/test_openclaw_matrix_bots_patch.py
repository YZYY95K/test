"""Safety checks for the scoped OpenClaw Matrix bot compatibility patch."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "patch_openclaw_matrix_bots.sh"
DOC = ROOT / "docs" / "evidence" / "AGENTTEAMS_BETA_COMPATIBILITY.md"


def test_matrix_patch_is_explicitly_scoped_and_fail_closed() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "set -Eeuo pipefail" in text
    assert '[[ -n "$NAMESPACE" ]] || die "--namespace is required"' in text
    assert '[[ -n "$TEAM" ]] || die "--team is required"' in text
    assert 'agentteams.io/team' in text
    assert 'agentteams.io/runtime' in text
    assert 'RUNTIME_LABEL=openclaw' in text
    assert 'readonly EXPECTED_AGENT_COUNT="6"' in text
    assert "Team must expose exactly {expected_count} status members" in text
    assert "Team must have exactly {expected_count} Ready OpenClaw Agent Pods" in text
    assert "Ready OpenClaw Agent Pods do not exactly cover Team status members" in text
    assert "AGENTTEAMS_WORKER_NAME" not in text
    assert "members.tsv" in text
    assert "pods.tsv" in text
    assert 'get pods' in text and "-o json" not in text.split('get pods', 1)[1].split("python3", 1)[0]


def test_matrix_patch_preserves_communication_boundaries() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert text.count('.channels.matrix.allowBots = "mentions"') == 2
    assert text.count('.channels.matrix.streaming = "off"') == 2
    assert text.count('.channels.matrix.streaming == "off"') == 3
    assert text.count('$matrix.groupPolicy == "allowlist"') == 2
    assert text.count('$matrix.groups["*"].requireMention == true') == 2
    assert text.count(
        "del(.channels.matrix.allowBots, .channels.matrix.streaming)"
    ) == 4
    assert text.count('cmp -s "$before_matrix" "$after_matrix"') == 2
    assert 'groupAllowFrom | type == "array" and length > 0' in text
    assert 'dm.allowFrom | type == "array" and length > 0' in text
    assert 'and . != "*"' in text
    assert "changed concurrently; retry the patch" in text


def test_matrix_patch_does_not_emit_or_embed_secrets() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    forbidden = (
        "set -x",
        "ghp_",
        "password:",
        "accessToken |",
        "AGENTTEAMS_FS_SECRET_KEY",
        "AGENTTEAMS_WORKER_MATRIX_TOKEN",
        "AGENTTEAMS_WORKER_GATEWAY_KEY",
    )
    for marker in forbidden:
        assert marker not in text
    assert 'mc cp "$remote" "$config" >/dev/null' in text
    assert 'No configuration content is copied to the operator host or printed' in text


def test_embedded_programs_have_expected_safe_structure() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    python_programs = re.findall(r"<<'PY'\n(.*?)\nPY", text, re.DOTALL)
    shell_programs = re.findall(r"<<'SH'\n(.*?)\nSH", text, re.DOTALL)

    assert len(python_programs) == 1
    compile(python_programs[0], "<openclaw-target-discovery>", "exec")
    assert len(shell_programs) == 4
    for program in shell_programs:
        assert program.startswith("set -eu\n")
        assert "set -x" not in program


def test_target_discovery_uses_team_runtime_identity_and_ready_pods(tmp_path: Path) -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    program = re.findall(r"<<'PY'\n(.*?)\nPY", text, re.DOTALL)[0]
    members = tmp_path / "members.tsv"
    pods = tmp_path / "pods.tsv"
    targets = tmp_path / "targets.tsv"
    members.write_text(
        "leader-cr\tleader-runtime\n"
        "worker-a\tworker-a-runtime\n"
        "worker-b\tworker-b-runtime\n"
        "worker-c\tworker-c-runtime\n"
        "worker-d\tworker-d-runtime\n"
        "worker-e\tworker-e-runtime\n",
        encoding="utf-8",
    )
    pods.write_text(
        "pod-a\tworker-a\t\tRunning\tTrue\n"
        "pod-leader\tleader-cr\t\tRunning\tTrue\n"
        "pod-b\tworker-b\t\tRunning\tTrue\n"
        "pod-c\tworker-c\t\tRunning\tTrue\n"
        "pod-d\tworker-d\t\tRunning\tTrue\n"
        "pod-e\tworker-e\t\tRunning\tTrue\n",
        encoding="utf-8",
    )

    subprocess.run(
        [sys.executable, "-", str(members), str(pods), str(targets), "6"],
        input=program,
        text=True,
        check=True,
    )

    assert targets.read_text(encoding="utf-8") == (
        "leader-runtime\tpod-leader\tworker\n"
        "worker-a-runtime\tpod-a\tworker\n"
        "worker-b-runtime\tpod-b\tworker\n"
        "worker-c-runtime\tpod-c\tworker\n"
        "worker-d-runtime\tpod-d\tworker\n"
        "worker-e-runtime\tpod-e\tworker\n"
    )


def test_target_discovery_rejects_incomplete_six_agent_team(tmp_path: Path) -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    program = re.findall(r"<<'PY'\n(.*?)\nPY", text, re.DOTALL)[0]
    members = tmp_path / "members.tsv"
    pods = tmp_path / "pods.tsv"
    targets = tmp_path / "targets.tsv"
    members.write_text(
        "leader\tleader-runtime\n"
        "worker-a\tworker-a-runtime\n"
        "worker-b\tworker-b-runtime\n"
        "worker-c\tworker-c-runtime\n"
        "worker-d\tworker-d-runtime\n",
        encoding="utf-8",
    )
    pods.write_text("", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-", str(members), str(pods), str(targets), "6"],
        input=program,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "exactly 6 status members; found 5" in result.stderr


def test_compatibility_document_explains_lifecycle_and_security() -> None:
    text = DOC.read_text(encoding="utf-8")

    assert "patch_openclaw_matrix_bots.sh" in text
    assert "mention-gated Agent-to-Agent delivery" in text
    assert '`streaming: "off"` is a delivery requirement' in text
    assert "Matrix `m.replace` edits" in text
    assert "Reapply it after a Team spec update" in text
    assert "optimistic concurrency" in text
