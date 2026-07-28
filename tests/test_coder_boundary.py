"""Executable blast-radius and secret boundaries for CoderAgent."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from devflow.agents.coder_agent import CoderAgent
from devflow.agents.locator_agent import LocatedContext, RootCause
from devflow.exceptions import AgentError
from devflow.models.issue import IssueData
from devflow.models.patch import ChangeType, FileChange, ImpactAnalysis, Patch, RiskLevel
from devflow.security.secrets import contains_secret, redact_text


def _issue(*, body: str = "A focused bug report.") -> IssueData:
    return IssueData(
        issue_number=42,
        title="Fix the state",
        body=body,
        labels=["bug"],
        author="fixture",
        created_at=datetime.now(timezone.utc),
        repo_owner="example",
        repo_name="repo",
    )


def _located(*, context: str = "src/fix.py: fixed = False") -> LocatedContext:
    return LocatedContext(
        root_cause=RootCause(
            summary="The state remains false.",
            file="src/fix.py",
            start_line=1,
            end_line=1,
            confidence=0.99,
        ),
        affected_files=[],
        context_payload=context,
        related_tests=["tests/test_fix.py"],
        impact_analysis=ImpactAnalysis(
            affected_files=["src/fix.py"],
            affected_modules=["fix"],
            risk_level=RiskLevel.LOW,
            test_files_needed=["tests/test_fix.py"],
        ),
    )


def _patch(
    *,
    path: str = "src/fix.py",
    content: str = "fixed = True\n",
    description: str = "A bounded fix.",
) -> Patch:
    return Patch(
        branch_name="devflow/fix-state",
        changes=[
            FileChange(
                file_path=path,
                change_type=ChangeType.MODIFY,
                original_content="fixed = False\n",
                new_content=content,
                diff=(
                    f"--- a/{path}\n"
                    f"+++ b/{path}\n"
                    "@@ -1 +1 @@\n"
                    "-fixed = False\n"
                    f"+{content}"
                ),
            )
        ],
        commit_message="fix: correct state",
        description=description,
    )


class _PatchLLM:
    def __init__(self, patch: Patch) -> None:
        self.patch = patch
        self.prompts: list[str] = []

    async def complete_structured(self, **kwargs: Any) -> Patch:
        self.prompts.append(str(kwargs["prompt"]))
        return self.patch

    async def complete(self, prompt: str, **_kwargs: Any) -> str:
        self.prompts.append(prompt)
        return ""


def _input(issue: IssueData, located: LocatedContext) -> dict[str, Any]:
    return {
        "issue_id": issue.issue_number,
        "issue": issue.model_dump(mode="json"),
        "tier": "T2",
        "located_context": located.model_dump(mode="json"),
    }


@pytest.mark.asyncio
async def test_coder_redacts_prompt_sources_before_model_call() -> None:
    secret = "gh" + "p_" + "A" * 40
    llm = _PatchLLM(_patch())
    coder = CoderAgent(llm_client=llm)

    await coder.run(
        _input(
            _issue(body=f"Observed credential {secret}"),
            _located(context=f"src/fix.py contains {secret}"),
        )
    )

    assert len(llm.prompts) == 1
    assert secret not in llm.prompts[0]
    assert "[REDACTED]" in llm.prompts[0]


@pytest.mark.asyncio
async def test_coder_blocks_secret_shaped_model_output() -> None:
    secret = "sk-" + "B" * 24
    llm = _PatchLLM(_patch(description=f"do not emit {secret}"))
    coder = CoderAgent(llm_client=llm)

    with pytest.raises(AgentError, match="global model-call budget"):
        await coder.run(_input(_issue(), _located()))


@pytest.mark.asyncio
async def test_coder_rejects_change_outside_located_blast_radius() -> None:
    llm = _PatchLLM(_patch(path="src/unrelated.py"))
    coder = CoderAgent(llm_client=llm)

    with pytest.raises(AgentError, match="global model-call budget"):
        await coder.run(_input(_issue(), _located()))


def test_coder_rejects_duplicate_diff_mismatch_and_invalid_python() -> None:
    duplicate = _patch()
    duplicate.changes.append(duplicate.changes[0].model_copy(deep=True))
    with pytest.raises(AgentError, match="duplicate"):
        CoderAgent._validate_patch(duplicate, _located())

    mismatched = _patch()
    mismatched.changes[0].diff = "--- a/other.py\n+++ b/other.py\n"
    with pytest.raises(AgentError, match="headers"):
        CoderAgent._validate_patch(mismatched, _located())

    invalid = _patch(content="if True print('bad')\n")
    with pytest.raises(AgentError, match="invalid Python syntax"):
        CoderAgent._validate_patch(invalid, _located())


def test_shared_secret_policy_covers_bearer_aws_and_truncated_pem() -> None:
    samples = [
        "bearer " + "x" * 20,
        "ASIA" + "A" * 16,
        "-----BEGIN " + "PRIVATE KEY-----\ntruncated",
    ]

    for sample in samples:
        assert contains_secret(sample)
        sanitized, changed = redact_text(sample)
        assert changed
        assert sample not in sanitized
        assert sanitized == "[REDACTED]"


def test_shared_secret_policy_covers_named_high_entropy_credentials() -> None:
    credential = "".join(("Ab9_", "Zy8-", "Xq7.", "Wm6+", "Tr5/", "Ku4="))
    samples = [
        f"api_key={credential}",
        f'password: "{credential}"',
        {"access_token": credential},
    ]

    for sample in samples:
        assert contains_secret(sample)
    first_sample = samples[0]
    assert isinstance(first_sample, str)
    sanitized, changed = redact_text(first_sample)
    assert changed
    assert credential not in sanitized
    assert sanitized == "api_key=[REDACTED]"

    for placeholder in (
        "api_key=${DEVFLOW_API_KEY}",
        "password: changeme",
        "token=example-token",
    ):
        assert not contains_secret(placeholder)


@pytest.mark.asyncio
async def test_coder_redacts_named_credential_before_model_call() -> None:
    credential = "".join(("Qp9_", "Lm8-", "Vx7.", "Rs6+", "Nt5/", "Hk4="))
    llm = _PatchLLM(_patch())
    coder = CoderAgent(llm_client=llm)

    await coder.run(
        _input(
            _issue(body=f"provider api_key={credential}"),
            _located(context=f"password: {credential}"),
        )
    )

    assert len(llm.prompts) == 1
    assert credential not in llm.prompts[0]
    assert "[REDACTED]" in llm.prompts[0]
