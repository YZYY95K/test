"""Network-free tests for LLM request, parsing, and failure boundaries."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import BaseModel

import devflow.llm_client as llm_module
from devflow.exceptions import LLMError
from devflow.llm_client import LLMClient


class Answer(BaseModel):
    value: int


class FakeCompletions:
    def __init__(self, content: str = "ok", error: Exception | None = None) -> None:
        self.content = content
        self.error = error
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=self.content))]
        )


def _client(completions: FakeCompletions) -> LLMClient:
    client = LLMClient(api_key="test", base_url="http://127.0.0.1:1", default_model="m")
    client._client = cast(
        Any, SimpleNamespace(chat=SimpleNamespace(completions=completions))
    )
    return client


def test_llm_client_requires_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    with pytest.raises(LLMError, match="not configured"):
        LLMClient()


@pytest.mark.asyncio
async def test_complete_builds_messages_and_wraps_provider_failure() -> None:
    completions = FakeCompletions("done")
    client = _client(completions)

    assert await client.complete("task", system="policy", temperature=0.1) == "done"
    call = completions.calls[0]
    assert call["model"] == "m"
    assert call["messages"] == [
        {"role": "system", "content": "policy"},
        {"role": "user", "content": "task"},
    ]

    failing = _client(FakeCompletions(error=RuntimeError("provider down")))
    with pytest.raises(LLMError, match="provider down"):
        await failing.complete("task")


@pytest.mark.asyncio
async def test_structured_completion_accepts_fence_and_rejects_bad_json() -> None:
    client = _client(FakeCompletions("```json\n{\"value\": 7}\n```"))
    result = await client.complete_structured(prompt="answer", response_model=Answer)
    assert result.value == 7

    invalid = _client(FakeCompletions("not json"))
    with pytest.raises(LLMError, match="Invalid Answer"):
        await invalid.complete_structured(prompt="answer", response_model=Answer)


def test_shared_client_is_lazy_and_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    llm_module._shared_client = None
    assert llm_module.get_llm_client() is None

    cached = _client(FakeCompletions())
    llm_module._shared_client = cached
    assert llm_module.get_llm_client() is cached
    llm_module._shared_client = None
