"""OpenAI-compatible LLM client with validated structured responses."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, TypeVar

from openai import AsyncOpenAI
from pydantic import BaseModel

from devflow.exceptions import LLMError

ResponseT = TypeVar("ResponseT", bound=BaseModel)


@dataclass(frozen=True)
class CompletionResult:
    """One completion plus provider-reported token usage."""

    content: str
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None


class LLMClient:
    """Thin async client used by all agents.

    The interface is intentionally small so tests and the offline demo can
    inject deterministic replacements without network access.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        default_model: str | None = None,
    ) -> None:
        resolved_key = api_key or os.getenv("LLM_API_KEY")
        if not resolved_key:
            raise LLMError("LLM_API_KEY is not configured.")
        self.default_model = default_model or os.getenv("LLM_MODEL", "glm-5.2")
        self._client = AsyncOpenAI(
            api_key=resolved_key,
            base_url=base_url
            or os.getenv("LLM_BASE_URL", "https://api.z.ai/api/paas/v4/"),
        )

    async def complete(
        self,
        prompt: str,
        *,
        model: str | None = None,
        temperature: float = 0.2,
        system: str | None = None,
    ) -> str:
        return (
            await self.complete_with_usage(
                prompt,
                model=model,
                temperature=temperature,
                system=system,
            )
        ).content

    async def complete_with_usage(
        self,
        prompt: str,
        *,
        model: str | None = None,
        temperature: float = 0.2,
        system: str | None = None,
    ) -> CompletionResult:
        """Complete a prompt and retain the provider's usage accounting."""

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        try:
            completions: Any = self._client.chat.completions
            response = await completions.create(
                model=model or self.default_model,
                messages=messages,
                temperature=temperature,
            )
            usage = response.usage
            return CompletionResult(
                content=response.choices[0].message.content or "",
                prompt_tokens=getattr(usage, "prompt_tokens", None),
                completion_tokens=getattr(usage, "completion_tokens", None),
                total_tokens=getattr(usage, "total_tokens", None),
            )
        except Exception as exc:
            raise LLMError(f"LLM completion failed: {exc}") from exc

    async def complete_structured(
        self,
        *,
        prompt: str,
        response_model: type[ResponseT],
        model: str | None = None,
        temperature: float = 0.2,
        system: str | None = None,
    ) -> ResponseT:
        schema = json.dumps(response_model.model_json_schema(), ensure_ascii=False)
        structured_prompt = (
            f"{prompt}\n\nReturn only valid JSON matching this schema:\n{schema}"
        )
        raw = await self.complete(
            structured_prompt,
            model=model,
            temperature=temperature,
            system=system,
        )
        try:
            text = raw.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[1].rsplit("```", 1)[0]
            return response_model.model_validate_json(text)
        except Exception as exc:
            raise LLMError(
                f"Invalid {response_model.__name__} response: {exc}"
            ) from exc


_shared_client: LLMClient | None = None


def get_llm_client() -> LLMClient | None:
    """Return a lazily-created shared client, or ``None`` without credentials."""

    global _shared_client
    if _shared_client is not None:
        return _shared_client
    if not os.getenv("LLM_API_KEY"):
        return None
    _shared_client = LLMClient()
    return _shared_client
