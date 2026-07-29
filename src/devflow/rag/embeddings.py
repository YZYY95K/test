"""Pluggable embedding providers with a deterministic credential-free fallback."""

from __future__ import annotations

import hashlib
import math
import os
import re
from typing import Any, Protocol

from devflow.exceptions import LLMError

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[\u4e00-\u9fff]")


class EmbeddingProvider(Protocol):
    dimension: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class OpenAIEmbeddingProvider:
    """OpenAI-compatible embedding adapter for Z.AI or another provider."""

    def __init__(self, *, api_key: str, base_url: str, model: str) -> None:
        if not api_key:
            raise LLMError("embedding API key is unavailable")
        from openai import OpenAI

        self._client: Any = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.dimension = int(os.getenv("EMBEDDING_DIMENSION", "2048"))

    def embed(self, texts: list[str]) -> list[list[float]]:
        try:
            response = self._client.embeddings.create(model=self.model, input=texts)
            return [list(item.embedding) for item in response.data]
        except Exception as exc:
            raise LLMError(
                f"Embedding API call failed: {type(exc).__name__}"
            ) from exc


class HashEmbeddingProvider:
    """Bounded local feature hashing for offline retrieval and degraded mode."""

    def __init__(self, dimension: int = 384) -> None:
        if dimension < 64 or dimension > 4096:
            raise ValueError("local embedding dimension must be between 64 and 4096")
        self.dimension = dimension

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(text) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        tokens = [token.lower() for token in _TOKEN.findall(text)]
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimension
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        return [value / norm for value in vector] if norm else vector


def build_embedding_provider(
    *, api_key: str | None, base_url: str | None, model: str
) -> EmbeddingProvider:
    provider = os.getenv("EMBEDDING_PROVIDER", "openai-compatible").lower()
    if provider == "local-hash":
        return HashEmbeddingProvider(int(os.getenv("LOCAL_EMBEDDING_DIMENSION", "384")))
    if provider != "openai-compatible":
        raise LLMError(f"unsupported embedding provider: {provider}")
    return OpenAIEmbeddingProvider(
        api_key=api_key or "",
        base_url=base_url or "https://api.z.ai/api/paas/v4/",
        model=model,
    )


__all__ = [
    "EmbeddingProvider",
    "HashEmbeddingProvider",
    "OpenAIEmbeddingProvider",
    "build_embedding_provider",
]
