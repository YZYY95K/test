"""RAG indexing, retrieval, and degraded embedding tests without network calls."""

from __future__ import annotations

from typing import Any

import pytest

from devflow.exceptions import LLMError, SkillError
from devflow.rag.codebase_indexer import (
    CodebaseIndexer,
    _chunk_file,
    _detect_language,
    _should_ignore,
)
from devflow.rag.embeddings import HashEmbeddingProvider
from devflow.rag.experience_store import ExperienceStore


class FakeCollection:
    def __init__(self) -> None:
        self.added: dict[str, Any] | None = None
        self.upserted: dict[str, Any] | None = None
        self.query_result: dict[str, Any] = {}

    def add(self, **kwargs: Any) -> None:
        self.added = kwargs

    def upsert(self, **kwargs: Any) -> None:
        self.upserted = kwargs

    def query(self, **_kwargs: Any) -> dict[str, Any]:
        return self.query_result


class FailingProvider:
    dimension = 384

    def embed(self, _texts: list[str]) -> list[list[float]]:
        raise LLMError("embedding unavailable")


def test_hash_embeddings_are_normalized_deterministic_and_distinct() -> None:
    provider = HashEmbeddingProvider(128)
    first, repeated, other = provider.embed(
        ["parse_config yaml loader", "parse_config yaml loader", "http retry timeout"]
    )

    assert first == repeated
    assert first != other
    assert sum(value * value for value in first) == pytest.approx(1.0)
    assert provider.embed([""])[0] == [0.0] * 128


def test_code_chunking_respects_language_structure_and_ignores_build_paths() -> None:
    source = "x = 1\n\ndef add(a, b):\n    return a + b\n\nclass Box:\n    pass\n"
    chunks = _chunk_file("src/calc.py", source)

    assert _detect_language("web/app.tsx") == "typescript"
    assert _should_ignore("node_modules/pkg/index.js")
    assert not _should_ignore("src/node_module_helper.py")
    assert [(chunk.start_line, chunk.end_line) for chunk in chunks] == [(3, 4), (6, 7)]
    assert _chunk_file("broken.py", "def broken(\n")[0].content == "def broken(\n"
    assert len(_chunk_file("notes.md", "line\n" * 161)) == 3


@pytest.mark.asyncio
async def test_codebase_indexer_indexes_and_searches_with_injected_backends() -> None:
    async def fetch(repo_owner: str, repo_name: str) -> list[tuple[str, str]]:
        del repo_owner, repo_name
        return [
            ("src/calc.py", "def add(a, b):\n    return a + b\n"),
            ("README.md", "calculator usage\n"),
            (".git/config", "ignored"),
            ("empty.py", "   "),
        ]

    collection = FakeCollection()
    indexer = CodebaseIndexer(file_fetcher=fetch)
    indexer._collection = collection
    indexer._embedding_provider = HashEmbeddingProvider(128)

    count = await indexer.index_repository("example", "calculator")
    assert count == 2
    assert collection.added is not None
    assert len(collection.added["ids"]) == 2

    collection.query_result = {
        "documents": [["def add(a, b):\n    return a + b\n"]],
        "metadatas": [[{
            "file_path": "src/calc.py",
            "start_line": 1,
            "end_line": 2,
            "language": "python",
        }]],
    }
    results = await indexer.search("addition bug", top_k=3)
    assert results[0].file_path == "src/calc.py"
    assert results[0].language == "python"


@pytest.mark.asyncio
async def test_codebase_indexer_reports_missing_fetcher_and_empty_repository() -> None:
    with pytest.raises(SkillError, match="No file_fetcher"):
        await CodebaseIndexer().index_repository("example", "repo")

    async def empty(repo_owner: str, repo_name: str) -> list[tuple[str, str]]:
        del repo_owner, repo_name
        return [("empty.py", ""), ("dist/generated.js", "ignored")]

    assert await CodebaseIndexer(file_fetcher=empty).index_repository("e", "r") == 0


@pytest.mark.asyncio
async def test_experience_store_store_search_and_duplicate_threshold() -> None:
    collection = FakeCollection()
    store = ExperienceStore()
    store._collection = collection
    store._embedding_provider = HashEmbeddingProvider(128)

    metadata = {
        "pattern_id": "pattern-1",
        "issue_number": 42,
        "tier": "T2",
        "root_cause_file": "src/calc.py",
    }
    await store.store("pattern-1", "wrong arithmetic operator", metadata)
    assert collection.upserted is not None
    assert collection.upserted["ids"] == ["pattern-1"]

    collection.query_result = {
        "documents": [["wrong arithmetic operator"]],
        "metadatas": [[metadata]],
    }
    patterns = await store.search("addition bug")
    assert patterns[0].pattern_id == "pattern-1"
    assert patterns[0].issue_number == 42

    collection.query_result = {
        "distances": [[0.05]],
        "metadatas": [[{"issue_number": 42}]],
    }
    assert await store.find_duplicate("Addition", "Wrong result") == 42
    collection.query_result = {
        "distances": [[0.5]],
        "metadatas": [[{"issue_number": 42}]],
    }
    assert await store.find_duplicate("Different", "Issue") is None


@pytest.mark.asyncio
async def test_experience_dedup_degrades_on_embedding_failure() -> None:
    store = ExperienceStore()
    store._embedding_provider = FailingProvider()

    assert await store.find_duplicate("title", "body") is None
