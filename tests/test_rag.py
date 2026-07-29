"""RAG isolation, integrity, indexing, and degraded embedding tests."""

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
from devflow.rag.scope import RepositoryScope, cosine_similarity

NOW = 1_800_000_000.0
INTEGRITY_KEY = b"test-only-rag-integrity-key-32-bytes"
REVISION_A = "a" * 40
REVISION_B = "b" * 40
SCOPE_A = RepositoryScope(
    tenant_id="tenant-a",
    repo_owner="Example",
    repo_name="Calculator",
    revision=REVISION_A,
)
SCOPE_OTHER_TENANT = RepositoryScope(
    tenant_id="tenant-b",
    repo_owner="example",
    repo_name="calculator",
    revision=REVISION_A,
)
SCOPE_OTHER_REVISION = RepositoryScope(
    tenant_id="tenant-a",
    repo_owner="example",
    repo_name="calculator",
    revision=REVISION_B,
)


class FakeCollection:
    def __init__(self) -> None:
        self.upserted: dict[str, Any] | None = None
        self.query_result: dict[str, Any] = {}
        self.query_calls: list[dict[str, Any]] = []

    def upsert(self, **kwargs: Any) -> None:
        self.upserted = kwargs

    def query(self, **kwargs: Any) -> dict[str, Any]:
        self.query_calls.append(kwargs)
        return self.query_result


class FailingProvider:
    dimension = 384

    def embed(self, _texts: list[str]) -> list[list[float]]:
        raise LLMError("embedding unavailable")


def _query_result_from_upsert(
    collection: FakeCollection,
    *,
    index: int = 0,
    distance: float | None = None,
) -> dict[str, Any]:
    assert collection.upserted is not None
    result = {
        "ids": [[collection.upserted["ids"][index]]],
        "documents": [[collection.upserted["documents"][index]]],
        "metadatas": [[collection.upserted["metadatas"][index]]],
        "embeddings": [[collection.upserted["embeddings"][index]]],
    }
    if distance is not None:
        result["distances"] = [[distance]]
    return result


def _distance_to_stored(collection: FakeCollection, query: str) -> float:
    assert collection.upserted is not None
    query_embedding = HashEmbeddingProvider(128).embed([query])[0]
    stored_embedding = collection.upserted["embeddings"][0]
    return 1.0 - cosine_similarity(query_embedding, stored_embedding)


def _bound_codebase(
    collection: FakeCollection,
    *,
    scope: RepositoryScope = SCOPE_A,
    clock: Any = lambda: NOW,
    integrity_key: bytes = INTEGRITY_KEY,
) -> CodebaseIndexer:
    async def fetch(
        repo_owner: str,
        repo_name: str,
        exact_revision: str,
    ) -> list[tuple[str, str]]:
        assert (repo_owner, repo_name, exact_revision) == (
            scope.repo_owner,
            scope.repo_name,
            scope.revision,
        )
        return [
            ("src/calc.py", "def add(a, b):\n    return a + b\n"),
            ("README.md", "calculator usage\n"),
            (".git/config", "ignored"),
            ("empty.py", "   "),
        ]

    indexer = CodebaseIndexer(
        file_fetcher=fetch,
        scope=scope,
        clock=clock,
        integrity_key=integrity_key,
    )
    indexer._collection = collection
    indexer._embedding_provider = HashEmbeddingProvider(128)
    return indexer


def _bound_experience(
    collection: FakeCollection,
    *,
    scope: RepositoryScope = SCOPE_A,
    clock: Any = lambda: NOW,
    record_ttl_seconds: int = 7_776_000,
    integrity_key: bytes = INTEGRITY_KEY,
) -> ExperienceStore:
    store = ExperienceStore(
        scope=scope,
        clock=clock,
        record_ttl_seconds=record_ttl_seconds,
        integrity_key=integrity_key,
    )
    store._collection = collection
    store._embedding_provider = HashEmbeddingProvider(128)
    return store


async def _store_pattern(store: ExperienceStore) -> None:
    await store.store(
        "pattern-1",
        "wrong arithmetic operator",
        {
            "pattern_id": "pattern-1",
            "issue_number": 42,
            "tier": "T2",
            "root_cause_file": "src/calc.py",
        },
    )


def test_repository_scope_is_canonical_and_requires_an_exact_revision() -> None:
    assert SCOPE_A.repository_id == "example/calculator"
    assert SCOPE_A.namespace.startswith("rag-v1:")
    assert SCOPE_A.namespace != SCOPE_OTHER_TENANT.namespace
    assert SCOPE_A.namespace != SCOPE_OTHER_REVISION.namespace
    assert CodebaseIndexer._collection_name(SCOPE_A) != (
        CodebaseIndexer._collection_name(SCOPE_OTHER_TENANT)
    )
    assert ExperienceStore._collection_name(SCOPE_A) != (
        ExperienceStore._collection_name(SCOPE_OTHER_REVISION)
    )
    assert "tenant-a" not in CodebaseIndexer._collection_name(SCOPE_A)

    with pytest.raises(ValueError, match="exact 40- or 64-character"):
        RepositoryScope("tenant-a", "example", "calculator", "main")
    with pytest.raises(ValueError, match="canonical"):
        RepositoryScope(" tenant-a", "example", "calculator", REVISION_A)


def test_rag_stores_reject_missing_or_weak_integrity_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DEVFLOW_RAG_HMAC_KEY", raising=False)
    with pytest.raises(SkillError, match="at least 32 bytes"):
        CodebaseIndexer(scope=SCOPE_A)
    with pytest.raises(SkillError, match="at least 32 bytes"):
        ExperienceStore(scope=SCOPE_A, integrity_key=b"weak")


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
async def test_codebase_indexer_seals_exact_revision_and_filters_every_search() -> None:
    collection = FakeCollection()
    indexer = _bound_codebase(collection)

    assert await indexer.index_repository() == 2
    assert collection.upserted is not None
    assert len(collection.upserted["ids"]) == 2
    for metadata in collection.upserted["metadatas"]:
        assert metadata["tenant_id"] == SCOPE_A.tenant_id
        assert metadata["repository_revision"] == SCOPE_A.revision
        assert metadata["namespace"] == SCOPE_A.namespace
        assert metadata["integrity_algorithm"] == "hmac-sha256"
        assert len(metadata["record_hmac_sha256"]) == 64

    collection.query_result = _query_result_from_upsert(collection)
    results = await indexer.search("addition bug", top_k=3)

    assert results[0].file_path == "src/calc.py"
    assert results[0].repository_id == SCOPE_A.repository_id
    assert results[0].repository_revision == SCOPE_A.revision
    assert results[0].namespace == SCOPE_A.namespace
    assert collection.query_calls[-1]["where"] == {"namespace": SCOPE_A.namespace}


@pytest.mark.asyncio
async def test_codebase_indexer_requires_scope_fetcher_and_nonempty_repository() -> None:
    with pytest.raises(SkillError, match="explicit tenant"):
        await CodebaseIndexer(integrity_key=INTEGRITY_KEY).index_repository()

    with pytest.raises(SkillError, match="No file_fetcher"):
        await CodebaseIndexer(
            scope=SCOPE_A,
            integrity_key=INTEGRITY_KEY,
        ).index_repository()

    async def empty(
        repo_owner: str,
        repo_name: str,
        exact_revision: str,
    ) -> list[tuple[str, str]]:
        assert (repo_owner, repo_name, exact_revision) == (
            SCOPE_A.repo_owner,
            SCOPE_A.repo_name,
            SCOPE_A.revision,
        )
        return [("empty.py", ""), ("dist/generated.js", "ignored")]

    assert (
        await CodebaseIndexer(
            file_fetcher=empty,
            scope=SCOPE_A,
            clock=lambda: NOW,
            integrity_key=INTEGRITY_KEY,
        ).index_repository()
        == 0
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("wrong_scope", [SCOPE_OTHER_TENANT, SCOPE_OTHER_REVISION])
async def test_codebase_search_fails_closed_if_backend_crosses_scope(
    wrong_scope: RepositoryScope,
) -> None:
    collection = FakeCollection()
    source = _bound_codebase(collection)
    await source.index_repository()
    collection.query_result = _query_result_from_upsert(collection)

    reader = CodebaseIndexer(
        scope=wrong_scope,
        clock=lambda: NOW,
        integrity_key=INTEGRITY_KEY,
    )
    reader._collection = collection
    reader._embedding_provider = HashEmbeddingProvider(128)
    with pytest.raises(SkillError, match="does not match scope"):
        await reader.search("addition")
    assert collection.query_calls[-1]["where"] == {
        "namespace": wrong_scope.namespace
    }


@pytest.mark.asyncio
async def test_codebase_search_fails_closed_on_tamper_and_incomplete_provenance() -> None:
    collection = FakeCollection()
    indexer = _bound_codebase(collection)
    await indexer.index_repository()
    collection.query_result = _query_result_from_upsert(collection)
    collection.query_result["documents"][0][0] += "\nmalicious()"

    with pytest.raises(SkillError, match="integrity digest mismatch"):
        await indexer.search("addition")

    collection.query_result = {
        "documents": [["unsealed"]],
        "metadatas": [[{}]],
        "ids": [[]],
    }
    with pytest.raises(SkillError, match="incomplete result provenance"):
        await indexer.search("addition")


@pytest.mark.asyncio
async def test_legacy_unsealed_code_record_is_not_retrievable() -> None:
    collection = FakeCollection()
    indexer = _bound_codebase(collection)
    await indexer.index_repository()
    collection.query_result = _query_result_from_upsert(collection)
    del collection.query_result["metadatas"][0][0]["record_hmac_sha256"]

    with pytest.raises(SkillError, match="integrity digest is missing"):
        await indexer.search("addition")


@pytest.mark.asyncio
async def test_experience_store_seals_and_retrieves_only_bound_namespace() -> None:
    collection = FakeCollection()
    store = _bound_experience(collection)
    await _store_pattern(store)

    assert collection.upserted is not None
    assert collection.upserted["ids"][0].startswith(
        f"experience:{SCOPE_A.namespace}:"
    )
    metadata = collection.upserted["metadatas"][0]
    assert metadata["repository_id"] == SCOPE_A.repository_id
    assert metadata["repository_revision"] == SCOPE_A.revision
    assert metadata["integrity_algorithm"] == "hmac-sha256"
    assert len(metadata["record_hmac_sha256"]) == 64

    collection.query_result = _query_result_from_upsert(collection)
    patterns = await store.search("addition bug")
    assert patterns[0].pattern_id == "pattern-1"
    assert patterns[0].issue_number == 42
    assert patterns[0].repository_revision == SCOPE_A.revision
    assert collection.query_calls[-1]["where"] == {"namespace": SCOPE_A.namespace}

    duplicate_query = "wrong arithmetic operator\n\n"
    collection.query_result = _query_result_from_upsert(
        collection,
        distance=_distance_to_stored(collection, duplicate_query),
    )
    assert await store.find_duplicate("wrong arithmetic operator", "") == 42
    unrelated_query = "Different\n\nIssue"
    collection.query_result = _query_result_from_upsert(
        collection,
        distance=_distance_to_stored(collection, unrelated_query),
    )
    assert await store.find_duplicate("Different", "Issue") is None


@pytest.mark.asyncio
async def test_experience_store_rejects_scope_spoofing_and_conflicting_scope() -> None:
    collection = FakeCollection()
    store = _bound_experience(collection)

    with pytest.raises(SkillError, match="reserved fields"):
        await store.store(
            "pattern-1",
            "summary",
            {"repository_revision": SCOPE_OTHER_REVISION.revision},
        )
    with pytest.raises(SkillError, match="conflicts with the bound"):
        await store.search("query", scope=SCOPE_OTHER_TENANT)
    assert collection.upserted is None
    assert collection.query_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("wrong_scope", [SCOPE_OTHER_TENANT, SCOPE_OTHER_REVISION])
async def test_experience_search_fails_closed_if_backend_ignores_namespace_filter(
    wrong_scope: RepositoryScope,
) -> None:
    collection = FakeCollection()
    writer = _bound_experience(collection)
    await _store_pattern(writer)
    collection.query_result = _query_result_from_upsert(collection)

    reader = _bound_experience(collection, scope=wrong_scope)
    with pytest.raises(SkillError, match="does not match scope"):
        await reader.search("addition")


@pytest.mark.asyncio
async def test_experience_search_fails_closed_on_expired_or_tampered_record() -> None:
    current = [NOW]
    collection = FakeCollection()
    store = _bound_experience(
        collection,
        clock=lambda: current[0],
        record_ttl_seconds=10,
    )
    await _store_pattern(store)
    collection.query_result = _query_result_from_upsert(collection)

    current[0] = NOW + 11
    with pytest.raises(SkillError, match="record is expired"):
        await store.search("addition")

    current[0] = NOW
    collection.query_result = _query_result_from_upsert(collection)
    collection.query_result["metadatas"][0][0]["issue_number"] = 999
    with pytest.raises(SkillError, match="integrity digest mismatch"):
        await store.search("addition")


@pytest.mark.asyncio
async def test_experience_search_fails_closed_with_wrong_integrity_key() -> None:
    collection = FakeCollection()
    writer = _bound_experience(collection)
    await _store_pattern(writer)
    collection.query_result = _query_result_from_upsert(collection)

    reader = _bound_experience(
        collection,
        integrity_key=b"different-test-rag-key-material-32-bytes",
    )
    with pytest.raises(SkillError, match="integrity key id mismatch"):
        await reader.search("addition")


@pytest.mark.asyncio
async def test_duplicate_check_validates_record_before_using_similarity() -> None:
    collection = FakeCollection()
    store = _bound_experience(collection)
    await _store_pattern(store)
    collection.query_result = _query_result_from_upsert(collection, distance=0.5)
    collection.query_result["documents"][0][0] = "tampered"

    with pytest.raises(SkillError, match="integrity digest mismatch"):
        await store.find_duplicate("Different", "Issue")


@pytest.mark.asyncio
async def test_search_fails_closed_when_vector_embedding_is_tampered() -> None:
    collection = FakeCollection()
    store = _bound_experience(collection)
    await _store_pattern(store)
    collection.query_result = _query_result_from_upsert(collection)
    collection.query_result["embeddings"][0][0][0] += 0.25

    with pytest.raises(SkillError, match="embedding digest mismatch"):
        await store.search("addition")


@pytest.mark.asyncio
async def test_duplicate_check_fails_closed_when_backend_distance_is_tampered() -> None:
    collection = FakeCollection()
    store = _bound_experience(collection)
    await _store_pattern(store)
    collection.query_result = _query_result_from_upsert(collection, distance=0.0)

    with pytest.raises(SkillError, match="distance is inconsistent"):
        await store.find_duplicate("completely", "unrelated")


@pytest.mark.asyncio
async def test_experience_dedup_degrades_only_on_embedding_failure() -> None:
    store = ExperienceStore(scope=SCOPE_A, integrity_key=INTEGRITY_KEY)
    store._embedding_provider = FailingProvider()

    assert await store.find_duplicate("title", "body") is None


@pytest.mark.asyncio
async def test_unbound_experience_operations_fail_before_backend_access() -> None:
    store = ExperienceStore(integrity_key=INTEGRITY_KEY)
    store._embedding_provider = HashEmbeddingProvider(128)

    with pytest.raises(SkillError, match="explicit tenant"):
        await store.store("pattern", "summary", {})
    with pytest.raises(SkillError, match="explicit tenant"):
        await store.search("query")
    with pytest.raises(SkillError, match="explicit tenant"):
        await store.find_duplicate("title", "body")
