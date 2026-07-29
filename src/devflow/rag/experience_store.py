"""Experience store for reusable fix-pattern persistence and retrieval.

Stores distilled fix patterns in ChromaDB with semantic embeddings so that
future issues can be matched against historical solutions. This powers the
deduplication lookup in :class:`IssueClassifierSkill` and the few-shot example
generation for :class:`PatchGeneratorSkill`.

The default boundary is exact-revision reuse within one tenant and repository.
There is no implicit global or cross-repository fallback. Stored documents,
metadata, and vectors are authenticated and expire closed.
"""

from __future__ import annotations

import hashlib
import math
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from numbers import Real
from typing import Any

from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from devflow.exceptions import LLMError, SkillError
from devflow.models.patch import canonical_repository_path
from devflow.observability import logger, tracer
from devflow.rag.embeddings import EmbeddingProvider, build_embedding_provider
from devflow.rag.scope import (
    RepositoryScope,
    cosine_similarity,
    embedding_sha256,
    query_result_row,
    require_integrity_key,
    resolve_scope,
    seal_record,
    utc_epoch,
    validate_user_metadata,
    verify_record,
)

# ---------------------------------------------------------------------------
# Public models
# ---------------------------------------------------------------------------


@dataclass
class ExperiencePattern:
    """A reusable fix pattern extracted from a completed issue.

    Attributes:
        pattern_id: Unique identifier of the pattern in the store.
        summary: Human-readable description of the fix pattern.
        issue_number: GitHub issue number this pattern was distilled from.
        tier: Complexity tier (T1-T5) of the source issue.
        root_cause_file: File path where the root cause was located.
    """

    pattern_id: str
    summary: str
    issue_number: int
    tier: str
    root_cause_file: str
    tenant_id: str
    repository_id: str
    repository_revision: str
    namespace: str
    record_hmac_sha256: str
    similarity: float


# ---------------------------------------------------------------------------
# ExperienceStore
# ---------------------------------------------------------------------------


def _validate_pattern_metadata(
    metadata: dict[str, Any],
    *,
    expected_pattern_id: str,
) -> tuple[int, str, str]:
    """Validate fields consumed by retrieval instead of coercing backend data."""
    pattern_id = metadata.get("pattern_id")
    issue_number = metadata.get("issue_number")
    tier = metadata.get("tier")
    root_cause_file = metadata.get("root_cause_file")
    if pattern_id != expected_pattern_id:
        raise SkillError("RAG record failed closed: pattern identity mismatch")
    if (
        not isinstance(issue_number, int)
        or isinstance(issue_number, bool)
        or issue_number < 1
    ):
        raise SkillError("RAG record failed closed: invalid issue number")
    if (
        not isinstance(tier, str)
        or not tier
        or tier != tier.strip()
        or len(tier) > 32
    ):
        raise SkillError("RAG record failed closed: invalid experience tier")
    if not isinstance(root_cause_file, str):
        raise SkillError(
            "RAG record failed closed: invalid root-cause repository path"
        )
    try:
        canonical_path = canonical_repository_path(root_cause_file)
    except (TypeError, ValueError) as exc:
        raise SkillError(
            "RAG record failed closed: invalid root-cause repository path"
        ) from exc
    return issue_number, tier, canonical_path


class ExperienceStore:
    """Stores and retrieves fix patterns in ChromaDB.

    Each pattern is embedded so that semantic similarity search can find
    historically relevant solutions for new issues. The store also supports
    duplicate detection: given a new issue's title and body, it returns the
    issue number of a closely matching prior pattern if one exists.
    """

    COLLECTION_NAME = "experience_store"
    EMBEDDING_MODEL = "embedding-3"
    EMBEDDING_DIMENSION = 2048

    #: Minimum cosine similarity (1 - distance) to consider an issue a duplicate.
    DUPLICATE_SIMILARITY_THRESHOLD = 0.88

    def __init__(
        self,
        persist_path: str | None = None,
        embedding_api_key: str | None = None,
        embedding_base_url: str | None = None,
        scope: RepositoryScope | None = None,
        record_ttl_seconds: int = 7_776_000,
        clock: Callable[[], float] = time.time,
        integrity_key: bytes | None = None,
    ) -> None:
        """Initialize the experience store.

        Args:
            persist_path: Filesystem path for the ChromaDB persistent directory.
                Defaults to the ``CHROMADB_PATH`` env var, or ``.devflow/chromadb``.
            embedding_api_key: API key for the embeddings endpoint.
                Defaults to ``LLM_API_KEY`` env var.
            embedding_base_url: Base URL for the embeddings endpoint.
                Defaults to ``LLM_BASE_URL`` env var.
            scope: Optional repository scope bound for this store instance.
            record_ttl_seconds: Lifetime of a memory record before retrieval fails.
            clock: Time source, injectable for deterministic verification.
            integrity_key: HMAC key for authenticating stored records. Defaults
                to ``DEVFLOW_RAG_HMAC_KEY`` and must be at least 32 bytes.
        """
        if (
            not isinstance(record_ttl_seconds, int)
            or isinstance(record_ttl_seconds, bool)
            or record_ttl_seconds <= 0
        ):
            raise ValueError("record_ttl_seconds must be a positive integer")
        self._persist_path = persist_path or os.getenv(
            "CHROMADB_PATH", ".devflow/chromadb"
        ) or ".devflow/chromadb"
        self._embedding_api_key = (
            embedding_api_key
            or os.getenv("EMBEDDING_API_KEY")
            or os.getenv("LLM_API_KEY", "")
        )
        self._embedding_base_url = (
            embedding_base_url
            or os.getenv("EMBEDDING_BASE_URL")
            or os.getenv("LLM_BASE_URL", "https://api.z.ai/api/paas/v4/")
        )
        self._embedding_model = os.getenv("EMBEDDING_MODEL", self.EMBEDDING_MODEL)
        self._scope = scope
        self._record_ttl_seconds = record_ttl_seconds
        self._clock = clock
        configured_key = os.getenv("DEVFLOW_RAG_HMAC_KEY", "").encode()
        self._integrity_key = require_integrity_key(
            integrity_key if integrity_key is not None else configured_key
        )
        self._client: Any | None = None
        self._collections: dict[str, Any] = {}
        self._collection: Any | None = None
        self._embedding_provider: EmbeddingProvider | None = None

    # -- lazy initialization ------------------------------------------------

    def _get_chroma_client(self) -> Any:
        """Lazily create the ChromaDB persistent client."""
        if self._client is None:
            try:
                import chromadb
            except ImportError as exc:
                raise SkillError('Install DevFlow with the "rag" extra for ChromaDB') from exc
            os.makedirs(self._persist_path, exist_ok=True)
            self._client = chromadb.PersistentClient(path=self._persist_path)
            logger.info(
                "experience_store.chroma_initialized", path=self._persist_path
            )
        return self._client

    @staticmethod
    def _collection_name(scope: RepositoryScope) -> str:
        return f"{ExperienceStore.COLLECTION_NAME}_{scope.namespace.removeprefix('rag-v1:')}"

    def _get_collection(self, scope: RepositoryScope) -> Any:
        """Lazily create a physically scoped experience collection."""
        # Kept as an explicit test/integration injection seam. Production
        # clients use the namespace-keyed collection cache below.
        if self._collection is None:
            cached = self._collections.get(scope.namespace)
            if cached is not None:
                return cached
            client = self._get_chroma_client()
            collection = client.get_or_create_collection(
                name=self._collection_name(scope),
                metadata={
                    "description": "Exact-revision distilled fix patterns",
                    "namespace": scope.namespace,
                    "repository_id": scope.repository_id,
                    "repository_revision": scope.revision,
                    "tenant_id": scope.tenant_id,
                },
            )
            self._collections[scope.namespace] = collection
            return collection
        return self._collection

    def _get_embedding_provider(self) -> EmbeddingProvider:
        if self._embedding_provider is None:
            self._embedding_provider = build_embedding_provider(
                api_key=self._embedding_api_key,
                base_url=self._embedding_base_url,
                model=self._embedding_model,
            )
        return self._embedding_provider

    # -- embedding ----------------------------------------------------------

    @retry(
        retry=retry_if_exception_type((TimeoutError, ConnectionError, LLMError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=15),
        reraise=True,
    )
    def _create_embedding(self, text: str) -> list[float]:
        """Generate an embedding vector for a single text.

        Args:
            text: Text to embed (issue title + body, or pattern summary).

        Returns:
            Embedding vector as a list of floats.

        Raises:
            LLMError: If the embedding API call fails after retries.
        """
        try:
            return self._get_embedding_provider().embed([text])[0]
        except Exception as exc:
            if isinstance(exc, LLMError):
                raise
            raise LLMError(
                f"Embedding API call failed: {type(exc).__name__}"
            ) from exc

    # -- public API ---------------------------------------------------------

    async def store(
        self,
        pattern_id: str,
        summary: str,
        metadata: dict[str, Any],
        *,
        scope: RepositoryScope | None = None,
    ) -> None:
        """Store a fix pattern with its embedding in ChromaDB.

        Args:
            pattern_id: Unique identifier for the pattern. If it already
                exists, it is upserted (updated in place).
            summary: Human-readable pattern summary to embed and store.
            metadata: Additional metadata (e.g. ``issue_number``, ``tier``,
                ``root_cause_file``).
            scope: Exact RAG scope. This may be omitted only when the store was
                constructed with a scope.

        Raises:
            SkillError: If storage fails.
        """
        repository_scope = resolve_scope(scope, self._scope)
        if (
            not isinstance(pattern_id, str)
            or not pattern_id
            or pattern_id != pattern_id.strip()
            or len(pattern_id) > 256
        ):
            raise SkillError("experience pattern_id must be canonical non-empty text")
        if not isinstance(summary, str) or not summary.strip():
            raise SkillError("experience summary must be non-empty text")
        user_metadata = validate_user_metadata(metadata)
        supplied_pattern_id = user_metadata.get("pattern_id")
        if supplied_pattern_id is not None and supplied_pattern_id != pattern_id:
            raise SkillError("experience metadata pattern_id does not match record id")
        validation_metadata = {**user_metadata, "pattern_id": pattern_id}
        _validate_pattern_metadata(
            validation_metadata,
            expected_pattern_id=pattern_id,
        )

        with tracer.start_as_current_span("experience_store.store") as span:
            span.set_attribute("pattern_id", pattern_id)
            span.set_attribute("rag.namespace", repository_scope.namespace)

            try:
                embedding = self._create_embedding(summary)
            except LLMError:
                raise
            except Exception as exc:
                raise SkillError(
                    f"Failed to create embedding for pattern {pattern_id}: {exc}"
                ) from exc

            collection = self._get_collection(repository_scope)
            now = utc_epoch(self._clock)
            record_id = (
                f"experience:{repository_scope.namespace}:"
                f"{hashlib.sha256(pattern_id.encode('utf-8')).hexdigest()}"
            )
            record_metadata = {
                **user_metadata,
                **repository_scope.metadata(
                    now=now,
                    ttl_seconds=self._record_ttl_seconds,
                ),
                "pattern_id": pattern_id,
                "summary_sha256": hashlib.sha256(
                    summary.encode("utf-8")
                ).hexdigest(),
                "embedding_sha256": embedding_sha256(embedding),
            }
            sealed_metadata = seal_record(
                record_id=record_id,
                document=summary,
                metadata=record_metadata,
                integrity_key=self._integrity_key,
            )
            try:
                collection.upsert(
                    ids=[record_id],
                    embeddings=[embedding],
                    documents=[summary],
                    metadatas=[sealed_metadata],
                )
            except Exception as exc:
                raise SkillError(
                    f"Failed to store pattern {pattern_id}: {type(exc).__name__}"
                ) from exc

            logger.info(
                "experience_store.pattern_stored",
                pattern_id=pattern_id,
                issue_number=user_metadata.get("issue_number"),
                repository_revision=repository_scope.revision,
            )

    async def search(
        self,
        query: str,
        top_k: int = 5,
        *,
        scope: RepositoryScope | None = None,
    ) -> list[ExperiencePattern]:
        """Search the experience store for patterns matching *query*.

        Args:
            query: Natural-language query (typically an issue title + body).
            top_k: Maximum number of patterns to return.
            scope: Exact RAG scope. This may be omitted only when the store was
                constructed with a scope.

        Returns:
            List of :class:`ExperiencePattern` ranked by relevance.

        Raises:
            SkillError: If the search fails.
        """
        repository_scope = resolve_scope(scope, self._scope)
        if not isinstance(query, str) or not query.strip():
            raise SkillError("experience search query must be non-empty text")
        if (
            not isinstance(top_k, int)
            or isinstance(top_k, bool)
            or top_k < 1
            or top_k > 100
        ):
            raise SkillError("experience top_k must be between 1 and 100")

        with tracer.start_as_current_span("experience_store.search") as span:
            span.set_attribute("query_length", len(query))
            span.set_attribute("top_k", top_k)
            span.set_attribute("rag.namespace", repository_scope.namespace)

            try:
                query_embedding = self._create_embedding(query)
            except LLMError:
                raise
            except Exception as exc:
                raise SkillError(
                    f"Failed to create query embedding: {exc}"
                ) from exc

            collection = self._get_collection(repository_scope)
            try:
                results = collection.query(
                    query_embeddings=[query_embedding],
                    n_results=top_k,
                    where={"namespace": repository_scope.namespace},
                    include=["documents", "metadatas", "embeddings"],
                )
            except Exception as exc:
                raise SkillError(
                    f"ChromaDB query failed: {type(exc).__name__}"
                ) from exc

            patterns: list[ExperiencePattern] = []
            row_documents = query_result_row(results, "documents")
            row_metadatas = query_result_row(results, "metadatas")
            row_ids = query_result_row(results, "ids")
            row_embeddings = query_result_row(results, "embeddings")
            if not (
                len(row_documents)
                == len(row_metadatas)
                == len(row_ids)
                == len(row_embeddings)
            ):
                raise SkillError(
                    "RAG backend returned incomplete result provenance"
                )
            now = utc_epoch(self._clock)
            for record_id, doc, meta, embedding in zip(
                row_ids,
                row_documents,
                row_metadatas,
                row_embeddings,
                strict=True,
            ):
                verified_doc, verified_meta = verify_record(
                    record_id=record_id,
                    document=doc,
                    metadata=meta,
                    scope=repository_scope,
                    integrity_key=self._integrity_key,
                    now=now,
                )
                if verified_meta.get("embedding_sha256") != embedding_sha256(
                    embedding
                ):
                    raise SkillError(
                        "RAG record failed closed: embedding digest mismatch"
                    )
                similarity = cosine_similarity(query_embedding, embedding)
                if verified_meta.get("summary_sha256") != hashlib.sha256(
                    verified_doc.encode("utf-8")
                ).hexdigest():
                    raise SkillError(
                        "RAG record failed closed: summary digest mismatch"
                    )
                pattern_id = verified_meta.get("pattern_id")
                if not isinstance(pattern_id, str) or not pattern_id:
                    raise SkillError(
                        "RAG record failed closed: invalid pattern id"
                    )
                issue_number, tier, root_cause_file = _validate_pattern_metadata(
                    verified_meta,
                    expected_pattern_id=pattern_id,
                )
                patterns.append(
                    ExperiencePattern(
                        pattern_id=pattern_id,
                        summary=verified_doc,
                        issue_number=issue_number,
                        tier=tier,
                        root_cause_file=root_cause_file,
                        tenant_id=repository_scope.tenant_id,
                        repository_id=repository_scope.repository_id,
                        repository_revision=repository_scope.revision,
                        namespace=repository_scope.namespace,
                        record_hmac_sha256=str(
                            verified_meta["record_hmac_sha256"]
                        ),
                        similarity=similarity,
                    )
                )

            patterns.sort(
                key=lambda pattern: (
                    -pattern.similarity,
                    pattern.pattern_id,
                )
            )
            span.set_attribute("results_count", len(patterns))
            logger.debug(
                "experience_store.search_complete",
                query_sha256=hashlib.sha256(query.encode("utf-8")).hexdigest(),
                results=len(patterns),
            )
            return patterns

    async def find_duplicate(
        self,
        issue_title: str,
        issue_body: str,
        *,
        scope: RepositoryScope | None = None,
    ) -> int | None:
        """Check whether an issue is a duplicate of a previously stored pattern.

        Computes the embedding of the issue title + body and queries the store
        for the closest match. If the cosine similarity exceeds
        :attr:`DUPLICATE_SIMILARITY_THRESHOLD`, the matching issue number is
        returned.

        Args:
            issue_title: Title of the issue to check.
            issue_body: Body of the issue to check.
            scope: Exact RAG scope. This may be omitted only when the store was
                constructed with a scope.

        Returns:
            The issue number of the duplicate pattern, or ``None`` if no
            sufficiently similar pattern exists.

        Raises:
            SkillError: If the deduplication query fails.
        """
        repository_scope = resolve_scope(scope, self._scope)
        if not isinstance(issue_title, str) or not issue_title.strip():
            raise SkillError("issue_title must be non-empty text")
        if not isinstance(issue_body, str):
            raise SkillError("issue_body must be text")
        with tracer.start_as_current_span("experience_store.find_duplicate") as span:
            combined_text = f"{issue_title}\n\n{issue_body or ''}"
            span.set_attribute("rag.namespace", repository_scope.namespace)

            try:
                query_embedding = self._create_embedding(combined_text)
            except LLMError:
                # Dedup unavailable — proceed without dedup per failure_handling.
                logger.warning(
                    "experience_store.dedup_unavailable",
                    reason="embedding_api_failure",
                )
                return None
            except Exception as exc:
                raise SkillError(
                    f"Failed to create embedding for dedup: {exc}"
                ) from exc

            collection = self._get_collection(repository_scope)
            try:
                results = collection.query(
                    query_embeddings=[query_embedding],
                    n_results=1,
                    where={"namespace": repository_scope.namespace},
                    include=[
                        "documents",
                        "metadatas",
                        "distances",
                        "embeddings",
                    ],
                )
            except Exception as exc:
                raise SkillError(
                    f"Dedup query failed: {type(exc).__name__}"
                ) from exc

            distances = query_result_row(results, "distances")
            metadatas = query_result_row(results, "metadatas")
            documents = query_result_row(results, "documents")
            ids = query_result_row(results, "ids")
            embeddings = query_result_row(results, "embeddings")

            if not distances and not metadatas and not documents and not ids:
                return None
            if (
                len(distances) != 1
                or len(metadatas) != 1
                or len(documents) != 1
                or len(ids) != 1
                or len(embeddings) != 1
            ):
                raise SkillError("RAG backend returned incomplete dedup provenance")

            _, verified_metadata = verify_record(
                record_id=ids[0],
                document=documents[0],
                metadata=metadatas[0],
                scope=repository_scope,
                integrity_key=self._integrity_key,
                now=utc_epoch(self._clock),
            )
            if verified_metadata.get("embedding_sha256") != embedding_sha256(
                embeddings[0]
            ):
                raise SkillError(
                    "RAG record failed closed: embedding digest mismatch"
                )
            pattern_id = verified_metadata.get("pattern_id")
            if not isinstance(pattern_id, str) or not pattern_id:
                raise SkillError("RAG record failed closed: invalid pattern id")
            issue_number, _, _ = _validate_pattern_metadata(
                verified_metadata,
                expected_pattern_id=pattern_id,
            )

            # ChromaDB returns cosine distance; similarity = 1 - distance.
            distance = distances[0]
            if (
                isinstance(distance, bool)
                or not isinstance(distance, Real)
                or not math.isfinite(float(distance))
                or float(distance) < 0.0
                or float(distance) > 2.0
            ):
                raise SkillError("RAG backend returned an invalid cosine distance")
            similarity = cosine_similarity(query_embedding, embeddings[0])
            local_distance = 1.0 - similarity
            if abs(float(distance) - local_distance) > 0.0001:
                raise SkillError(
                    "RAG backend distance is inconsistent with authenticated vectors"
                )
            span.set_attribute("similarity", similarity)

            if similarity >= self.DUPLICATE_SIMILARITY_THRESHOLD:
                logger.info(
                    "experience_store.duplicate_found",
                    similarity=similarity,
                    duplicate_issue_number=issue_number,
                )
                return issue_number

            logger.debug(
                "experience_store.no_duplicate",
                similarity=similarity,
                threshold=self.DUPLICATE_SIMILARITY_THRESHOLD,
            )
            return None
