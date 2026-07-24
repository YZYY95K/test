"""Experience store for reusable fix-pattern persistence and retrieval.

Stores distilled fix patterns in ChromaDB with semantic embeddings so that
future issues can be matched against historical solutions. This powers the
deduplication lookup in :class:`IssueClassifierSkill` and the few-shot example
generation for :class:`PatchGeneratorSkill`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import chromadb
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from devflow.exceptions import LLMError, SkillError
from devflow.observability import logger, tracer

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


# ---------------------------------------------------------------------------
# ExperienceStore
# ---------------------------------------------------------------------------


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
    ) -> None:
        """Initialize the experience store.

        Args:
            persist_path: Filesystem path for the ChromaDB persistent directory.
                Defaults to the ``CHROMADB_PATH`` env var, or ``.devflow/chromadb``.
            embedding_api_key: API key for the embeddings endpoint.
                Defaults to ``LLM_API_KEY`` env var.
            embedding_base_url: Base URL for the embeddings endpoint.
                Defaults to ``LLM_BASE_URL`` env var.
        """
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
        self._client: chromadb.api.ClientAPI | None = None
        self._collection: chromadb.api.Collection | None = None
        self._embedding_client: Any | None = None

    # -- lazy initialization ------------------------------------------------

    def _get_chroma_client(self) -> chromadb.api.ClientAPI:
        """Lazily create the ChromaDB persistent client."""
        if self._client is None:
            os.makedirs(self._persist_path, exist_ok=True)
            self._client = chromadb.PersistentClient(path=self._persist_path)
            logger.info(
                "experience_store.chroma_initialized", path=self._persist_path
            )
        return self._client

    def _get_collection(self) -> chromadb.api.Collection:
        """Lazily create or retrieve the experience store collection."""
        if self._collection is None:
            client = self._get_chroma_client()
            self._collection = client.get_or_create_collection(
                name=self.COLLECTION_NAME,
                metadata={"description": "Distilled fix patterns for dedup and few-shot"},
            )
        return self._collection

    def _get_embedding_client(self) -> Any:
        """Lazily create the OpenAI-compatible embeddings client."""
        if self._embedding_client is None:
            from openai import OpenAI

            self._embedding_client = OpenAI(
                api_key=self._embedding_api_key,
                base_url=self._embedding_base_url,
            )
        return self._embedding_client

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
        client = self._get_embedding_client()
        try:
            response = client.embeddings.create(
                model=self._embedding_model,
                input=text,
            )
            return list(response.data[0].embedding)
        except Exception as exc:
            raise LLMError(f"Embedding API call failed: {exc}") from exc

    # -- public API ---------------------------------------------------------

    async def store(
        self,
        pattern_id: str,
        summary: str,
        metadata: dict[str, Any],
    ) -> None:
        """Store a fix pattern with its embedding in ChromaDB.

        Args:
            pattern_id: Unique identifier for the pattern. If it already
                exists, it is upserted (updated in place).
            summary: Human-readable pattern summary to embed and store.
            metadata: Additional metadata (e.g. ``issue_number``, ``tier``,
                ``root_cause_file``).

        Raises:
            SkillError: If storage fails.
        """
        with tracer.start_as_current_span("experience_store.store") as span:
            span.set_attribute("pattern_id", pattern_id)

            try:
                embedding = self._create_embedding(summary)
            except LLMError:
                raise
            except Exception as exc:
                raise SkillError(
                    f"Failed to create embedding for pattern {pattern_id}: {exc}"
                ) from exc

            collection = self._get_collection()
            try:
                collection.upsert(
                    ids=[pattern_id],
                    embeddings=[embedding],
                    documents=[summary],
                    metadatas=[metadata],
                )
            except Exception as exc:
                raise SkillError(
                    f"Failed to store pattern {pattern_id}: {exc}"
                ) from exc

            logger.info(
                "experience_store.pattern_stored",
                pattern_id=pattern_id,
                issue_number=metadata.get("issue_number"),
            )

    async def search(
        self, query: str, top_k: int = 5
    ) -> list[ExperiencePattern]:
        """Search the experience store for patterns matching *query*.

        Args:
            query: Natural-language query (typically an issue title + body).
            top_k: Maximum number of patterns to return.

        Returns:
            List of :class:`ExperiencePattern` ranked by relevance.

        Raises:
            SkillError: If the search fails.
        """
        with tracer.start_as_current_span("experience_store.search") as span:
            span.set_attribute("query_length", len(query))
            span.set_attribute("top_k", top_k)

            try:
                query_embedding = self._create_embedding(query)
            except LLMError:
                raise
            except Exception as exc:
                raise SkillError(
                    f"Failed to create query embedding: {exc}"
                ) from exc

            collection = self._get_collection()
            try:
                results = collection.query(
                    query_embeddings=[query_embedding],
                    n_results=top_k,
                )
            except Exception as exc:
                raise SkillError(f"ChromaDB query failed: {exc}") from exc

            patterns: list[ExperiencePattern] = []
            documents = results.get("documents", [[]])
            metadatas = results.get("metadatas", [[]])

            if documents and documents[0]:
                for doc, meta in zip(
                    documents[0],
                    metadatas[0] if metadatas else [{}] * len(documents[0]),
                    strict=False,
                ):
                    patterns.append(
                        ExperiencePattern(
                            pattern_id=meta.get("pattern_id", ""),
                            summary=doc,
                            issue_number=meta.get("issue_number", 0),
                            tier=meta.get("tier", ""),
                            root_cause_file=meta.get("root_cause_file", ""),
                        )
                    )

            span.set_attribute("results_count", len(patterns))
            logger.debug(
                "experience_store.search_complete",
                query=query[:100],
                results=len(patterns),
            )
            return patterns

    async def find_duplicate(
        self, issue_title: str, issue_body: str
    ) -> int | None:
        """Check whether an issue is a duplicate of a previously stored pattern.

        Computes the embedding of the issue title + body and queries the store
        for the closest match. If the cosine similarity exceeds
        :attr:`DUPLICATE_SIMILARITY_THRESHOLD`, the matching issue number is
        returned.

        Args:
            issue_title: Title of the issue to check.
            issue_body: Body of the issue to check.

        Returns:
            The issue number of the duplicate pattern, or ``None`` if no
            sufficiently similar pattern exists.

        Raises:
            SkillError: If the deduplication query fails.
        """
        with tracer.start_as_current_span("experience_store.find_duplicate") as span:
            combined_text = f"{issue_title}\n\n{issue_body or ''}"

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

            collection = self._get_collection()
            try:
                results = collection.query(
                    query_embeddings=[query_embedding],
                    n_results=1,
                )
            except Exception as exc:
                raise SkillError(f"Dedup query failed: {exc}") from exc

            distances = results.get("distances", [[]])
            metadatas = results.get("metadatas", [[]])

            if not distances or not distances[0] or not metadatas or not metadatas[0]:
                return None

            # ChromaDB returns cosine distance; similarity = 1 - distance.
            distance = distances[0][0]
            similarity = 1.0 - distance
            span.set_attribute("similarity", similarity)

            if similarity >= self.DUPLICATE_SIMILARITY_THRESHOLD:
                issue_number = metadatas[0][0].get("issue_number")
                logger.info(
                    "experience_store.duplicate_found",
                    similarity=similarity,
                    duplicate_issue_number=issue_number,
                )
                return int(issue_number) if issue_number else None

            logger.debug(
                "experience_store.no_duplicate",
                similarity=similarity,
                threshold=self.DUPLICATE_SIMILARITY_THRESHOLD,
            )
            return None
