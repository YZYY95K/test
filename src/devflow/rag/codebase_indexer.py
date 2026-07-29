"""Codebase indexer for retrieval-augmented generation (RAG).

Indexes repository code into a ChromaDB vector store, chunking files by
function/class boundaries so that downstream retrieval returns semantically
meaningful code regions rather than arbitrary line windows.

The indexer is decoupled from the file source via a ``FileFetcher`` callable:
the caller decides whether files come from the GitHub API, a local clone, or
a test fixture. Embeddings are produced via an OpenAI-compatible endpoint
(``embedding-3`` by default).

Every operation is bound to one tenant, canonical repository identity, and
immutable Git object id. Records live in a scope-specific collection, carry
expiry metadata, and are authenticated (including the stored vector) before
they are released to an agent.
"""

from __future__ import annotations

import ast
import hashlib
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from devflow.exceptions import LLMError, SkillError
from devflow.models.patch import canonical_repository_path
from devflow.observability import logger, metrics, tracer
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
    verify_record,
)

# ---------------------------------------------------------------------------
# Public models
# ---------------------------------------------------------------------------


@dataclass
class CodeChunk:
    """A semantically coherent chunk of source code.

    Attributes:
        file_path: Repository-relative path of the source file.
        start_line: 1-based line number where the chunk begins.
        end_line: 1-based line number where the chunk ends (inclusive).
        content: Raw source text of the chunk.
        language: Programming language identifier (e.g. ``"python"``).
    """

    file_path: str
    start_line: int
    end_line: int
    content: str
    language: str
    tenant_id: str = ""
    repository_id: str = ""
    repository_revision: str = ""
    namespace: str = ""
    record_hmac_sha256: str = ""
    similarity: float = 0.0


class FileFetcher(Protocol):
    """Callable that retrieves file contents for a repository.

    Implementations may wrap the GitHub MCP ``get_file_contents`` tool,
    a local filesystem walk, or any other source.
    """

    def __call__(
        self, repo_owner: str, repo_name: str, exact_revision: str
    ) -> Awaitable[list[tuple[str, str]]]:
        """Return files fetched from the exact immutable revision."""
        ...


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

#: Mapping of file extension -> language identifier.
_LANGUAGE_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".md": "markdown",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
    ".scss": "scss",
    ".toml": "toml",
    ".xml": "xml",
}

#: Files / directories to skip during indexing.
_IGNORE_PATTERNS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".tox",
        ".eggs",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    }
)

#: Maximum lines per generic (non-Python) chunk.
_MAX_GENERIC_CHUNK_LINES = 80


def _detect_language(file_path: str) -> str:
    """Infer the programming language from a file's extension."""
    _, ext = os.path.splitext(file_path)
    return _LANGUAGE_MAP.get(ext, "text")


def _should_ignore(file_path: str) -> bool:
    """Return ``True`` if *file_path* matches an ignore pattern."""
    parts = file_path.replace("\\", "/").split("/")
    return any(part in _IGNORE_PATTERNS for part in parts)


def _chunk_python_file(content: str, file_path: str) -> list[CodeChunk]:
    """Chunk a Python source file by top-level function and class definitions.

    Falls back to a single whole-file chunk if parsing fails.
    """
    try:
        tree = ast.parse(content)
    except SyntaxError:
        logger.warning("codebase_indexer.syntax_error", file_path=file_path)
        return [
            CodeChunk(
                file_path=file_path,
                start_line=1,
                end_line=len(content.splitlines()) or 1,
                content=content,
                language="python",
            )
        ]

    lines = content.splitlines(keepends=True)
    total_lines = len(lines)
    chunks: list[CodeChunk] = []

    # Collect top-level definitions (functions, async functions, classes).
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = node.lineno
            end = node.end_lineno or start
            # Clamp to file bounds.
            end = min(end, total_lines)
            chunk_content = "".join(lines[start - 1 : end])
            if chunk_content.strip():
                chunks.append(
                    CodeChunk(
                        file_path=file_path,
                        start_line=start,
                        end_line=end,
                        content=chunk_content,
                        language="python",
                    )
                )

    # If no definitions were found, index the whole file as one chunk.
    if not chunks and content.strip():
        chunks.append(
            CodeChunk(
                file_path=file_path,
                start_line=1,
                end_line=total_lines or 1,
                content=content,
                language="python",
            )
        )

    return chunks


def _chunk_generic_file(
    content: str, file_path: str, language: str
) -> list[CodeChunk]:
    """Chunk a non-Python file by fixed-size line windows."""
    lines = content.splitlines(keepends=True)
    if not lines:
        return []

    chunks: list[CodeChunk] = []
    for i in range(0, len(lines), _MAX_GENERIC_CHUNK_LINES):
        window = lines[i : i + _MAX_GENERIC_CHUNK_LINES]
        chunk_content = "".join(window)
        if chunk_content.strip():
            chunks.append(
                CodeChunk(
                    file_path=file_path,
                    start_line=i + 1,
                    end_line=i + len(window),
                    content=chunk_content,
                    language=language,
                )
            )
    return chunks


def _chunk_file(file_path: str, content: str) -> list[CodeChunk]:
    """Dispatch to the appropriate chunker based on file language."""
    language = _detect_language(file_path)
    if language == "python":
        return _chunk_python_file(content, file_path)
    return _chunk_generic_file(content, file_path, language)


# ---------------------------------------------------------------------------
# CodebaseIndexer
# ---------------------------------------------------------------------------


class CodebaseIndexer:
    """Indexes repository source code into ChromaDB for RAG retrieval.

    The indexer computes embeddings via an OpenAI-compatible API and stores
    them alongside authenticated chunk metadata so that LocatorAgent can
    query an exact repository revision without cross-tenant fallback.
    """

    COLLECTION_NAME = "codebase_index"
    EMBEDDING_MODEL = "embedding-3"
    EMBEDDING_DIMENSION = 2048

    def __init__(
        self,
        persist_path: str | None = None,
        embedding_api_key: str | None = None,
        embedding_base_url: str | None = None,
        file_fetcher: FileFetcher | None = None,
        scope: RepositoryScope | None = None,
        record_ttl_seconds: int = 2_592_000,
        clock: Callable[[], float] = time.time,
        integrity_key: bytes | None = None,
    ) -> None:
        """Initialize the codebase indexer.

        Args:
            persist_path: Filesystem path for the ChromaDB persistent directory.
                Defaults to the ``CHROMADB_PATH`` env var, or ``.devflow/chromadb``.
            embedding_api_key: API key for the embeddings endpoint.
                Defaults to ``LLM_API_KEY`` env var.
            embedding_base_url: Base URL for the embeddings endpoint.
                Defaults to ``LLM_BASE_URL`` env var.
            file_fetcher: Callable that retrieves ``(path, content)`` pairs
                for a repository. Required for ``index_repository``.
            scope: Optional repository scope bound for this indexer instance.
            record_ttl_seconds: Lifetime of indexed records before retrieval fails.
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
        self._file_fetcher = file_fetcher
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
                "codebase_indexer.chroma_initialized", path=self._persist_path
            )
        return self._client

    @staticmethod
    def _collection_name(scope: RepositoryScope) -> str:
        return f"{CodebaseIndexer.COLLECTION_NAME}_{scope.namespace.removeprefix('rag-v1:')}"

    def _get_collection(self, scope: RepositoryScope) -> Any:
        """Lazily create a physically scoped codebase collection."""
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
                    "description": "Exact-revision codebase chunks for RAG",
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
    def _create_embeddings(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for a batch of texts.

        Args:
            texts: List of source code strings to embed.

        Returns:
            List of embedding vectors, one per input text.

        Raises:
            LLMError: If the embedding API call fails after retries.
        """
        try:
            return self._get_embedding_provider().embed(texts)
        except Exception as exc:
            if isinstance(exc, LLMError):
                raise
            raise LLMError(
                f"Embedding API call failed: {type(exc).__name__}"
            ) from exc

    # -- public API ---------------------------------------------------------

    async def index_repository(self, scope: RepositoryScope | None = None) -> int:
        """Index all source files in a repository into ChromaDB.

        Args:
            scope: Tenant, repository, and exact immutable revision. This may
                be omitted only when the indexer was constructed with a scope.

        Returns:
            Number of code chunks indexed.

        Raises:
            SkillError: If no file fetcher is configured or indexing fails.
        """
        repository_scope = resolve_scope(scope, self._scope)
        with tracer.start_as_current_span("codebase_indexer.index_repository") as span:
            span.set_attribute("repo.owner", repository_scope.repo_owner)
            span.set_attribute("repo.name", repository_scope.repo_name)
            span.set_attribute("repo.revision", repository_scope.revision)
            span.set_attribute("rag.namespace", repository_scope.namespace)

            if self._file_fetcher is None:
                raise SkillError(
                    "No file_fetcher configured. Pass a FileFetcher to "
                    "CodebaseIndexer.__init__ to enable repository indexing."
                )

            logger.info(
                "codebase_indexer.indexing_started",
                repo_owner=repository_scope.repo_owner,
                repo_name=repository_scope.repo_name,
                repository_revision=repository_scope.revision,
            )

            try:
                files = await self._file_fetcher(
                    repository_scope.repo_owner,
                    repository_scope.repo_name,
                    repository_scope.revision,
                )
            except Exception as exc:
                raise SkillError(
                    f"File fetcher failed for {repository_scope.repository_id}: "
                    f"{type(exc).__name__}"
                ) from exc

            all_chunks: list[CodeChunk] = []
            seen_paths: set[str] = set()
            for file_path, content in files:
                try:
                    canonical_path = canonical_repository_path(file_path)
                except (TypeError, ValueError) as exc:
                    raise SkillError(
                        "File fetcher returned a non-canonical repository path"
                    ) from exc
                if canonical_path in seen_paths:
                    raise SkillError(
                        "File fetcher returned duplicate repository paths"
                    )
                seen_paths.add(canonical_path)
                if not isinstance(content, str):
                    raise SkillError("File fetcher returned non-text file content")
                if _should_ignore(canonical_path):
                    continue
                if not content or not content.strip():
                    continue
                chunks = _chunk_file(canonical_path, content)
                all_chunks.extend(chunks)

            if not all_chunks:
                logger.warning(
                    "codebase_indexer.no_chunks",
                    repo_owner=repository_scope.repo_owner,
                    repo_name=repository_scope.repo_name,
                )
                metrics.record(
                    name="devflow_codebase_chunks_indexed",
                    value=0,
                    unit="count",
                    tags={"repo": repository_scope.repository_id},
                )
                return 0

            # Batch embedding (ChromaDB has a batch limit; embed in groups).
            batch_size = 100
            collection = self._get_collection(repository_scope)
            indexed_at = utc_epoch(self._clock)

            for i in range(0, len(all_chunks), batch_size):
                batch = all_chunks[i : i + batch_size]
                texts = [chunk.content for chunk in batch]
                embeddings = self._create_embeddings(texts)

                ids = [
                    "code:"
                    f"{repository_scope.namespace}:"
                    + hashlib.sha256(
                        (
                            f"{chunk.file_path}\0{chunk.start_line}\0"
                            f"{chunk.end_line}\0{chunk.content}"
                        ).encode()
                    ).hexdigest()
                    for chunk in batch
                ]
                metadatas = []
                for record_id, chunk, embedding in zip(
                    ids,
                    batch,
                    embeddings,
                    strict=True,
                ):
                    metadata = {
                        **repository_scope.metadata(
                            now=indexed_at,
                            ttl_seconds=self._record_ttl_seconds,
                        ),
                        "file_path": chunk.file_path,
                        "start_line": chunk.start_line,
                        "end_line": chunk.end_line,
                        "language": chunk.language,
                        "content_sha256": hashlib.sha256(
                            chunk.content.encode("utf-8")
                        ).hexdigest(),
                        "embedding_sha256": embedding_sha256(embedding),
                    }
                    metadatas.append(
                        seal_record(
                            record_id=record_id,
                            document=chunk.content,
                            metadata=metadata,
                            integrity_key=self._integrity_key,
                        )
                    )

                collection.upsert(
                    ids=ids,
                    embeddings=embeddings,
                    documents=texts,
                    metadatas=metadatas,
                )

            span.set_attribute("chunks_indexed", len(all_chunks))
            metrics.record(
                name="devflow_codebase_chunks_indexed",
                value=len(all_chunks),
                unit="count",
                tags={"repo": repository_scope.repository_id},
            )
            logger.info(
                "codebase_indexer.indexing_complete",
                repo_owner=repository_scope.repo_owner,
                repo_name=repository_scope.repo_name,
                repository_revision=repository_scope.revision,
                chunks_indexed=len(all_chunks),
            )
            return len(all_chunks)

    async def search(
        self,
        query: str,
        top_k: int = 5,
        *,
        scope: RepositoryScope | None = None,
    ) -> list[CodeChunk]:
        """Search the codebase index for chunks relevant to *query*.

        Args:
            query: Natural-language query describing the code of interest.
            top_k: Maximum number of chunks to return.
            scope: Exact RAG scope. This may be omitted only when the indexer
                was constructed with a scope.

        Returns:
            List of :class:`CodeChunk` objects ranked by relevance.

        Raises:
            SkillError: If the search fails.
        """
        repository_scope = resolve_scope(scope, self._scope)
        if not isinstance(query, str) or not query.strip():
            raise SkillError("RAG search query must be non-empty text")
        if (
            not isinstance(top_k, int)
            or isinstance(top_k, bool)
            or top_k < 1
            or top_k > 100
        ):
            raise SkillError("RAG top_k must be between 1 and 100")
        with tracer.start_as_current_span("codebase_indexer.search") as span:
            span.set_attribute("query_length", len(query))
            span.set_attribute("top_k", top_k)
            span.set_attribute("rag.namespace", repository_scope.namespace)

            try:
                query_embedding = self._create_embeddings([query])[0]
            except LLMError:
                raise
            except Exception as exc:
                raise SkillError(f"Failed to create query embedding: {exc}") from exc

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

            chunks: list[CodeChunk] = []
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
                content_digest = verified_meta.get("content_sha256")
                if (
                    not isinstance(content_digest, str)
                    or content_digest
                    != hashlib.sha256(verified_doc.encode("utf-8")).hexdigest()
                ):
                    raise SkillError(
                        "RAG record failed closed: content digest mismatch"
                    )
                file_path = verified_meta.get("file_path")
                start_line = verified_meta.get("start_line")
                end_line = verified_meta.get("end_line")
                language = verified_meta.get("language")
                if not isinstance(file_path, str):
                    raise SkillError(
                        "RAG record failed closed: invalid repository path"
                    )
                try:
                    canonical_path = canonical_repository_path(file_path)
                except (TypeError, ValueError) as exc:
                    raise SkillError(
                        "RAG record failed closed: invalid repository path"
                    ) from exc
                if (
                    not isinstance(start_line, int)
                    or isinstance(start_line, bool)
                    or not isinstance(end_line, int)
                    or isinstance(end_line, bool)
                    or start_line < 1
                    or end_line < start_line
                    or not isinstance(language, str)
                    or not language
                ):
                    raise SkillError(
                        "RAG record failed closed: invalid code chunk metadata"
                    )
                chunks.append(
                    CodeChunk(
                        file_path=canonical_path,
                        start_line=start_line,
                        end_line=end_line,
                        content=verified_doc,
                        language=language,
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

            chunks.sort(
                key=lambda chunk: (
                    -chunk.similarity,
                    chunk.file_path,
                    chunk.start_line,
                )
            )
            span.set_attribute("results_count", len(chunks))
            logger.debug(
                "codebase_indexer.search_complete",
                query_sha256=hashlib.sha256(query.encode("utf-8")).hexdigest(),
                results=len(chunks),
            )
            return chunks
