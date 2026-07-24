"""Codebase indexer for retrieval-augmented generation (RAG).

Indexes repository code into a ChromaDB vector store, chunking files by
function/class boundaries so that downstream retrieval returns semantically
meaningful code regions rather than arbitrary line windows.

The indexer is decoupled from the file source via a ``FileFetcher`` callable:
the caller decides whether files come from the GitHub API, a local clone, or
a test fixture. Embeddings are produced via an OpenAI-compatible endpoint
(``embedding-3`` by default).
"""

from __future__ import annotations

import ast
import os
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Any, Protocol

from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from devflow.exceptions import LLMError, SkillError
from devflow.observability import logger, metrics, tracer
from devflow.rag.embeddings import EmbeddingProvider, build_embedding_provider

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


class FileFetcher(Protocol):
    """Callable that retrieves file contents for a repository.

    Implementations may wrap the GitHub MCP ``get_file_contents`` tool,
    a local filesystem walk, or any other source.
    """

    def __call__(
        self, repo_owner: str, repo_name: str
    ) -> Awaitable[list[tuple[str, str]]]:
        """Return a list of ``(file_path, file_content)`` tuples."""
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
    them alongside chunk metadata so that LocatorAgent can query for relevant
    code regions by natural-language description.
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
        self._file_fetcher = file_fetcher
        self._client: Any | None = None
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

    def _get_collection(self) -> Any:
        """Lazily create or retrieve the codebase index collection."""
        if self._collection is None:
            client = self._get_chroma_client()
            self._collection = client.get_or_create_collection(
                name=self.COLLECTION_NAME,
                metadata={"description": "Codebase chunks for RAG retrieval"},
            )
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
                f"Embedding API call failed: {exc}"
            ) from exc

    # -- public API ---------------------------------------------------------

    async def index_repository(
        self, repo_owner: str, repo_name: str
    ) -> int:
        """Index all source files in a repository into ChromaDB.

        Args:
            repo_owner: GitHub repository owner (user or org).
            repo_name: GitHub repository name.

        Returns:
            Number of code chunks indexed.

        Raises:
            SkillError: If no file fetcher is configured or indexing fails.
        """
        with tracer.start_as_current_span("codebase_indexer.index_repository") as span:
            span.set_attribute("repo.owner", repo_owner)
            span.set_attribute("repo.name", repo_name)

            if self._file_fetcher is None:
                raise SkillError(
                    "No file_fetcher configured. Pass a FileFetcher to "
                    "CodebaseIndexer.__init__ to enable repository indexing."
                )

            logger.info(
                "codebase_indexer.indexing_started",
                repo_owner=repo_owner,
                repo_name=repo_name,
            )

            try:
                files = await self._file_fetcher(repo_owner, repo_name)
            except Exception as exc:
                raise SkillError(
                    f"File fetcher failed for {repo_owner}/{repo_name}: {exc}"
                ) from exc

            all_chunks: list[CodeChunk] = []
            for file_path, content in files:
                if _should_ignore(file_path):
                    continue
                if not content or not content.strip():
                    continue
                chunks = _chunk_file(file_path, content)
                all_chunks.extend(chunks)

            if not all_chunks:
                logger.warning(
                    "codebase_indexer.no_chunks",
                    repo_owner=repo_owner,
                    repo_name=repo_name,
                )
                metrics.record(
                    name="devflow_codebase_chunks_indexed",
                    value=0,
                    unit="count",
                    tags={"repo": f"{repo_owner}/{repo_name}"},
                )
                return 0

            # Batch embedding (ChromaDB has a batch limit; embed in groups).
            batch_size = 100
            collection = self._get_collection()

            for i in range(0, len(all_chunks), batch_size):
                batch = all_chunks[i : i + batch_size]
                texts = [chunk.content for chunk in batch]
                embeddings = self._create_embeddings(texts)

                ids = [
                    f"{chunk.file_path}:{chunk.start_line}:{chunk.end_line}"
                    for chunk in batch
                ]
                metadatas = [
                    {
                        "file_path": chunk.file_path,
                        "start_line": chunk.start_line,
                        "end_line": chunk.end_line,
                        "language": chunk.language,
                    }
                    for chunk in batch
                ]

                collection.add(
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
                tags={"repo": f"{repo_owner}/{repo_name}"},
            )
            logger.info(
                "codebase_indexer.indexing_complete",
                repo_owner=repo_owner,
                repo_name=repo_name,
                chunks_indexed=len(all_chunks),
            )
            return len(all_chunks)

    async def search(self, query: str, top_k: int = 5) -> list[CodeChunk]:
        """Search the codebase index for chunks relevant to *query*.

        Args:
            query: Natural-language query describing the code of interest.
            top_k: Maximum number of chunks to return.

        Returns:
            List of :class:`CodeChunk` objects ranked by relevance.

        Raises:
            SkillError: If the search fails.
        """
        with tracer.start_as_current_span("codebase_indexer.search") as span:
            span.set_attribute("query_length", len(query))
            span.set_attribute("top_k", top_k)

            try:
                query_embedding = self._create_embeddings([query])[0]
            except LLMError:
                raise
            except Exception as exc:
                raise SkillError(f"Failed to create query embedding: {exc}") from exc

            collection = self._get_collection()
            try:
                results = collection.query(
                    query_embeddings=[query_embedding],
                    n_results=top_k,
                )
            except Exception as exc:
                raise SkillError(f"ChromaDB query failed: {exc}") from exc

            chunks: list[CodeChunk] = []
            documents = results.get("documents", [[]])
            metadatas = results.get("metadatas", [[]])

            if documents and documents[0]:
                for doc, meta in zip(
                    documents[0],
                    metadatas[0] if metadatas else [],
                    strict=False,
                ):
                    chunks.append(
                        CodeChunk(
                            file_path=meta.get("file_path", "unknown"),
                            start_line=meta.get("start_line", 1),
                            end_line=meta.get("end_line", 1),
                            content=doc,
                            language=meta.get("language", "text"),
                        )
                    )

            span.set_attribute("results_count", len(chunks))
            logger.debug(
                "codebase_indexer.search_complete",
                query=query[:100],
                results=len(chunks),
            )
            return chunks
