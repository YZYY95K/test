"""Retrieval-augmented generation (RAG) layer for DevFlow.

This package provides the vector-store-backed components that power
codebase retrieval (LocatorAgent) and experience pattern storage /
deduplication (TriageAgent and the experience distiller).

Two stores are exposed:

* :class:`CodebaseIndexer` — indexes repository source code into ChromaDB
  for semantic search by the ``code-root-cause`` skill.
* :class:`ExperienceStore` — stores and retrieves distilled fix patterns
  for deduplication and few-shot example generation.
"""

from devflow.rag.codebase_indexer import (
    CodebaseIndexer,
    CodeChunk,
    FileFetcher,
)
from devflow.rag.experience_store import ExperiencePattern, ExperienceStore
from devflow.rag.scope import RepositoryScope

__all__ = [
    "CodeChunk",
    "CodebaseIndexer",
    "FileFetcher",
    "ExperiencePattern",
    "ExperienceStore",
    "RepositoryScope",
]
