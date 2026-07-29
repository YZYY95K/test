#!/usr/bin/env python3
"""Verify self-contained GOAI finals presentation semantics without authoring tools."""

from __future__ import annotations

import argparse
import io
import json
import posixpath
import re
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from xml.etree import ElementTree

EXPECTED_PAGES = 12
MAX_PPTX_BYTES = 32 * 1024 * 1024
MAX_PDF_BYTES = 32 * 1024 * 1024
MAX_PPTX_ENTRIES = 2_000
MAX_PPTX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
PPTX_SLIDE = re.compile(r"ppt/slides/slide([1-9][0-9]*)\.xml")
PPTX_NOTES = re.compile(r"ppt/notesSlides/notesSlide([1-9][0-9]*)\.xml")
RELATIONSHIP_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_DOCUMENT_REL = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
)
SLIDE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide"
NOTES_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide"
FORBIDDEN_PPTX_PARTS = (
    "ppt/activeX/",
    "ppt/embeddings/",
    "ppt/externalLinks/",
    "vbaProject.bin",
)
FORBIDDEN_PDF_MARKERS = (
    b"/AcroForm",
    b"/EmbeddedFile",
    b"/Encrypt",
    b"/JavaScript",
    b"/JS",
    b"/Launch",
    b"/OpenAction",
)


class FinalsMaterialError(ValueError):
    """One final presentation artifact violates the semantic release gate."""


@dataclass(frozen=True)
class FinalsMaterialResult:
    pdf_pages: int
    pptx_notes: int
    pptx_slides: int
    sources_notes: int


def _xml(data: bytes, label: str) -> ElementTree.Element:
    try:
        return ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        raise FinalsMaterialError(f"{label} is not valid XML") from exc


def _relationship_source(name: str) -> str | None:
    if name == "_rels/.rels":
        return ""
    marker = "/_rels/"
    if marker not in name or not name.endswith(".rels"):
        return None
    parent, relative = name.split(marker, 1)
    if "/" in relative or not relative[:-5]:
        return None
    return f"{parent}/{relative[:-5]}"


def _relationship_target(source: str, target: str) -> str:
    if (
        not target
        or "\\" in target
        or "?" in target
        or "#" in target
        or ":" in target
        or any(ord(character) < 32 for character in target)
    ):
        raise FinalsMaterialError("finals PPTX relationship target is invalid")
    base = posixpath.dirname(source)
    resolved = posixpath.normpath(
        target.lstrip("/") if target.startswith("/") else posixpath.join(base, target)
    )
    if resolved in {"", ".", ".."} or resolved.startswith("../"):
        raise FinalsMaterialError("finals PPTX relationship escapes the package")
    return resolved


def _relationship_graph(
    archive: zipfile.ZipFile, names: set[str]
) -> dict[str, list[tuple[str, str]]]:
    graph: dict[str, list[tuple[str, str]]] = {}
    for name in sorted(item for item in names if item.endswith(".rels")):
        source = _relationship_source(name)
        if source is None:
            raise FinalsMaterialError("finals PPTX relationship part path is invalid")
        root = _xml(archive.read(name), name)
        if root.tag != f"{{{RELATIONSHIP_NS}}}Relationships":
            raise FinalsMaterialError("finals PPTX relationship root is invalid")
        identifiers: set[str] = set()
        records: list[tuple[str, str]] = []
        for relationship in root:
            if relationship.tag != f"{{{RELATIONSHIP_NS}}}Relationship":
                raise FinalsMaterialError("finals PPTX relationship element is invalid")
            attributes = relationship.attrib
            if set(attributes) - {"Id", "Type", "Target", "TargetMode"}:
                raise FinalsMaterialError("finals PPTX relationship attributes are invalid")
            identifier = attributes.get("Id", "")
            relation_type = attributes.get("Type", "")
            target = attributes.get("Target", "")
            if (
                not identifier
                or identifier in identifiers
                or not relation_type.startswith("http://schemas.openxmlformats.org/")
            ):
                raise FinalsMaterialError("finals PPTX relationship identity is invalid")
            identifiers.add(identifier)
            if attributes.get("TargetMode", "").lower() == "external":
                raise FinalsMaterialError("finals PPTX contains an external relationship")
            resolved = _relationship_target(source, target)
            if resolved not in names:
                raise FinalsMaterialError("finals PPTX relationship target is missing")
            records.append((relation_type, resolved))
        graph[source] = records
    return graph


def _one_target(
    graph: dict[str, list[tuple[str, str]]], source: str, relation_type: str
) -> str:
    targets = [target for kind, target in graph.get(source, []) if kind == relation_type]
    if len(targets) != 1:
        raise FinalsMaterialError("finals PPTX relationship graph is incomplete")
    return targets[0]


def verify_pptx_bytes(data: bytes) -> tuple[int, int, int]:
    """Verify slide/notes counts, Sources notes, and self-contained relationships."""

    if len(data) > MAX_PPTX_BYTES:
        raise FinalsMaterialError("finals PPTX exceeds the byte limit")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            if archive.comment:
                raise FinalsMaterialError("finals PPTX ZIP comment is forbidden")
            infos = archive.infolist()
            if len(infos) > MAX_PPTX_ENTRIES:
                raise FinalsMaterialError("finals PPTX entry limit exceeded")
            name_list = [item.filename for item in infos]
            if len(name_list) != len(set(name_list)):
                raise FinalsMaterialError("finals PPTX contains duplicate ZIP entries")
            names = set(name_list)
            total = 0
            for item in infos:
                total += item.file_size
                if (
                    item.is_dir()
                    or item.flag_bits & 0x1
                    or total > MAX_PPTX_UNCOMPRESSED_BYTES
                ):
                    raise FinalsMaterialError("finals PPTX member policy is invalid")
            if any(
                name.endswith(".bin")
                or any(part in name for part in FORBIDDEN_PPTX_PARTS)
                for name in name_list
            ):
                raise FinalsMaterialError("finals PPTX contains macros or external payload parts")
            slides = sorted(
                int(match.group(1))
                for name in name_list
                if (match := PPTX_SLIDE.fullmatch(name))
            )
            notes = sorted(
                int(match.group(1))
                for name in names
                if (match := PPTX_NOTES.fullmatch(name))
            )
            expected = list(range(1, EXPECTED_PAGES + 1))
            if slides != expected or notes != expected:
                raise FinalsMaterialError("finals PPTX must contain exactly 12 slides and notes")
            source_notes = 0
            for number in notes:
                root = _xml(
                    archive.read(f"ppt/notesSlides/notesSlide{number}.xml"),
                    f"notesSlide{number}",
                )
                text = "".join(root.itertext())
                if "[Sources]" not in text:
                    raise FinalsMaterialError(
                        f"notesSlide{number} does not contain the required [Sources] block"
                    )
                source_notes += 1
            graph = _relationship_graph(archive, names)
            if _one_target(graph, "", OFFICE_DOCUMENT_REL) != "ppt/presentation.xml":
                raise FinalsMaterialError("finals PPTX root does not bind the presentation")
            presentation_slides = {
                target
                for relation_type, target in graph.get("ppt/presentation.xml", [])
                if relation_type == SLIDE_REL
            }
            expected_slides = {f"ppt/slides/slide{number}.xml" for number in expected}
            if presentation_slides != expected_slides:
                raise FinalsMaterialError("finals PPTX presentation slide graph is incomplete")
            for number in expected:
                slide = f"ppt/slides/slide{number}.xml"
                note = f"ppt/notesSlides/notesSlide{number}.xml"
                if _one_target(graph, slide, NOTES_REL) != note:
                    raise FinalsMaterialError("finals PPTX slide-to-notes binding is invalid")
                if _one_target(graph, note, SLIDE_REL) != slide:
                    raise FinalsMaterialError("finals PPTX notes-to-slide binding is invalid")
            content_types = archive.read("[Content_Types].xml")
            if b"macroEnabled" in content_types or b"application/vnd.ms-office.vbaProject" in (
                content_types
            ):
                raise FinalsMaterialError("finals PPTX declares macro-enabled content")
    except (KeyError, zipfile.BadZipFile) as exc:
        raise FinalsMaterialError("finals PPTX is missing required package parts") from exc
    return len(slides), len(notes), source_notes


def verify_pdf_bytes(data: bytes) -> int:
    """Parse a bounded PDF and reject active object-tree features."""

    if len(data) > MAX_PDF_BYTES or not data.startswith(b"%PDF-"):
        raise FinalsMaterialError("finals PDF header or byte limit is invalid")
    if b"%%EOF" not in data[-1024:]:
        raise FinalsMaterialError("finals PDF trailer is missing")
    if any(marker in data for marker in FORBIDDEN_PDF_MARKERS):
        raise FinalsMaterialError("finals PDF is encrypted, interactive, or executable")
    try:
        from pypdf import PdfReader
        from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject
    except ImportError as exc:  # pragma: no cover - release environment invariant
        raise FinalsMaterialError("hash-locked PDF parser is unavailable") from exc
    try:
        reader = PdfReader(io.BytesIO(data), strict=True)
        if reader.is_encrypted:
            raise FinalsMaterialError("finals PDF is encrypted, interactive, or executable")
        pages = len(reader.pages)
        root = reader.trailer["/Root"]
        stack: list[object] = [root, *reader.pages]
        visited: set[tuple[int, int]] = set()
        examined = 0
        forbidden_keys = {
            "/AA",
            "/AcroForm",
            "/EmbeddedFile",
            "/EmbeddedFiles",
            "/JavaScript",
            "/JS",
            "/OpenAction",
        }
        forbidden_names = {"/JavaScript", "/Launch"}
        while stack:
            current = stack.pop()
            if isinstance(current, IndirectObject):
                identity = (current.idnum, current.generation)
                if identity in visited:
                    continue
                visited.add(identity)
                current = current.get_object()
            examined += 1
            if examined > 100_000:
                raise FinalsMaterialError("finals PDF object graph limit exceeded")
            if isinstance(current, DictionaryObject):
                for key, value in current.items():
                    if str(key) in forbidden_keys:
                        raise FinalsMaterialError(
                            "finals PDF is encrypted, interactive, or executable"
                        )
                    stack.append(value)
            elif isinstance(current, ArrayObject):
                stack.extend(current)
            elif isinstance(current, NameObject) and str(current) in forbidden_names:
                raise FinalsMaterialError("finals PDF is encrypted, interactive, or executable")
    except FinalsMaterialError:
        raise
    except Exception as exc:
        raise FinalsMaterialError("finals PDF object graph is invalid") from exc
    if pages != EXPECTED_PAGES:
        raise FinalsMaterialError("finals PDF must contain exactly 12 pages")
    return pages


def verify_material_bytes(pptx: bytes, pdf: bytes) -> FinalsMaterialResult:
    """Verify both final artifacts and return their common semantic dimensions."""

    slides, notes, sources = verify_pptx_bytes(pptx)
    pages = verify_pdf_bytes(pdf)
    if slides != pages:
        raise FinalsMaterialError("finals PPTX and PDF page counts differ")
    return FinalsMaterialResult(
        pdf_pages=pages,
        pptx_notes=notes,
        pptx_slides=slides,
        sources_notes=sources,
    )


def _regular_bytes(path: Path, limit: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise FinalsMaterialError(f"{label} is missing") from exc
    if path.is_symlink() or not path.is_file() or metadata.st_size > limit:
        raise FinalsMaterialError(f"{label} must be one bounded regular file")
    return path.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pptx", required=True, type=Path)
    parser.add_argument("--pdf", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        result = verify_material_bytes(
            _regular_bytes(arguments.pptx, MAX_PPTX_BYTES, "finals PPTX"),
            _regular_bytes(arguments.pdf, MAX_PDF_BYTES, "finals PDF"),
        )
    except FinalsMaterialError as exc:
        print(json.dumps({"error": str(exc), "ok": False}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, **asdict(result)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
