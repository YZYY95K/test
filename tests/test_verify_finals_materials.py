from __future__ import annotations

import io
import zipfile

import pytest

from scripts.verify_finals_materials import (
    FinalsMaterialError,
    FinalsMaterialResult,
    verify_material_bytes,
    verify_pdf_bytes,
    verify_pptx_bytes,
)


def _pptx(*, source_notes: int = 12, external: bool = False, macro: bool = False) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("ppt/presentation.xml", "<presentation/>")
        relationships = "http://schemas.openxmlformats.org/package/2006/relationships"
        office = (
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
        )
        for number in range(1, 13):
            archive.writestr(
                f"ppt/slides/slide{number}.xml",
                f"<slide><text>Slide {number}</text></slide>",
            )
            source = "[Sources]" if number <= source_notes else "References"
            archive.writestr(
                f"ppt/notesSlides/notesSlide{number}.xml",
                f"<notes><text>{source} fixture {number}</text></notes>",
            )
            archive.writestr(
                f"ppt/slides/_rels/slide{number}.xml.rels",
                f'<Relationships xmlns="{relationships}">'
                f'<Relationship Id="rId1" Type="{office}notesSlide" '
                f'Target="../notesSlides/notesSlide{number}.xml"/>'
                "</Relationships>",
            )
            archive.writestr(
                f"ppt/notesSlides/_rels/notesSlide{number}.xml.rels",
                f'<Relationships xmlns="{relationships}">'
                f'<Relationship Id="rId1" Type="{office}slide" '
                f'Target="../slides/slide{number}.xml"/>'
                "</Relationships>",
            )
        target_mode = ' TargetMode="External"' if external else ""
        archive.writestr(
            "_rels/.rels",
            (
                f'<Relationships xmlns="{relationships}">'
                f'<Relationship Id="rId1" Type="{office}officeDocument" '
                f'Target="ppt/presentation.xml"{target_mode}/>'
                "</Relationships>"
            ),
        )
        slide_relationships = "".join(
            f'<Relationship Id="rId{number}" Type="{office}slide" '
            f'Target="slides/slide{number}.xml"/>'
            for number in range(1, 13)
        )
        archive.writestr(
            "ppt/_rels/presentation.xml.rels",
            f'<Relationships xmlns="{relationships}">{slide_relationships}</Relationships>',
        )
        if macro:
            archive.writestr("ppt/vbaProject.bin", b"macro")
    return output.getvalue()


def _pdf(*, pages: int = 12, extra: bytes = b"") -> bytes:
    from pypdf import PdfWriter

    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=100, height=100)
    output = io.BytesIO()
    writer.write(output)
    data = output.getvalue()
    if extra:
        data = data.replace(b"%%EOF", extra + b"\n%%EOF")
    return data


def test_final_materials_semantic_gate_accepts_twelve_static_pages() -> None:
    assert verify_material_bytes(_pptx(), _pdf()) == FinalsMaterialResult(
        pdf_pages=12,
        pptx_notes=12,
        pptx_slides=12,
        sources_notes=12,
    )


def test_pptx_requires_sources_in_every_notes_page() -> None:
    with pytest.raises(FinalsMaterialError, match=r"notesSlide12.*\[Sources\]"):
        verify_pptx_bytes(_pptx(source_notes=11))


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (_pptx(external=True), "external relationship"),
        (_pptx(macro=True), "macros or external payload"),
    ],
)
def test_pptx_rejects_external_relationships_and_macros(data: bytes, message: str) -> None:
    with pytest.raises(FinalsMaterialError, match=message):
        verify_pptx_bytes(data)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (_pdf(pages=11), "exactly 12"),
        (_pdf(extra=b"/Encrypt"), "encrypted, interactive, or executable"),
        (_pdf(extra=b"/AcroForm"), "encrypted, interactive, or executable"),
        (_pdf(extra=b"/JavaScript"), "encrypted, interactive, or executable"),
    ],
)
def test_pdf_rejects_wrong_page_count_and_active_features(data: bytes, message: str) -> None:
    with pytest.raises(FinalsMaterialError, match=message):
        verify_pdf_bytes(data)
