"""License evidence must improve coverage without guessing ambiguous metadata."""

from __future__ import annotations

import pytest

from scripts.generate_dependency_licenses import license_evidence


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        (
            {"license_expression": "Apache-2.0", "license": "MIT"},
            ("Apache-2.0", "verified-pypi-license-expression"),
        ),
        (
            {"license_expression": None, "license": "  MIT License  "},
            ("MIT", "verified-pypi-license-field-exact"),
        ),
        (
            {"license_expression": None, "license": "MIT OR Apache-2.0"},
            ("MIT OR Apache-2.0", "verified-pypi-license-field-exact"),
        ),
        (
            {
                "license_expression": None,
                "license": None,
                "classifiers": ["License :: OSI Approved :: Apache Software License"],
            },
            ("Apache-2.0", "verified-pypi-license-classifier-exact"),
        ),
    ],
)
def test_license_evidence_uses_only_exact_authoritative_metadata(
    info: dict[str, object], expected: tuple[str, str]
) -> None:
    assert license_evidence(info) == expected


@pytest.mark.parametrize(
    "info",
    [
        {"license_expression": None, "license": "BSD"},
        {
            "license_expression": None,
            "classifiers": [
                "License :: OSI Approved :: MIT License",
                "License :: OSI Approved :: Apache Software License",
            ],
        },
        {"license_expression": None, "license": "Copyright 2026, all rights reserved"},
    ],
)
def test_license_evidence_keeps_ambiguous_metadata_unasserted(
    info: dict[str, object],
) -> None:
    assert license_evidence(info) == (
        "NOASSERTION",
        "noassertion-pypi-license-metadata-ambiguous-or-missing",
    )
