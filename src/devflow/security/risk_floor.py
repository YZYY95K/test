"""Deterministic, model-independent risk floor for issue triage.

Issue text is untrusted input.  This module therefore does not use an LLM,
network service, repository state, or mutable configuration.  It identifies a
small set of actions that must cross the human-approval boundary and applies a
minimum complexity tier to any model classification.

Only stable rule identifiers leave this module.  Matched issue text and secret
values are deliberately never included in a decision.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass, replace
from enum import Enum
from typing import Final

from devflow.models.issue import ComplexityLevel, IssueClassification, IssueData
from devflow.security.secrets import secret_kinds

_MAX_SCAN_CHARACTERS: Final = 128_000
_MIN_MODEL_CONFIDENCE: Final = 0.75
_TIER_RANK: Final = {
    ComplexityLevel.T1: 1,
    ComplexityLevel.T2: 2,
    ComplexityLevel.T3: 3,
    ComplexityLevel.T4: 4,
    ComplexityLevel.T5: 5,
}


class RiskDomain(str, Enum):
    """High-risk domains that always require the T4 approval boundary."""

    SECURITY = "security"
    CREDENTIAL = "credential"
    DATA_LOSS = "data_loss"
    MIGRATION = "migration"
    PERMISSION = "permission"
    PRODUCTION_RELEASE = "production_release"
    PROMPT_INJECTION = "prompt_injection"
    INPUT_UNCERTAINTY = "input_uncertainty"


class RiskConfidence(str, Enum):
    """Confidence in the deterministic scan, not confidence from an LLM."""

    HIGH = "high"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class RiskFloorDecision:
    """An auditable risk-floor decision containing no issue content."""

    minimum_tier: ComplexityLevel
    domains: tuple[RiskDomain, ...]
    rule_ids: tuple[str, ...]
    confidence: RiskConfidence
    conflict: bool = False

    @property
    def requires_human_approval(self) -> bool:
        """Return whether the decision crosses the human approval boundary."""

        return _TIER_RANK[self.minimum_tier] >= _TIER_RANK[ComplexityLevel.T4]


@dataclass(frozen=True, slots=True)
class RiskFloorResult:
    """A model proposal after enforcement of the deterministic floor."""

    classification: IssueClassification
    decision: RiskFloorDecision
    proposed_tier: ComplexityLevel

    @property
    def upgraded(self) -> bool:
        """Return whether the policy raised the model-proposed tier."""

        return self.classification.complexity_level is not self.proposed_tier


_DOMAIN_PATTERNS: Final[tuple[tuple[RiskDomain, str, re.Pattern[str]], ...]] = (
    (
        RiskDomain.SECURITY,
        "security.term",
        re.compile(
            r"\b(?:security|vulnerabilit(?:y|ies)|cve-\d{4}-\d+|"
            r"remote code execution|rce|sql injection|xss|csrf|"
            r"authentication|authorization|auth bypass|privilege escalation|"
            r"cryptograph(?:y|ic)|encryption|"
            r"supply chain attack|unsafe deserialization)\b"
        ),
    ),
    (
        RiskDomain.CREDENTIAL,
        "credential.term",
        re.compile(
            r"\b(?:credentials?|api[-_ ]?keys?|access[-_ ]?tokens?|"
            r"refresh[-_ ]?tokens?|passwords?|passwds?|private[-_ ]?keys?|"
            r"ssh[-_ ]?keys?|client[-_ ]?secrets?|secret(?:s| rotation| leak)?)\b"
        ),
    ),
    (
        RiskDomain.DATA_LOSS,
        "data_loss.term",
        re.compile(
            r"\b(?:data[-_ ]loss|data[-_ ]corruption|"
            r"drop[-_ ](?:the[-_ ])?(?:database|table)|"
            r"truncate (?:the )?table|wipe (?:the )?(?:database|data|storage)|"
            r"delete all (?:data|records|rows)|purge (?:data|records)|"
            r"destructive change)\b"
        ),
    ),
    (
        RiskDomain.MIGRATION,
        "migration.term",
        re.compile(
            r"\b(?:migrations?|schema (?:change|upgrade|downgrade)|"
            r"database (?:upgrade|downgrade)|alembic|flyway|liquibase|"
            r"online ddl|data backfill)\b"
        ),
    ),
    (
        RiskDomain.PERMISSION,
        "permission.term",
        re.compile(
            r"\b(?:permissions?|privileges?|rbac|iam|access control|"
            r"authorization policy|sudo|root access|service account|"
            r"chmod|chown|setuid|setgid)\b"
        ),
    ),
    (
        RiskDomain.PRODUCTION_RELEASE,
        "production_release.term",
        re.compile(
            r"\b(?:production|prod deploy(?:ment)?|deploy to prod|"
            r"release to prod|production rollout|production rollback|"
            r"canary release|blue[- ]green deployment|hotfix release)\b"
        ),
    ),
)

_PATH_PATTERNS: Final[tuple[tuple[RiskDomain, str, re.Pattern[str]], ...]] = (
    (
        RiskDomain.CREDENTIAL,
        "credential.path",
        re.compile(
            r"(?:\.env(?:\.[a-z0-9_-]+)*|(?:^|/)(?:id_rsa|id_ed25519|"
            r"authorized_keys|kubeconfig|credentials?\.(?:json|ya?ml|toml)|"
            r"secrets?\.(?:json|ya?ml|toml)|[^/\s`\"']+\.(?:pem|key)))"
            r"(?=$|[^a-z0-9_.-])"
        ),
    ),
    (
        RiskDomain.MIGRATION,
        "migration.path",
        re.compile(r"(?:^|/)(?:migrations?|alembic|flyway|liquibase)(?:/|$)"),
    ),
    (
        RiskDomain.PERMISSION,
        "permission.path",
        re.compile(
            r"(?:^|/)(?:rbac|iam|acl|service[-_]?accounts?)(?:/|\.(?:ya?ml|json)|$)"
        ),
    ),
    (
        RiskDomain.PRODUCTION_RELEASE,
        "production_release.path",
        re.compile(
            r"(?:^|/)(?:prod(?:uction)?|deploy|releases?|helm|terraform|"
            r"k8s|kubernetes)(?:/|\.(?:ya?ml|json|tf)|$)|"
            r"(?:^|[^a-z0-9_.-])\.github/workflows/"
            r"(?:deploy|release|prod)[^/\s]*\.ya?ml"
        ),
    ),
)

_PROMPT_INJECTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"\bignore (?:all )?(?:the )?(?:previous|prior|system|developer) "
        r"(?:instructions?|prompts?|messages?)\b"
    ),
    re.compile(r"\b(?:complexity[-_ ]?level|risk[-_ ]?tier)\s*[:=]\s*t[1-3]\b"),
    re.compile(
        r"\b(?:classify|mark|set|assign|treat) (?:this|the issue|it)?\s*"
        r"(?:as|to)?\s*t[1-3]\b"
    ),
    re.compile(r"\b(?:reveal|print|return) (?:the )?(?:system|developer) prompt\b"),
)


def assess_issue_risk(issue: IssueData) -> RiskFloorDecision:
    """Compute a deterministic minimum tier from untrusted issue fields.

    The scan is deliberately conservative.  Oversized or binary-like input is
    classified with low confidence and therefore receives a T4 floor.
    """

    raw_fields = (issue.title, issue.body or "", *issue.labels)
    total_characters = sum(len(value) for value in raw_fields)
    truncated = total_characters > _MAX_SCAN_CHARACTERS
    scan_budget = _MAX_SCAN_CHARACTERS
    bounded_fields: list[str] = []
    for value in raw_fields:
        bounded = value[:scan_budget]
        bounded_fields.append(bounded)
        scan_budget -= len(bounded)
        if scan_budget <= 0:
            break

    normalized = _normalize("\n".join(bounded_fields))
    path_text = normalized.replace("\\", "/")
    domains: set[RiskDomain] = set()
    rule_ids: set[str] = set()

    for domain, rule_id, pattern in _DOMAIN_PATTERNS:
        if pattern.search(normalized) is not None:
            domains.add(domain)
            rule_ids.add(rule_id)

    for domain, rule_id, pattern in _PATH_PATTERNS:
        if pattern.search(path_text) is not None:
            domains.add(domain)
            rule_ids.add(rule_id)

    if any(pattern.search(normalized) is not None for pattern in _PROMPT_INJECTION_PATTERNS):
        domains.add(RiskDomain.PROMPT_INJECTION)
        rule_ids.add("prompt_injection.directive")

    # Secret detectors report only stable categories; secret bytes never enter
    # the policy result.
    if secret_kinds(bounded_fields):
        domains.add(RiskDomain.CREDENTIAL)
        rule_ids.add("credential.secret_shape")

    low_confidence = truncated or "\x00" in normalized
    if low_confidence:
        domains.add(RiskDomain.INPUT_UNCERTAINTY)
        rule_ids.add("input.scan_incomplete")

    conflict = RiskDomain.PROMPT_INJECTION in domains
    minimum_tier = ComplexityLevel.T4 if domains else ComplexityLevel.T1
    return RiskFloorDecision(
        minimum_tier=minimum_tier,
        domains=tuple(sorted(domains, key=lambda item: item.value)),
        rule_ids=tuple(sorted(rule_ids)),
        confidence=RiskConfidence.LOW if low_confidence else RiskConfidence.HIGH,
        conflict=conflict,
    )


def enforce_risk_floor(
    issue: IssueData,
    proposed: IssueClassification,
    *,
    model_confidence: float | None,
) -> RiskFloorResult:
    """Apply the deterministic floor without ever lowering the model tier.

    ``model_confidence`` must be supplied by the caller.  A provider failure,
    missing score, non-finite score, or score below 0.75 fails closed to T4.
    A disagreement in which the model proposes a tier below a deterministic
    high-risk rule is also recorded as a rule conflict and fails closed.
    """

    decision = assess_issue_risk(issue)
    low_model_confidence = (
        model_confidence is None
        or not math.isfinite(model_confidence)
        or not 0.0 <= model_confidence <= 1.0
        or model_confidence < _MIN_MODEL_CONFIDENCE
    )
    if low_model_confidence:
        decision = _escalate_decision(
            decision,
            domain=RiskDomain.INPUT_UNCERTAINTY,
            rule_id="classifier.low_confidence",
            low_confidence=True,
        )

    if _TIER_RANK[proposed.complexity_level] < _TIER_RANK[decision.minimum_tier]:
        decision = _escalate_decision(
            decision,
            rule_id="classifier.downgrade_conflict",
            conflict=True,
        )

    effective_tier = max(
        (proposed.complexity_level, decision.minimum_tier),
        key=_TIER_RANK.__getitem__,
    )
    classification = proposed.model_copy(
        update={"complexity_level": effective_tier}
    )
    return RiskFloorResult(
        classification=classification,
        decision=decision,
        proposed_tier=proposed.complexity_level,
    )


def _escalate_decision(
    decision: RiskFloorDecision,
    *,
    rule_id: str,
    domain: RiskDomain | None = None,
    low_confidence: bool = False,
    conflict: bool = False,
) -> RiskFloorDecision:
    domains = set(decision.domains)
    if domain is not None:
        domains.add(domain)
    return replace(
        decision,
        minimum_tier=max(
            (decision.minimum_tier, ComplexityLevel.T4),
            key=_TIER_RANK.__getitem__,
        ),
        domains=tuple(sorted(domains, key=lambda item: item.value)),
        rule_ids=tuple(sorted({*decision.rule_ids, rule_id})),
        confidence=(
            RiskConfidence.LOW if low_confidence else decision.confidence
        ),
        conflict=decision.conflict or conflict,
    )


def _normalize(value: str) -> str:
    """Normalize compatibility characters before case-insensitive matching."""

    return unicodedata.normalize("NFKC", value).casefold()


__all__ = [
    "RiskConfidence",
    "RiskDomain",
    "RiskFloorDecision",
    "RiskFloorResult",
    "assess_issue_risk",
    "enforce_risk_floor",
]
