"""Typed identity and approval context crossing the MCP trust boundary."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ApprovalEvidence(BaseModel):
    """Human approval signed by a trusted authority for one exact action."""

    approval_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    action: str = Field(pattern=r"^[a-z0-9_.:-]+$")
    target: str = Field(min_length=1, max_length=300)
    artifact_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approved_by: str = Field(min_length=1, max_length=200)
    approved_at: datetime
    signature: str = Field(pattern=r"^[a-f0-9]{64}$")


class MCPCallContext(BaseModel):
    """Non-secret execution identity supplied with every MCP invocation."""

    run_id: str = Field(min_length=1, max_length=200)
    issue_id: int = Field(ge=1)
    task_id: str = Field(min_length=1, max_length=200)
    agent: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]+$")
    skill: str = Field(pattern=r"^[a-z0-9-]+$")
    trace_id: str = Field(min_length=1, max_length=300)
    idempotency_key: str = Field(min_length=1, max_length=300)
    risk_tier: str | None = Field(default=None, pattern=r"^T[1-5]$")
    approval: ApprovalEvidence | None = None
    context_signature: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


__all__ = ["ApprovalEvidence", "MCPCallContext"]
