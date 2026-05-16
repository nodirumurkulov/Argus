"""Baseline and drift detection helpers."""

from pydantic import BaseModel, Field

from argus.models import Finding


class DriftResult(BaseModel):
    """Finding-level drift between baseline and current reports."""

    new: list[Finding] = Field(default_factory=list)
    resolved: list[Finding] = Field(default_factory=list)
    unchanged: list[Finding] = Field(default_factory=list)


def _findings_by_fingerprint(findings: list[Finding]) -> dict[str, Finding]:
    """Index findings by stable fingerprint."""
    return {finding.fingerprint: finding for finding in findings}
