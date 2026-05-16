"""Baseline and drift detection helpers."""

from pydantic import BaseModel, Field

from argus.models import Finding


class DriftResult(BaseModel):
    """Finding-level drift between baseline and current reports."""

    new: list[Finding] = Field(default_factory=list)
    resolved: list[Finding] = Field(default_factory=list)
    unchanged: list[Finding] = Field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """Return True when findings changed between reports."""
        return bool(self.new or self.resolved)

    def summary(self) -> dict[str, int]:
        """Return finding drift counts."""
        return {
            "new": len(self.new),
            "resolved": len(self.resolved),
            "unchanged": len(self.unchanged),
        }


def _findings_by_fingerprint(findings: list[Finding]) -> dict[str, Finding]:
    """Index findings by stable fingerprint."""
    return {finding.fingerprint: finding for finding in findings}


def compare_findings(
    baseline_findings: list[Finding],
    current_findings: list[Finding],
) -> DriftResult:
    """Compare two finding sets using stable fingerprints."""
    baseline = _findings_by_fingerprint(baseline_findings)
    current = _findings_by_fingerprint(current_findings)
    baseline_keys = set(baseline)
    current_keys = set(current)

    return DriftResult(
        new=[current[key] for key in sorted(current_keys - baseline_keys)],
        resolved=[baseline[key] for key in sorted(baseline_keys - current_keys)],
        unchanged=[current[key] for key in sorted(current_keys & baseline_keys)],
    )
