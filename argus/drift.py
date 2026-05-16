"""Baseline and drift detection helpers."""

import json
from pathlib import Path

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


def load_findings_report(path: str | Path) -> list[Finding]:
    """Load findings from an ARGUS JSON report."""
    data = json.loads(Path(path).read_text())
    findings_data = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings_data, list):
        raise ValueError("expected a JSON object with a findings list")
    return [Finding(**finding) for finding in findings_data]


def compare_report_files(baseline_path: str | Path, current_path: str | Path) -> DriftResult:
    """Compare two ARGUS JSON report files."""
    return compare_findings(
        baseline_findings=load_findings_report(baseline_path),
        current_findings=load_findings_report(current_path),
    )
