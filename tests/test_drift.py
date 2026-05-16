"""Baseline drift detection tests."""

import json

from argus.drift import compare_findings
from argus.models import Finding


def _finding(finding_id: str, evidence: str) -> Finding:
    return Finding(
        id=finding_id,
        title="Test finding",
        severity="medium",
        category="test",
        description="Used by drift tests.",
        evidence=[evidence],
    )


def test_compare_findings_separates_new_resolved_and_unchanged() -> None:
    """Finding drift should use stable fingerprints for grouping."""
    unchanged = _finding("ARGUS-TEST-001", "resource:a")
    resolved = _finding("ARGUS-TEST-002", "resource:b")
    new = _finding("ARGUS-TEST-003", "resource:c")

    result = compare_findings([unchanged, resolved], [unchanged, new])

    assert result.new == [new]
    assert result.resolved == [resolved]
    assert result.unchanged == [unchanged]


def test_drift_result_reports_change_status() -> None:
    """Drift result should indicate whether reports differ."""
    unchanged = _finding("ARGUS-TEST-001", "resource:a")

    same_result = compare_findings([unchanged], [unchanged])
    changed_result = compare_findings([], [unchanged])

    assert same_result.has_changes is False
    assert changed_result.has_changes is True


def test_drift_result_summary_counts() -> None:
    """Drift summaries should expose new, resolved, and unchanged counts."""
    unchanged = _finding("ARGUS-TEST-001", "resource:a")
    resolved = _finding("ARGUS-TEST-002", "resource:b")
    new = _finding("ARGUS-TEST-003", "resource:c")

    result = compare_findings([unchanged, resolved], [unchanged, new])

    assert result.summary() == {"new": 1, "resolved": 1, "unchanged": 1}


def test_load_findings_report_reads_argus_json(tmp_path) -> None:
    """Report loading should parse findings from ARGUS JSON output."""
    from argus.drift import load_findings_report

    finding = _finding("ARGUS-TEST-001", "resource:a")
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"findings": [finding.model_dump()]}))

    loaded = load_findings_report(report_path)

    assert loaded == [finding]


def test_compare_report_files_uses_loaded_fingerprints(tmp_path) -> None:
    """File comparison should produce the same drift groups as in-memory comparison."""
    from argus.drift import compare_report_files

    old_finding = _finding("ARGUS-TEST-001", "resource:a")
    new_finding = _finding("ARGUS-TEST-002", "resource:b")
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    baseline_path.write_text(json.dumps({"findings": [old_finding.model_dump()]}))
    current_path.write_text(json.dumps({"findings": [new_finding.model_dump()]}))

    result = compare_report_files(baseline_path, current_path)

    assert result.resolved == [old_finding]
    assert result.new == [new_finding]
