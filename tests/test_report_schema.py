"""Stable JSON report schema tests."""

import json

from argus.models import Finding, REPORT_SCHEMA_VERSION, Report
from argus.output import write_json_output


def test_report_model_includes_schema_version() -> None:
    """Report models should expose the current schema version."""
    report = Report()

    assert report.schema_version == REPORT_SCHEMA_VERSION


def test_json_output_includes_schema_version(tmp_path) -> None:
    """JSON finding exports should include the stable schema version."""
    output_path = tmp_path / "findings.json"
    finding = Finding(
        id="ARGUS-TEST-001",
        title="Test finding",
        severity="high",
        category="test",
        description="Used by schema tests.",
    )

    write_json_output([finding], str(output_path))

    data = json.loads(output_path.read_text())
    assert data["schema_version"] == REPORT_SCHEMA_VERSION


def test_json_output_keeps_required_top_level_fields(tmp_path) -> None:
    """Schema contract should fail if required top-level fields disappear."""
    output_path = tmp_path / "findings.json"

    write_json_output([], str(output_path))

    data = json.loads(output_path.read_text())
    assert set(data) == {"schema_version", "findings", "summary"}
