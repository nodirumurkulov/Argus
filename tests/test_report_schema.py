"""Stable JSON report schema tests."""

from argus.models import REPORT_SCHEMA_VERSION, Report


def test_report_model_includes_schema_version() -> None:
    """Report models should expose the current schema version."""
    report = Report()

    assert report.schema_version == REPORT_SCHEMA_VERSION
