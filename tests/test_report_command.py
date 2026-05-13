"""Report command tests."""

import json
from pathlib import Path

from typer.testing import CliRunner

from argus.cli import app


runner = CliRunner()


def test_report_requires_input() -> None:
    """report should fail clearly when --input is omitted."""
    result = runner.invoke(app, ["report"])

    assert result.exit_code == 1
    assert "--input is required" in result.output


def test_report_rejects_missing_input_file() -> None:
    """report should fail clearly when the findings file does not exist."""
    result = runner.invoke(app, ["report", "--input", "missing.json"])

    assert result.exit_code == 1
    assert "Findings file not found" in result.output


def test_report_writes_markdown_from_findings_json(tmp_path: Path) -> None:
    """report should render a markdown report from exported findings JSON."""
    findings_path = tmp_path / "findings.json"
    report_path = tmp_path / "report.md"
    findings_path.write_text(json.dumps({
        "findings": [
            {
                "id": "ARGUS-TEST-001",
                "title": "Test finding",
                "severity": "high",
                "category": "test",
                "description": "A finding used by report command tests.",
                "evidence": ["example evidence"],
                "recommendation": "Fix the test issue.",
                "mitre": ["T0000"],
                "references": [],
            }
        ]
    }))

    result = runner.invoke(app, [
        "report",
        "--input",
        str(findings_path),
        "--output",
        str(report_path),
    ])

    assert result.exit_code == 0
    assert report_path.is_file()
    assert "Test finding" in report_path.read_text()
