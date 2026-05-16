"""HTML report rendering tests."""

from pathlib import Path

from argus.models import Finding
from argus.output import write_html_output


def _finding() -> Finding:
    return Finding(
        id="ARGUS-TEST-001",
        title="Test finding",
        severity="high",
        category="test",
        description="A finding used by HTML report tests.",
        evidence=["example evidence"],
        recommendation="Fix the test issue.",
        mitre=["T0000"],
    )


def test_write_html_output_creates_report_file(tmp_path: Path) -> None:
    """HTML reports should be written without requiring a browser."""
    output_path = tmp_path / "report.html"

    write_html_output([_finding()], str(output_path), hostname="test-host")

    assert output_path.is_file()
