"""CLI option validation tests."""

from typer.testing import CliRunner

from argus.cli import app


runner = CliRunner()


def test_scan_host_rejects_invalid_output_format() -> None:
    """scan-host should fail before collecting data for unsupported formats."""
    result = runner.invoke(app, ["scan-host", "--format", "xml"])

    assert result.exit_code != 0
    assert "must be one of" in result.output
    assert "Collecting host data" not in result.output


def test_analyze_logs_rejects_invalid_output_format() -> None:
    """analyze-logs should reject unsupported formats."""
    result = runner.invoke(app, ["analyze-logs", "examples/sample-auth.log", "--format", "xml"])

    assert result.exit_code != 0
    assert "must be one of" in result.output


def test_scan_host_rejects_invalid_severity() -> None:
    """scan-host should fail before collecting data for unsupported severities."""
    result = runner.invoke(app, ["scan-host", "--severity", "urgent"])

    assert result.exit_code != 0
    assert "must be one of" in result.output
    assert "Collecting host data" not in result.output
