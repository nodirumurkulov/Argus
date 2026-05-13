"""CLI option validation tests."""

from typer.testing import CliRunner

from argus.cli import app


runner = CliRunner()


def test_root_command_renders_dashboard() -> None:
    """Root command should render the ARGUS dashboard instead of empty output."""
    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "ARGUS" in result.output
    assert "scan-host" in result.output
    assert "analyze-logs" in result.output


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


def test_analyze_logs_rejects_invalid_severity() -> None:
    """analyze-logs should reject unsupported severities."""
    result = runner.invoke(app, ["analyze-logs", "examples/sample-auth.log", "--severity", "urgent"])

    assert result.exit_code != 0
    assert "must be one of" in result.output


def test_analyze_logs_filters_by_minimum_severity() -> None:
    """analyze-logs should filter findings below the selected severity."""
    result = runner.invoke(app, ["analyze-logs", "examples/sample-auth.log", "--severity", "critical"])

    assert result.exit_code == 0
    assert "CRITICAL" in result.output
    assert "Direct root SSH login" not in result.output
