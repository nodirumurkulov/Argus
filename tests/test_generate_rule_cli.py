"""Detection rule CLI tests."""

from pathlib import Path

import yaml
from typer.testing import CliRunner

from argus.cli import app


runner = CliRunner()


def test_generate_rule_lists_sigma_scenarios() -> None:
    """generate-rule should list supported Sigma scenarios when none is provided."""
    result = runner.invoke(app, ["generate-rule", "--type", "sigma"])

    assert result.exit_code == 0
    assert "Available Sigma scenarios" in result.output
    assert "ssh-bruteforce" in result.output
    assert "password-spraying" in result.output


def test_generate_rule_rejects_unknown_sigma_scenario() -> None:
    """Unsupported Sigma scenarios should fail clearly."""
    result = runner.invoke(app, [
        "generate-rule",
        "--type",
        "sigma",
        "--scenario",
        "unknown-scenario",
    ])

    assert result.exit_code == 1
    assert "Unknown Sigma scenario" in result.output
    assert "ssh-bruteforce" in result.output


def test_generate_rule_prints_sigma_yaml() -> None:
    """Sigma scenario generation should print parseable YAML."""
    result = runner.invoke(app, [
        "generate-rule",
        "--type",
        "sigma",
        "--scenario",
        "root-login",
    ])

    assert result.exit_code == 0
    data = yaml.safe_load(result.output)
    assert data["id"] == "argus-linux-ssh-root-login"
    assert data["logsource"]["service"] == "sshd"


def test_generate_rule_writes_sigma_yaml(tmp_path: Path) -> None:
    """Sigma scenario generation should support writing to a file."""
    output = tmp_path / "ssh-bruteforce.yml"
    result = runner.invoke(app, [
        "generate-rule",
        "--type",
        "sigma",
        "--scenario",
        "ssh-bruteforce",
        "--output",
        str(output),
    ])

    assert result.exit_code == 0
    assert output.is_file()
    data = yaml.safe_load(output.read_text())
    assert data["id"] == "argus-linux-ssh-bruteforce"


def test_generate_rule_rejects_unimplemented_rule_type() -> None:
    """Only Sigma generation should be implemented initially."""
    result = runner.invoke(app, ["generate-rule", "--type", "yara", "--scenario", "ssh-bruteforce"])

    assert result.exit_code == 1
    assert "not implemented yet" in result.output
