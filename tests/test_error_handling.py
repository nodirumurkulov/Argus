"""Regression coverage for intentional error handling during scans and report loading."""

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from argus.analyzers import engine
from argus.cli import app
from argus.collectors import aggregator
from argus.collectors.ssh import SSHCollector
from argus.drift import load_findings_report
from argus.models import Finding, HostData


@pytest.mark.parametrize("verbose", [False, True])
def test_analyzer_failure_does_not_discard_other_findings(
    monkeypatch: pytest.MonkeyPatch, sample_finding_data: dict, verbose: bool
) -> None:
    finding = Finding(**sample_finding_data)
    for name in vars(engine):
        if name.startswith("_analyze_"):
            monkeypatch.setattr(engine, name, lambda data: [])

    def fail(data: HostData) -> None:
        raise RuntimeError("unavailable data")

    monkeypatch.setattr(engine, "_analyze_ssh", fail)
    monkeypatch.setattr(engine, "_analyze_users", lambda data: [finding])

    assert engine.run_all_analyzers(HostData(), verbose=verbose) == [finding]


@pytest.mark.parametrize("verbose", [False, True])
def test_collector_failure_does_not_stop_later_collectors(
    monkeypatch: pytest.MonkeyPatch, verbose: bool
) -> None:
    host = HostData()
    collected = []
    monkeypatch.setattr(aggregator.HostCollector, "collect", lambda self: host)
    for name in vars(aggregator):
        if name.startswith("_collect_"):
            monkeypatch.setattr(aggregator, name, lambda data: None)

    def fail(data: HostData) -> None:
        raise RuntimeError("unavailable source")

    monkeypatch.setattr(aggregator, "_collect_ssh", fail)
    monkeypatch.setattr(aggregator, "_collect_persistence", lambda data: collected.append(data))

    assert aggregator.collect_host_data(verbose=verbose) is host
    assert collected == [host]


@pytest.mark.parametrize("payload", [[], {}, {"findings": None}, {"findings": {}}])
def test_invalid_report_contents_remain_validation_errors(
    tmp_path: Path, payload: object
) -> None:
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(payload))

    with pytest.raises(ValueError, match="expected a JSON object with a findings list"):
        load_findings_report(path)

    result = CliRunner().invoke(app, ["report", "--input", str(path)])
    assert result.exit_code == 1
    assert "Invalid findings JSON" in result.output


def test_command_output_is_preserved_on_nonzero_exit() -> None:
    output = SSHCollector().safe_run_command(
        [sys.executable, "-c", "print('partial output'); raise SystemExit(1)"]
    )

    assert output == "partial output\n"
