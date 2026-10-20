"""Sigma rule generation tests."""

import pytest
import yaml

from argus.detections import (
    UnknownSigmaScenario,
    get_sigma_rule,
    normalize_sigma_scenario,
    render_sigma_yaml,
    supported_sigma_scenarios,
)


def test_supported_sigma_scenarios_include_auth_cases() -> None:
    """ARGUS should expose all initial auth Sigma scenarios."""
    scenarios = supported_sigma_scenarios()

    assert "ssh-bruteforce" in scenarios
    assert "password-spraying" in scenarios
    assert "root-login" in scenarios
    assert "successful-after-failures" in scenarios


def test_normalize_sigma_scenario_aliases() -> None:
    """Common aliases should map to canonical scenario names."""
    assert normalize_sigma_scenario("ssh-brute-force") == "ssh-bruteforce"
    assert normalize_sigma_scenario("password_spray") == "password-spraying"
    assert normalize_sigma_scenario("root-ssh-login") == "root-login"


def test_unknown_sigma_scenario_raises() -> None:
    """Unsupported scenarios should fail explicitly."""
    with pytest.raises(UnknownSigmaScenario):
        normalize_sigma_scenario("windows-rdp-bruteforce")


def test_bruteforce_rule_renders_valid_yaml() -> None:
    """The SSH brute-force scenario should render parseable Sigma-style YAML."""
    rendered = render_sigma_yaml(get_sigma_rule("ssh-bruteforce"))
    data = yaml.safe_load(rendered)

    assert data["title"] == "ARGUS SSH Brute Force Attempts"
    assert data["logsource"] == {"product": "linux", "service": "sshd"}
    assert data["detection"]["selection"]["message|contains"] == "Failed password for"
    assert data["level"] == "high"
    assert "attack.t1110.001" in data["tags"]


def test_root_login_rule_contains_root_login_detection() -> None:
    """The root-login rule should match successful SSH root authentication."""
    data = yaml.safe_load(render_sigma_yaml(get_sigma_rule("root-login")))

    assert data["id"] == "argus-linux-ssh-root-login"
    assert data["detection"]["selection"]["message|contains|all"] == [
        "Accepted",
        " for root from ",
    ]
    assert data["level"] == "high"


def test_all_supported_scenarios_render_valid_yaml() -> None:
    """Every supported scenario should render parseable YAML with required fields."""
    for scenario in supported_sigma_scenarios():
        data = yaml.safe_load(render_sigma_yaml(get_sigma_rule(scenario)))

        assert data["title"].startswith("ARGUS")
        assert data["id"].startswith("argus-")
        assert data["logsource"]["product"] == "linux"
        assert "detection" in data
        assert "condition" in data["detection"]
