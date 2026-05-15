"""ARGUS detection rule generators (Sigma, auditd, YARA, Suricata)."""

from argus.detections.sigma import (
    SigmaRule,
    UnknownSigmaScenario,
    get_sigma_rule,
    normalize_sigma_scenario,
    render_sigma_yaml,
    supported_sigma_scenarios,
)

__all__ = [
    "SigmaRule",
    "UnknownSigmaScenario",
    "get_sigma_rule",
    "normalize_sigma_scenario",
    "render_sigma_yaml",
    "supported_sigma_scenarios",
]
