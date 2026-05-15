"""Sigma detection rule generation for ARGUS."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml


class UnknownSigmaScenario(ValueError):
    """Raised when a requested Sigma scenario is not supported."""


SUPPORTED_SCENARIOS = {
    "ssh-bruteforce": "SSH brute-force authentication failures",
    "password-spraying": "Password spraying across multiple SSH usernames",
    "root-login": "Direct successful SSH login as root",
    "successful-after-failures": "Successful SSH login after repeated failures",
}

SCENARIO_ALIASES = {
    "ssh-brute-force": "ssh-bruteforce",
    "bruteforce": "ssh-bruteforce",
    "brute-force": "ssh-bruteforce",
    "spraying": "password-spraying",
    "password-spray": "password-spraying",
    "root-ssh-login": "root-login",
    "successful-login-after-failures": "successful-after-failures",
    "success-after-failures": "successful-after-failures",
}

LINUX_SSHD_LOGSOURCE = {
    "product": "linux",
    "service": "sshd",
}

COMMON_FALSE_POSITIVES = [
    "Legitimate administrator activity during maintenance windows",
    "Misconfigured automation repeatedly attempting SSH authentication",
]

ARGUS_RULE_REFERENCES = [
    "https://attack.mitre.org/techniques/T1110/",
    "https://attack.mitre.org/techniques/T1021/004/",
]


def supported_sigma_scenarios() -> dict[str, str]:
    """Return supported scenario names and descriptions."""
    return SUPPORTED_SCENARIOS.copy()


def normalize_sigma_scenario(scenario: str) -> str:
    """Normalize scenario aliases and validate support."""
    normalized = scenario.strip().lower().replace("_", "-")
    normalized = SCENARIO_ALIASES.get(normalized, normalized)
    if normalized not in SUPPORTED_SCENARIOS:
        raise UnknownSigmaScenario(scenario)
    return normalized


def ssh_bruteforce_rule() -> SigmaRule:
    """Generate a Sigma rule for SSH brute-force attempts."""
    return SigmaRule(
        title="ARGUS SSH Brute Force Attempts",
        rule_id="argus-linux-ssh-bruteforce",
        description=(
            "Detects repeated SSH password authentication failures that may indicate "
            "a brute-force attack against local accounts."
        ),
        logsource=LINUX_SSHD_LOGSOURCE,
        detection={
            "selection": {
                "message|contains": "Failed password for",
            },
            "condition": "selection",
        },
        falsepositives=COMMON_FALSE_POSITIVES,
        level="high",
        tags=["attack.credential_access", "attack.t1110", "attack.t1110.001"],
        references=ARGUS_RULE_REFERENCES,
    )


def password_spraying_rule() -> SigmaRule:
    """Generate a Sigma rule for SSH password spraying indicators."""
    return SigmaRule(
        title="ARGUS SSH Password Spraying Indicators",
        rule_id="argus-linux-ssh-password-spraying",
        description=(
            "Detects SSH authentication failures against multiple users, including "
            "invalid users, that may indicate password spraying activity."
        ),
        logsource=LINUX_SSHD_LOGSOURCE,
        detection={
            "selection_failed": {
                "message|contains": "Failed password for",
            },
            "selection_invalid": {
                "message|contains": "invalid user",
            },
            "condition": "selection_failed and selection_invalid",
        },
        falsepositives=[
            "Internet-facing SSH service receiving commodity login noise",
            "Security testing against explicitly authorized hosts",
        ],
        level="high",
        tags=["attack.credential_access", "attack.t1110", "attack.t1110.003"],
        references=ARGUS_RULE_REFERENCES,
    )


@dataclass(frozen=True)
class SigmaRule:
    """A minimal Sigma-style rule representation."""

    title: str
    rule_id: str
    description: str
    logsource: dict[str, str]
    detection: dict[str, Any]
    level: str
    status: str = "experimental"
    author: str = "ARGUS"
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return the Sigma rule as an ordered dictionary."""
        data: dict[str, Any] = {
            "title": self.title,
            "id": self.rule_id,
            "status": self.status,
            "description": self.description,
            "author": self.author,
            "logsource": self.logsource,
            "detection": self.detection,
            "falsepositives": self.falsepositives,
            "level": self.level,
        }
        if self.tags:
            data["tags"] = self.tags
        if self.references:
            data["references"] = self.references
        return data


def render_sigma_yaml(rule: SigmaRule) -> str:
    """Render a Sigma rule to YAML."""
    return yaml.safe_dump(
        rule.to_dict(),
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )
