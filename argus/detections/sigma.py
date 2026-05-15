"""Sigma detection rule generation for ARGUS."""

from dataclasses import dataclass, field
from typing import Any

import yaml


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
