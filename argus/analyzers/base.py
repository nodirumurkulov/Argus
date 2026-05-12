"""Base analyzer abstract class for ARGUS security analysis."""

from abc import ABC, abstractmethod

from argus.models import Finding


class BaseAnalyzer(ABC):
    """Abstract base class for all ARGUS security analyzers.

    Analyzers take collected host data and produce security findings.
    Each analyzer focuses on a specific security domain (SSH, users, etc.).
    """

    name: str = "base"
    category: str = "general"

    @abstractmethod
    def analyze(self, *args, **kwargs) -> list[Finding]:
        """Analyze collected data and return security findings."""

    def _make_finding(
        self,
        finding_id: str,
        title: str,
        severity: str,
        description: str,
        evidence: list[str] | None = None,
        recommendation: str = "",
        mitre: list[str] | None = None,
    ) -> Finding:
        """Helper to create a Finding with consistent defaults."""
        return Finding(
            id=finding_id,
            title=title,
            severity=severity,
            category=self.category,
            description=description,
            evidence=evidence or [],
            recommendation=recommendation,
            mitre=mitre or [],
        )
