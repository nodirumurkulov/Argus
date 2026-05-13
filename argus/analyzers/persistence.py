"""Persistence mechanism analyzer for ARGUS."""

from argus.analyzers.base import BaseAnalyzer
from argus.models import Finding


def _id_fragment(value: str) -> str:
    """Create a compact finding ID fragment from path-like text."""
    fragment = "".join(char if char.isalnum() else "-" for char in value.lower())
    return fragment.strip("-")[:48] or "unknown"


class PersistenceAnalyzer(BaseAnalyzer):
    """Analyze persistence locations for security issues."""

    name = "persistence"
    category = "persistence"

    def analyze(self, persistence_locations: list[str]) -> list[Finding]:
        """Analyze persistence locations and return findings."""
        findings: list[Finding] = []
        self._check_writable_paths(persistence_locations, findings)
        self._check_suspicious_rc_files(persistence_locations, findings)
        self._check_startup_scripts(persistence_locations, findings)
        return findings

    def _check_writable_paths(
        self, locations: list[str], findings: list[Finding]
    ) -> None:
        """Check for writable persistence paths."""
        writable = [location for location in locations if location.startswith("writable:")]
        for loc in writable:
            path = loc.split(":", 1)[1]
            findings.append(self._make_finding(
                finding_id=f"ARGUS-PERS-001-{_id_fragment(path)}",
                title=f"Writable startup file: {path}",
                severity="medium",
                description=(
                    f"Startup file '{path}' is writable. An attacker could modify "
                    "this to execute arbitrary commands on system startup."
                ),
                evidence=[f"Writable: {path}"],
                recommendation=f"Review permissions and content of {path}.",
                mitre=["T1547.004"],
            ))

    def _check_suspicious_rc_files(
        self, locations: list[str], findings: list[Finding]
    ) -> None:
        """Check for shell rc files with suspicious content."""
        suspicious = [location for location in locations if location.startswith("suspicious_rc:")]
        for loc in suspicious:
            path = loc.split(":", 1)[1]
            findings.append(self._make_finding(
                finding_id=f"ARGUS-PERS-002-{_id_fragment(path)}",
                title=f"Suspicious shell rc file: {path}",
                severity="high",
                description=(
                    f"Shell configuration file '{path}' contains suspicious "
                    "commands (curl, wget, nc, base64, eval, etc.)."
                ),
                evidence=[f"Suspicious content in: {path}"],
                recommendation=f"Review content of {path} for unauthorized commands.",
                mitre=["T1546.004"],
            ))

    def _check_startup_scripts(
        self, locations: list[str], findings: list[Finding]
    ) -> None:
        """Report executable startup scripts."""
        scripts = [location for location in locations if location.startswith("startup_script:")]
        if len(scripts) > 20:
            findings.append(self._make_finding(
                finding_id="ARGUS-PERS-003",
                title=f"Large number of startup scripts ({len(scripts)})",
                severity="info",
                description=(
                    f"Found {len(scripts)} executable startup scripts. "
                    "Review for unauthorized entries."
                ),
                evidence=[s.split(":", 1)[1] for s in scripts[:10]],
                recommendation="Audit startup scripts in /etc/init.d/ and /etc/profile.d/.",
                mitre=["T1547"],
            ))
