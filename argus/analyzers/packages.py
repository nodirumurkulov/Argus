"""Package security analyzer for ARGUS."""

from argus.analyzers.base import BaseAnalyzer
from argus.models import Finding


SECURITY_PACKAGES = {
    "fail2ban": "Brute-force protection",
    "ufw": "Firewall management",
    "apparmor": "Mandatory access control",
    "auditd": "Audit logging",
    "aide": "File integrity monitoring",
    "rkhunter": "Rootkit detection",
    "unattended-upgrades": "Automatic security updates",
    "libpam-pwquality": "Password policy enforcement",
}


class PackageAnalyzer(BaseAnalyzer):
    """Analyze installed packages for security posture."""

    name = "packages"
    category = "packages"

    def analyze(self, security_status: dict[str, bool]) -> list[Finding]:
        """Analyze security package installation status."""
        findings: list[Finding] = []
        self._check_missing_security_packages(security_status, findings)
        return findings

    def _check_missing_security_packages(
        self, status: dict[str, bool], findings: list[Finding]
    ) -> None:
        """Report missing security-critical packages."""
        missing = [
            pkg for pkg, installed in status.items()
            if not installed and pkg in SECURITY_PACKAGES
        ]
        if not missing:
            return
        critical_missing = [p for p in missing if p in ("fail2ban", "ufw", "apparmor")]
        if critical_missing:
            findings.append(self._make_finding(
                finding_id="ARGUS-PKG-001",
                title="Critical security packages not installed",
                severity="medium",
                description=(
                    f"Missing critical security packages: {', '.join(critical_missing)}. "
                    "These provide essential system protection."
                ),
                evidence=[
                    f"Missing: {pkg} ({SECURITY_PACKAGES.get(pkg, '')})"
                    for pkg in critical_missing
                ],
                recommendation=f"Install: sudo apt install {' '.join(critical_missing)}",
                mitre=["T1562"],
            ))
        optional_missing = [p for p in missing if p not in ("fail2ban", "ufw", "apparmor")]
        if optional_missing:
            findings.append(self._make_finding(
                finding_id="ARGUS-PKG-002",
                title="Recommended security packages not installed",
                severity="info",
                description=(
                    f"Recommended security packages not installed: "
                    f"{', '.join(optional_missing)}"
                ),
                evidence=[
                    f"Missing: {pkg} ({SECURITY_PACKAGES.get(pkg, '')})"
                    for pkg in optional_missing
                ],
                recommendation=f"Consider: sudo apt install {' '.join(optional_missing)}",
            ))
