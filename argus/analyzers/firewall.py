"""Firewall configuration security analyzer for ARGUS."""

from argus.analyzers.base import BaseAnalyzer
from argus.models import Finding, FirewallStatus


class FirewallAnalyzer(BaseAnalyzer):
    """Analyze firewall configuration for security issues."""

    name = "firewall"
    category = "network"

    def analyze(self, firewall: FirewallStatus) -> list[Finding]:
        """Analyze firewall status and return findings."""
        findings: list[Finding] = []
        self._check_firewall_disabled(firewall, findings)
        self._check_default_policy(firewall, findings)
        return findings

    def _check_firewall_disabled(
        self, firewall: FirewallStatus, findings: list[Finding]
    ) -> None:
        """Check if firewall is inactive."""
        if not firewall.active:
            detected = ", ".join(firewall.detected_backends) or "none detected"
            findings.append(self._make_finding(
                finding_id="ARGUS-FW-001",
                title="No active firewall detected",
                severity="high",
                description=(
                    "No active firewall was detected on this system. "
                    "All ports may be accessible from the network."
                ),
                evidence=[
                    f"Backend: {firewall.backend or 'none detected'}",
                    f"Detected backends: {detected}",
                    "Status: inactive",
                ],
                recommendation="Enable ufw: sudo ufw enable",
                mitre=["T1562.004"],
            ))

    def _check_default_policy(
        self, firewall: FirewallStatus, findings: list[Finding]
    ) -> None:
        """Check if default policy is permissive."""
        if not firewall.active or not firewall.default_policy:
            return
        policy_lower = firewall.default_policy.lower()
        if "accept" in policy_lower or "allow" in policy_lower:
            detected = ", ".join(firewall.detected_backends) or firewall.backend
            findings.append(self._make_finding(
                finding_id="ARGUS-FW-002",
                title="Firewall default policy is permissive",
                severity="medium",
                description=(
                    f"The firewall default policy is '{firewall.default_policy}'. "
                    "This means all traffic is allowed unless explicitly blocked."
                ),
                evidence=[
                    f"Backend: {firewall.backend}",
                    f"Detected backends: {detected}",
                    f"Default policy: {firewall.default_policy}",
                ],
                recommendation="Set default policy to deny/drop incoming traffic.",
                mitre=["T1562.004"],
            ))
