"""Systemd service security analyzer for ARGUS."""

from argus.analyzers.base import BaseAnalyzer
from argus.models import Finding, SystemdService


class SystemdAnalyzer(BaseAnalyzer):
    """Analyze systemd services for security issues."""

    name = "systemd"
    category = "persistence"

    def analyze(self, services: list[SystemdService]) -> list[Finding]:
        """Analyze systemd services and return findings."""
        findings: list[Finding] = []
        self._check_writable_units(services, findings)
        self._check_suspicious_services(services, findings)
        return findings

    def _check_writable_units(
        self, services: list[SystemdService], findings: list[Finding]
    ) -> None:
        """Check for writable systemd unit files."""
        for service in services:
            if service.writable:
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-SYSD-001-{service.name}",
                    title=f"Writable systemd unit file: {service.name}",
                    severity="high",
                    description=(
                        f"Unit file '{service.unit_file}' is writable. An attacker "
                        "could modify this to execute arbitrary commands on boot."
                    ),
                    evidence=[
                        f"Unit: {service.name}",
                        f"File: {service.unit_file}",
                        f"ExecStart: {service.exec_start}",
                    ],
                    recommendation=f"Fix permissions: chmod 644 {service.unit_file}",
                    mitre=["T1543.002"],
                ))

    def _check_suspicious_services(
        self, services: list[SystemdService], findings: list[Finding]
    ) -> None:
        """Check for services with suspicious ExecStart commands."""
        suspicious_patterns = [
            "/tmp/", "/dev/shm/", "curl ", "wget ",
            "nc ", "ncat ", "base64", "bash -i",
            "python -c", "python3 -c", "reverse",
        ]
        for service in services:
            if not service.exec_start:
                continue
            exec_lower = service.exec_start.lower()
            matched = [p for p in suspicious_patterns if p in exec_lower]
            if matched:
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-SYSD-002-{service.name}",
                    title=f"Suspicious systemd service: {service.name}",
                    severity="high",
                    description=(
                        f"Service '{service.name}' has a suspicious ExecStart command "
                        f"containing: {', '.join(matched)}"
                    ),
                    evidence=[
                        f"Unit: {service.name}",
                        f"ExecStart: {service.exec_start}",
                        f"Enabled: {service.enabled}",
                    ],
                    recommendation=f"Investigate service '{service.name}' and disable if unauthorized.",
                    mitre=["T1543.002"],
                ))
