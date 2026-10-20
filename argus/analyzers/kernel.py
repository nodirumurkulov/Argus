"""Kernel hardening analyzer for ARGUS."""

from argus.analyzers.base import BaseAnalyzer
from argus.models import Finding

SYSCTL_EXPECTATIONS = {
    "net.ipv4.ip_forward": {
        "expected": "0",
        "severity": "medium",
        "title": "IP forwarding is enabled",
        "description": "IP forwarding allows the system to route packets between interfaces.",
        "recommendation": "Disable: sysctl -w net.ipv4.ip_forward=0",
        "mitre": ["T1599"],
    },
    "net.ipv4.conf.all.accept_redirects": {
        "expected": "0",
        "severity": "low",
        "title": "ICMP redirects accepted",
        "description": "Accepting ICMP redirects can allow MITM attacks.",
        "recommendation": "Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0",
        "mitre": ["T1557"],
    },
    "net.ipv4.conf.all.send_redirects": {
        "expected": "0",
        "severity": "low",
        "title": "ICMP redirects sent",
        "description": "Sending ICMP redirects should be disabled on non-routers.",
        "recommendation": "Disable: sysctl -w net.ipv4.conf.all.send_redirects=0",
        "mitre": ["T1557"],
    },
    "net.ipv4.conf.all.accept_source_route": {
        "expected": "0",
        "severity": "low",
        "title": "Source routing accepted",
        "description": "Source routing can be used to bypass network security controls.",
        "recommendation": "Disable: sysctl -w net.ipv4.conf.all.accept_source_route=0",
        "mitre": [],
    },
    "kernel.randomize_va_space": {
        "expected": "2",
        "severity": "medium",
        "title": "ASLR is not fully enabled",
        "description": "Address Space Layout Randomization is not set to full randomization.",
        "recommendation": "Enable: sysctl -w kernel.randomize_va_space=2",
        "mitre": ["T1211"],
    },
    "kernel.dmesg_restrict": {
        "expected": "1",
        "severity": "low",
        "title": "Kernel dmesg unrestricted",
        "description": "Unprivileged users can read kernel ring buffer messages.",
        "recommendation": "Restrict: sysctl -w kernel.dmesg_restrict=1",
        "mitre": [],
    },
    "kernel.kptr_restrict": {
        "expected": "1",
        "severity": "low",
        "title": "Kernel pointer addresses exposed",
        "description": "Kernel pointer addresses are not restricted, aiding exploitation.",
        "recommendation": "Restrict: sysctl -w kernel.kptr_restrict=1",
        "mitre": ["T1211"],
    },
    "fs.suid_dumpable": {
        "expected": "0",
        "severity": "low",
        "title": "SUID core dumps enabled",
        "description": "Core dumps from SUID programs may leak sensitive data.",
        "recommendation": "Disable: sysctl -w fs.suid_dumpable=0",
        "mitre": [],
    },
}


class KernelAnalyzer(BaseAnalyzer):
    """Analyze kernel/sysctl hardening settings."""

    name = "kernel"
    category = "kernel"

    def analyze(self, sysctl_settings: dict[str, str]) -> list[Finding]:
        """Analyze sysctl settings and return findings."""
        findings: list[Finding] = []
        counter = 1
        for key, expectation in SYSCTL_EXPECTATIONS.items():
            actual = sysctl_settings.get(key)
            if actual is None:
                continue
            if actual != expectation["expected"]:
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-KERN-{counter:03d}",
                    title=expectation["title"],
                    severity=expectation["severity"],
                    description=expectation["description"],
                    evidence=[f"{key} = {actual} (expected: {expectation['expected']})"],
                    recommendation=expectation["recommendation"],
                    mitre=expectation["mitre"],
                ))
            counter += 1
        return findings
