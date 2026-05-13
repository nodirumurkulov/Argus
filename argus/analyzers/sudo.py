"""Sudo privileges security analyzer for ARGUS."""

from argus.analyzers.base import BaseAnalyzer
from argus.models import Finding, UserInfo


def _id_fragment(value: str) -> str:
    """Create a compact finding ID fragment from sudoers subjects and paths."""
    fragment = "".join(char if char.isalnum() else "-" for char in value.lower())
    return fragment.strip("-")[:48] or "unknown"


class SudoAnalyzer(BaseAnalyzer):
    """Analyze sudo configuration for security issues."""

    name = "sudo"
    category = "sudo"

    def analyze(
        self,
        users: list[UserInfo],
        sudo_rules: dict[str, list[str]],
        writable_files: list[str],
    ) -> list[Finding]:
        """Analyze sudo configuration and return findings."""
        findings: list[Finding] = []
        self._check_nopasswd_sudo(users, findings)
        self._check_broad_sudo(sudo_rules, findings)
        self._check_dangerous_commands(sudo_rules, findings)
        self._check_writable_sudoers(writable_files, findings)
        return findings

    def _check_nopasswd_sudo(
        self, users: list[UserInfo], findings: list[Finding]
    ) -> None:
        """Check for users with passwordless sudo access."""
        for user in users:
            if user.sudo_nopasswd:
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-SUDO-001-{user.username}",
                    title=f"User '{user.username}' has passwordless sudo",
                    severity="medium",
                    description=(
                        f"User '{user.username}' can execute commands as root "
                        "without entering a password. If this account is compromised, "
                        "the attacker gains immediate root access."
                    ),
                    evidence=[f"{user.username} NOPASSWD sudo"],
                    recommendation=f"Remove NOPASSWD from sudo rules for '{user.username}'.",
                    mitre=["T1548.003"],
                ))

    def _check_broad_sudo(
        self, sudo_rules: dict[str, list[str]], findings: list[Finding]
    ) -> None:
        """Check for overly permissive sudo rules."""
        for user_or_group, rules in sudo_rules.items():
            for rule in rules:
                if "ALL=(ALL:ALL) ALL" in rule or "ALL=(ALL) ALL" in rule:
                    findings.append(self._make_finding(
                        finding_id=f"ARGUS-SUDO-002-{user_or_group}",
                        title=f"'{user_or_group}' has unrestricted sudo access",
                        severity="medium",
                        description=(
                            f"'{user_or_group}' has full sudo access to all commands. "
                            "Consider restricting to specific commands needed."
                        ),
                        evidence=[rule],
                        recommendation="Restrict sudo access to specific commands.",
                        mitre=["T1548.003"],
                    ))
                    break

    def _check_dangerous_commands(
        self, sudo_rules: dict[str, list[str]], findings: list[Finding]
    ) -> None:
        """Check for sudo rules allowing dangerous privilege escalation commands."""
        escalation_commands = [
            "/bin/bash", "/bin/sh", "/usr/bin/python",
            "/usr/bin/python3", "/usr/bin/perl", "/usr/bin/ruby",
            "/usr/bin/env", "/usr/bin/find", "/usr/bin/vim",
            "/usr/bin/vi", "/usr/bin/less", "/usr/bin/more",
            "/usr/bin/awk", "/usr/bin/nmap", "/usr/bin/git",
            "/usr/bin/docker", "/usr/bin/tar",
        ]
        for user_or_group, rules in sudo_rules.items():
            for rule in rules:
                rule_lower = rule.lower()
                found = [cmd for cmd in escalation_commands if cmd in rule_lower]
                if found:
                    findings.append(self._make_finding(
                        finding_id=f"ARGUS-SUDO-004-{user_or_group}",
                        title=f"'{user_or_group}' can sudo escalation-capable commands",
                        severity="high",
                        description=(
                            f"'{user_or_group}' can sudo commands that enable privilege "
                            f"escalation: {', '.join(found)}"
                        ),
                        evidence=[rule],
                        recommendation="Restrict sudo to only required commands.",
                        mitre=["T1548.003"],
                    ))
                    break

    def _check_writable_sudoers(
        self, writable_files: list[str], findings: list[Finding]
    ) -> None:
        """Check for writable sudoers include files."""
        for path in writable_files:
            findings.append(self._make_finding(
                finding_id=f"ARGUS-SUDO-003-{_id_fragment(path)}",
                title="Writable sudoers include file found",
                severity="high",
                description=(
                    f"Sudoers include file '{path}' is writable. An attacker could "
                    "modify this file to escalate privileges."
                ),
                evidence=[f"writable: {path}"],
                recommendation=f"Fix permissions: chmod 440 {path}",
                mitre=["T1548.003"],
            ))
