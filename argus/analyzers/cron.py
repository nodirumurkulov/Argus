"""Cron job security analyzer for ARGUS."""

from pathlib import Path

from argus.analyzers.base import BaseAnalyzer
from argus.models import CronEntry, Finding
from argus.permissions import is_group_or_world_writable


SUSPICIOUS_COMMANDS = [
    "curl ", "wget ", "nc ", "ncat ",
    "/dev/tcp/", "base64", "eval ",
    "python -c", "python3 -c", "bash -i",
    "nohup ", "/tmp/", "chmod 777",
]


def _id_fragment(value: str) -> str:
    """Create a compact finding ID fragment from user-controlled text."""
    fragment = "".join(char if char.isalnum() else "-" for char in value.lower())
    return fragment.strip("-")[:40] or "unknown"


class CronAnalyzer(BaseAnalyzer):
    """Analyze cron job entries for security issues."""

    name = "cron"
    category = "persistence"

    def analyze(self, cron_entries: list[CronEntry]) -> list[Finding]:
        """Analyze cron entries and return findings."""
        findings: list[Finding] = []
        self._check_suspicious_commands(cron_entries, findings)
        self._check_root_cron_jobs(cron_entries, findings)
        self._check_world_writable_scripts(cron_entries, findings)
        return findings

    def _check_suspicious_commands(
        self, entries: list[CronEntry], findings: list[Finding]
    ) -> None:
        """Check for cron entries with suspicious commands."""
        for index, entry in enumerate(entries, 1):
            cmd_lower = entry.command.lower()
            matched = [p for p in SUSPICIOUS_COMMANDS if p in cmd_lower]
            if matched:
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-CRON-001-{index:03d}-{_id_fragment(entry.user)}",
                    title="Suspicious cron job detected",
                    severity="high",
                    description=(
                        f"Cron job for user '{entry.user}' contains suspicious "
                        f"commands: {', '.join(matched)}"
                    ),
                    evidence=[
                        f"Schedule: {entry.schedule}",
                        f"User: {entry.user}",
                        f"Command: {entry.command}",
                        f"Source: {entry.source_file}",
                    ],
                    recommendation="Review this cron entry and remove if unauthorized.",
                    mitre=["T1053.003"],
                ))

    def _check_root_cron_jobs(
        self, entries: list[CronEntry], findings: list[Finding]
    ) -> None:
        """Report cron jobs running as root for awareness."""
        root_entries = [e for e in entries if e.user == "root"]
        if len(root_entries) > 10:
            findings.append(self._make_finding(
                finding_id="ARGUS-CRON-002",
                title=f"Large number of root cron jobs ({len(root_entries)})",
                severity="info",
                description=(
                    f"Found {len(root_entries)} cron jobs running as root. "
                    "Review for unnecessary privilege."
                ),
                evidence=[f"Root cron count: {len(root_entries)}"],
                recommendation="Audit root cron jobs and run as least-privilege users where possible.",
                mitre=["T1053.003"],
            ))

    def _check_world_writable_scripts(
        self, entries: list[CronEntry], findings: list[Finding]
    ) -> None:
        """Check if cron jobs reference group/world-writable scripts."""
        for index, entry in enumerate(entries, 1):
            cmd_parts = entry.command.split()
            if not cmd_parts:
                continue
            script = cmd_parts[0]
            script_path = Path(script)
            if (
                not script.startswith("/")
                or not script_path.is_file()
                or not is_group_or_world_writable(script_path)
            ):
                continue
            findings.append(self._make_finding(
                finding_id=f"ARGUS-CRON-003-{index:03d}",
                title="Cron job references group/world-writable script",
                severity="high",
                description=(
                    f"Cron job for '{entry.user}' runs '{script}' which is writable "
                    "by group or other users. An attacker could modify this script."
                ),
                evidence=[
                    f"User: {entry.user}",
                    f"Script: {script}",
                    f"Schedule: {entry.schedule}",
                ],
                recommendation=f"Fix permissions: chmod 755 {script}",
                mitre=["T1053.003"],
            ))
