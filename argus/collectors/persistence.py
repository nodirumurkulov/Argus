"""Persistence location scanner for ARGUS."""

from pathlib import Path

from argus.collectors.base import BaseCollector
from argus.permissions import is_executable_by_mode, is_group_or_world_writable

PERSISTENCE_PATHS = [
    "/etc/rc.local",
    "/etc/init.d",
    "/etc/profile.d",
    "/etc/bash.bashrc",
    "/etc/environment",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
]

STARTUP_SCRIPT_DIRS = [
    "/etc/profile.d",
    "/etc/init.d",
]


class PersistenceCollector(BaseCollector):
    """Scan for persistence mechanisms in common startup locations."""

    name = "persistence"

    def collect(self) -> list[str]:
        """Collect paths where persistence mechanisms may exist."""
        findings: list[str] = []
        self._check_persistence_files(findings)
        self._scan_startup_directories(findings)
        self._scan_shell_rc_files(findings)
        return findings

    def _check_persistence_files(self, findings: list[str]) -> None:
        """Check standard persistence file locations."""
        for path in PERSISTENCE_PATHS:
            p = Path(path)
            if not p.exists():
                continue
            if is_group_or_world_writable(path):
                findings.append(f"writable:{path}")
            elif p.is_file():
                findings.append(f"exists:{path}")

    def _scan_startup_directories(self, findings: list[str]) -> None:
        """Scan startup directories for scripts."""
        for dir_path in STARTUP_SCRIPT_DIRS:
            d = Path(dir_path)
            if not d.is_dir():
                continue
            try:
                for entry in sorted(d.iterdir()):
                    if (
                        entry.is_file()
                        and entry.suffix in (".sh", "")
                        and is_executable_by_mode(entry)
                    ):
                        findings.append(f"startup_script:{entry}")
            except PermissionError:
                pass

    def _scan_shell_rc_files(self, findings: list[str]) -> None:
        """Scan user home directories for suspicious shell rc files."""
        passwd = self.safe_read_file("/etc/passwd")
        if passwd is None:
            return
        for line in passwd.splitlines():
            parts = line.strip().split(":")
            if len(parts) < 6:
                continue
            home = parts[5]
            if not Path(home).is_dir():
                continue
            for rc_file in [".bashrc", ".bash_profile", ".profile"]:
                rc_path = Path(home) / rc_file
                if rc_path.is_file():
                    content = self.safe_read_file(str(rc_path))
                    if content and self._has_suspicious_content(content):
                        findings.append(f"suspicious_rc:{rc_path}")

    def _has_suspicious_content(self, content: str) -> bool:
        """Check if shell rc file contains suspicious patterns."""
        suspicious_patterns = [
            "curl ",
            "wget ",
            "nc ",
            "ncat ",
            "/dev/tcp/",
            "base64",
            "eval ",
            "exec ",
            "python -c",
            "python3 -c",
            "bash -i",
            "nohup ",
        ]
        lower_content = content.lower()
        return any(pattern in lower_content for pattern in suspicious_patterns)
