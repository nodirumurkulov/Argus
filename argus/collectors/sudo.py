"""Sudo configuration collector for ARGUS."""

from pathlib import Path

from argus.collectors.base import BaseCollector


class SudoCollector(BaseCollector):
    """Collect and parse sudoers configuration."""

    name = "sudo"

    def collect(self) -> dict[str, list[str]]:
        """Collect sudo configuration from sudoers files.

        Returns a dict mapping usernames/groups to their sudo rules.
        """
        rules: dict[str, list[str]] = {}
        self._parse_sudoers_file("/etc/sudoers", rules)
        self._parse_sudoers_directory("/etc/sudoers.d", rules)
        return rules

    def _parse_sudoers_file(self, path: str, rules: dict[str, list[str]]) -> None:
        """Parse a single sudoers file for user privilege lines."""
        raw = self.safe_read_file(path)
        if raw is None:
            return
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("Defaults"):
                continue
            if "\tALL=" in line or " ALL=" in line or "ALL=(" in line:
                parts = line.split(None, 1)
                if len(parts) >= 1:
                    user_or_group = parts[0]
                    rules.setdefault(user_or_group, []).append(line)

    def _parse_sudoers_directory(
        self, dir_path: str, rules: dict[str, list[str]]
    ) -> None:
        """Parse all files in sudoers.d directory."""
        sudoers_dir = Path(dir_path)
        if not sudoers_dir.is_dir():
            return
        try:
            for entry in sorted(sudoers_dir.iterdir()):
                if entry.is_file() and not entry.name.startswith("."):
                    self._parse_sudoers_file(str(entry), rules)
        except PermissionError:
            pass

    def get_nopasswd_users(self) -> list[str]:
        """Return list of users/groups with NOPASSWD sudo access."""
        rules = self.collect()
        nopasswd: list[str] = []
        for user_or_group, rule_lines in rules.items():
            if any("NOPASSWD" in r for r in rule_lines):
                nopasswd.append(user_or_group)
        return nopasswd

    def get_writable_sudoers_files(self) -> list[str]:
        """Check for writable sudoers include files."""
        import os

        writable: list[str] = []
        sudoers_dir = Path("/etc/sudoers.d")
        if sudoers_dir.is_dir():
            try:
                for entry in sudoers_dir.iterdir():
                    if entry.is_file() and os.access(str(entry), os.W_OK):
                        writable.append(str(entry))
            except PermissionError:
                pass
        return writable
