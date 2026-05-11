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
