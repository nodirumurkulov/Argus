"""Sudo configuration collector for ARGUS."""

from pathlib import Path

from argus.collectors.base import BaseCollector
from argus.permissions import is_group_or_world_writable


SUDOERS_FILE = "/etc/sudoers"
SUDOERS_DIR = "/etc/sudoers.d"


class SudoCollector(BaseCollector):
    """Collect and parse sudoers configuration."""

    name = "sudo"

    def collect(self) -> dict[str, list[str]]:
        """Collect sudo configuration from sudoers files.

        Returns a dict mapping usernames/groups to their sudo rules.
        """
        rules: dict[str, list[str]] = {}
        self._parse_sudoers_file(SUDOERS_FILE, rules)
        self._parse_sudoers_directory(SUDOERS_DIR, rules)
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
        """Check for group/world-writable sudoers files."""
        writable: list[str] = []
        sudoers_file = Path(SUDOERS_FILE)
        if sudoers_file.is_file() and is_group_or_world_writable(sudoers_file):
            writable.append(str(sudoers_file))
        sudoers_dir = Path(SUDOERS_DIR)
        if sudoers_dir.is_dir():
            try:
                for entry in sudoers_dir.iterdir():
                    if entry.is_file() and is_group_or_world_writable(entry):
                        writable.append(str(entry))
            except PermissionError:
                pass
        return writable
