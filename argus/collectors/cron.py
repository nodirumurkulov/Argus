"""Cron job collector for ARGUS."""

from pathlib import Path

from argus.collectors.base import BaseCollector
from argus.models import CronEntry


class CronCollector(BaseCollector):
    """Collect cron job entries from system and user crontabs."""

    name = "cron"

    def collect(self) -> list[CronEntry]:
        """Collect all cron entries from system and user crontabs."""
        entries: list[CronEntry] = []
        self._parse_system_crontab(entries)
        self._parse_cron_directory("/etc/cron.d", entries)
        self._collect_user_crontabs(entries)
        return entries

    def _parse_system_crontab(self, entries: list[CronEntry]) -> None:
        """Parse /etc/crontab for system-wide cron entries."""
        raw = self.safe_read_file("/etc/crontab")
        if raw is None:
            return
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 7:
                entries.append(CronEntry(
                    schedule=" ".join(parts[:5]),
                    user=parts[5],
                    command=" ".join(parts[6:]),
                    source_file="/etc/crontab",
                ))

    def _parse_cron_directory(
        self, dir_path: str, entries: list[CronEntry]
    ) -> None:
        """Parse all files in a cron directory (e.g. /etc/cron.d/)."""
        cron_dir = Path(dir_path)
        if not cron_dir.is_dir():
            return
        try:
            for entry in sorted(cron_dir.iterdir()):
                if entry.is_file() and not entry.name.startswith("."):
                    raw = self.safe_read_file(str(entry))
                    if raw is None:
                        continue
                    for line in raw.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) >= 7:
                            entries.append(CronEntry(
                                schedule=" ".join(parts[:5]),
                                user=parts[5],
                                command=" ".join(parts[6:]),
                                source_file=str(entry),
                            ))
        except PermissionError:
            pass

    def _collect_user_crontabs(self, entries: list[CronEntry]) -> None:
        """Collect user crontabs via crontab -l for known users."""
        spool_dir = Path("/var/spool/cron/crontabs")
        if not spool_dir.is_dir():
            return
        try:
            for entry in sorted(spool_dir.iterdir()):
                if entry.is_file():
                    raw = self.safe_read_file(str(entry))
                    if raw is None:
                        continue
                    for line in raw.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) >= 6:
                            entries.append(CronEntry(
                                schedule=" ".join(parts[:5]),
                                user=entry.name,
                                command=" ".join(parts[5:]),
                                source_file=str(entry),
                            ))
        except PermissionError:
            pass
