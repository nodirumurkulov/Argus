"""Log file collector for ARGUS."""

from pathlib import Path

from argus.collectors.base import BaseCollector


DEFAULT_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/auth.log.1",
    "/var/log/syslog",
    "/var/log/secure",
]


class LogCollector(BaseCollector):
    """Collect and read system log files."""

    name = "logs"

    def collect(self, log_path: str | None = None) -> list[str]:
        """Read log file lines. If no path given, tries default locations."""
        if log_path:
            return self._read_log(log_path)
        for path in DEFAULT_LOG_PATHS:
            lines = self._read_log(path)
            if lines:
                return lines
        return []

    def _read_log(self, path: str) -> list[str]:
        """Read a log file and return its lines."""
        p = Path(path)
        if not p.is_file():
            return []
        raw = self.safe_read_file(path)
        if raw is None:
            return []
        return [line for line in raw.splitlines() if line.strip()]

    def collect_multiple(self, paths: list[str]) -> dict[str, list[str]]:
        """Read multiple log files and return a dict of path -> lines."""
        result: dict[str, list[str]] = {}
        for path in paths:
            lines = self._read_log(path)
            if lines:
                result[path] = lines
        return result
