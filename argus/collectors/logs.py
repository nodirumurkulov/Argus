"""Log file collector for ARGUS."""

import re
from pathlib import Path

from argus.collectors.base import BaseCollector

DEFAULT_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/secure",
]


class LogCollector(BaseCollector):
    """Collect and read system log files.

    Supports plain-text, ``.gz`` compressed, and rotated archives.
    """

    name = "logs"

    ROTATED_RE = re.compile(r"\.(\d+)(\.gz)?$")

    @staticmethod
    def discover_rotated_paths(base_path: str) -> list[str]:
        """Return a sorted list of rotated archive paths for *base_path*.

        Scans the parent directory for files matching ``base_path.1``,
        ``base_path.2.gz``, etc., ordered from newest to oldest.
        """
        p = Path(base_path)
        parent = p.parent
        stem = p.name
        candidates: list[tuple[int, str]] = []
        if not parent.is_dir():
            return []
        for entry in parent.iterdir():
            ename = entry.name
            if not ename.startswith(stem) or ename == stem:
                continue
            suffix = ename[len(stem):]
            m = LogCollector.ROTATED_RE.match(suffix)
            if m:
                candidates.append((int(m.group(1)), str(entry)))
        candidates.sort(key=lambda x: x[0])
        return [path for _, path in candidates]

    def collect(
        self,
        log_path: str | None = None,
        max_lines: int | None = 200_000,
        discover_rotated: bool = False,
    ) -> list[str]:
        """Read log file lines.

        Parameters
        ----------
        log_path:
            Specific file to read.  When ``None``, tries *DEFAULT_LOG_PATHS*.
        max_lines:
            Maximum lines to return per file.  ``None`` means no limit.
        discover_rotated:
            When true, also read rotated archives newer than *log_path*.
        """
        if log_path is None:
            for path in DEFAULT_LOG_PATHS:
                lines = self._read_log(path, max_lines)
                if lines:
                    return lines
            return []

        lines = self._read_log(log_path, max_lines)
        if discover_rotated and lines is not None:
            for rotated in self.discover_rotated_paths(log_path):
                more = self._read_log(rotated, max_lines)
                if more:
                    lines = more + lines
        return lines or []

    def _read_log(
        self,
        path: str,
        max_lines: int | None = 200_000,
    ) -> list[str] | None:
        """Read a log file and return its non-empty lines."""
        p = Path(path)
        if not p.is_file():
            return None
        return self.safe_read_lines(str(p), max_lines)

    def collect_multiple(
        self,
        paths: list[str],
        max_lines: int | None = 200_000,
    ) -> dict[str, list[str]]:
        """Read multiple log files and return a dict of path -> lines."""
        result: dict[str, list[str]] = {}
        for path in paths:
            lines = self._read_log(path, max_lines)
            if lines:
                result[path] = lines
        return result
