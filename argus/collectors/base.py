"""Base collector abstract class for ARGUS data collection."""

import gzip
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()

_LOG_DEFAULT_MAX_LINES = 200_000


class BaseCollector(ABC):
    """Abstract base class for all ARGUS data collectors.

    Collectors are read-only — they gather system information
    without modifying any files or configurations.
    """

    name: str = "base"

    @abstractmethod
    def collect(self) -> Any:
        """Collect and return system data. Must be implemented by subclasses."""

    def safe_read_file(self, path: str) -> str | None:
        """Read a file safely, returning None if it doesn't exist or isn't readable."""
        try:
            with open(path) as f:
                return f.read()
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def safe_run_command(self, command: list[str]) -> str | None:
        """Run a command safely, returning stdout or None on failure."""
        import subprocess

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def safe_read_lines(
        self,
        path: str,
        max_lines: int | None = _LOG_DEFAULT_MAX_LINES,
    ) -> list[str]:
        """Read lines from a file with an optional cap.

        Supports plain text and ``.gz`` compressed files.
        Returns the last *max_lines* non-empty lines present in the file.
        """
        p = Path(path)
        if not p.is_file():
            return []
        try:
            if path.endswith(".gz"):
                return self._read_lines_gzip(path, max_lines)
            return self._read_lines_plain(path, max_lines)
        except (OSError, PermissionError, gzip.BadGzipFile):
            return []

    @staticmethod
    def _read_lines_plain(path: str, max_lines: int | None) -> list[str]:
        lines: list[str] = []
        with open(path) as f:
            for raw in f:
                line = raw.strip()
                if line:
                    lines.append(line)
        if max_lines is not None and len(lines) > max_lines:
            lines = lines[-max_lines:]
        return lines

    @staticmethod
    def _read_lines_gzip(path: str, max_lines: int | None) -> list[str]:
        lines: list[str] = []
        with gzip.open(path, "rt") as f:
            for raw in f:
                line = raw.strip()
                if line:
                    lines.append(line)
        if max_lines is not None and len(lines) > max_lines:
            lines = lines[-max_lines:]
        return lines
