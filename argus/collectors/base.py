"""Base collector abstract class for ARGUS data collection."""

from abc import ABC, abstractmethod
from typing import Any

from rich.console import Console

console = Console()


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
