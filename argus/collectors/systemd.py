"""Systemd service and timer collector for ARGUS."""

import os
from pathlib import Path

from argus.collectors.base import BaseCollector
from argus.models import SystemdService


SYSTEMD_PATHS = [
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
]


class SystemdCollector(BaseCollector):
    """Collect systemd service and timer unit information."""

    name = "systemd"

    def collect(self) -> list[SystemdService]:
        """Collect systemd service units from all standard paths."""
        services: list[SystemdService] = []
        self._collect_from_unit_files(services)
        self._collect_enabled_status(services)
        return services

    def _collect_from_unit_files(self, services: list[SystemdService]) -> None:
        """Scan systemd unit directories for service files."""
        seen_names: set[str] = set()
        for base_path in SYSTEMD_PATHS:
            unit_dir = Path(base_path)
            if not unit_dir.is_dir():
                continue
            try:
                for entry in sorted(unit_dir.iterdir()):
                    if not entry.name.endswith(".service"):
                        continue
                    if entry.name in seen_names:
                        continue
                    seen_names.add(entry.name)
                    service = self._parse_unit_file(entry)
                    if service:
                        services.append(service)
            except PermissionError:
                pass

    def _parse_unit_file(self, path: Path) -> SystemdService | None:
        """Parse a single systemd unit file."""
        raw = self.safe_read_file(str(path))
        if raw is None:
            return None
        service = SystemdService(
            name=path.name,
            unit_file=str(path),
            writable=os.access(str(path), os.W_OK),
        )
        section = ""
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("["):
                section = line.strip("[]")
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if section == "Unit" and key == "Description":
                service.description = value
            elif section == "Service" and key == "ExecStart":
                service.exec_start = value
            elif section == "Service" and key == "User":
                service.user = value
        return service

    def _collect_enabled_status(self, services: list[SystemdService]) -> None:
        """Check enabled/disabled status using systemctl."""
        output = self.safe_run_command(
            ["systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend"]
        )
        if output is None:
            return
        enabled_units: dict[str, str] = {}
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                enabled_units[parts[0]] = parts[1]
        for service in services:
            status = enabled_units.get(service.name, "")
            service.state = status
            service.enabled = status in ("enabled", "enabled-runtime", "static")
