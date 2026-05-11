"""Host data aggregator for ARGUS."""

import platform
import socket

from argus.collectors.base import BaseCollector
from argus.models import HostData


class HostCollector(BaseCollector):
    """Collect basic host information (hostname, kernel, OS)."""

    name = "host"

    def collect(self) -> HostData:
        """Collect basic host system information."""
        host_data = HostData()
        host_data.hostname = self._get_hostname()
        host_data.kernel_version = self._get_kernel_version()
        host_data.os_release = self._get_os_release()
        host_data.uptime = self._get_uptime()
        host_data.sysctl_settings = self._get_sysctl_settings()
        return host_data

    def _get_hostname(self) -> str:
        """Get system hostname."""
        try:
            return socket.gethostname()
        except OSError:
            return "unknown"

    def _get_kernel_version(self) -> str:
        """Get kernel version string."""
        return platform.release()

    def _get_os_release(self) -> str:
        """Get OS release info from /etc/os-release."""
        raw = self.safe_read_file("/etc/os-release")
        if raw is None:
            return platform.platform()
        for line in raw.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
        return platform.platform()

    def _get_uptime(self) -> str:
        """Get system uptime from /proc/uptime."""
        raw = self.safe_read_file("/proc/uptime")
        if raw is None:
            return "unknown"
        try:
            seconds = float(raw.split()[0])
            days = int(seconds // 86400)
            hours = int((seconds % 86400) // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{days}d {hours}h {minutes}m"
        except (ValueError, IndexError):
            return "unknown"

    def _get_sysctl_settings(self) -> dict[str, str]:
        """Collect security-relevant sysctl settings."""
        settings: dict[str, str] = {}
        sysctl_keys = [
            "net.ipv4.ip_forward",
            "net.ipv4.conf.all.accept_redirects",
            "net.ipv4.conf.all.send_redirects",
            "net.ipv4.conf.all.accept_source_route",
            "net.ipv4.conf.all.log_martians",
            "net.ipv4.tcp_syncookies",
            "kernel.randomize_va_space",
            "kernel.exec-shield",
            "kernel.dmesg_restrict",
            "kernel.kptr_restrict",
            "fs.suid_dumpable",
            "fs.protected_hardlinks",
            "fs.protected_symlinks",
        ]
        for key in sysctl_keys:
            proc_path = f"/proc/sys/{key.replace('.', '/')}"
            value = self.safe_read_file(proc_path)
            if value is not None:
                settings[key] = value.strip()
        return settings
