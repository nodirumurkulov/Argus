"""Firewall status collector for ARGUS."""

from argus.collectors.base import BaseCollector
from argus.models import FirewallStatus


class FirewallCollector(BaseCollector):
    """Collect firewall status from ufw and iptables."""

    name = "firewall"

    def collect(self) -> FirewallStatus:
        """Collect firewall status, trying ufw first then iptables."""
        status = self._collect_ufw()
        if status.backend:
            return status
        return self._collect_iptables()

    def _collect_ufw(self) -> FirewallStatus:
        """Collect firewall status from ufw."""
        output = self.safe_run_command(["ufw", "status", "verbose"])
        if output is None:
            return FirewallStatus()
        status = FirewallStatus(backend="ufw")
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Status:"):
                active_str = line.split(":", 1)[1].strip()
                status.active = active_str.lower() == "active"
            elif line.startswith("Default:"):
                status.default_policy = line.split(":", 1)[1].strip()
            elif line and not line.startswith("--") and not line.startswith("To"):
                if "ALLOW" in line or "DENY" in line or "REJECT" in line:
                    status.rules.append(line)
        return status
