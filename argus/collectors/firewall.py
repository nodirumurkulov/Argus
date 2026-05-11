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

    def _collect_iptables(self) -> FirewallStatus:
        """Collect firewall rules from iptables as fallback."""
        output = self.safe_run_command(["iptables", "-S"])
        if output is None:
            return FirewallStatus()
        rules = [
            line.strip()
            for line in output.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        has_rules = any(
            rule for rule in rules if not rule.startswith("-P")
        )
        default_policy = ""
        for rule in rules:
            if rule.startswith("-P INPUT"):
                default_policy = rule.split()[-1] if len(rule.split()) >= 3 else ""
                break
        return FirewallStatus(
            active=has_rules or bool(rules),
            backend="iptables",
            rules=rules,
            default_policy=default_policy,
        )
