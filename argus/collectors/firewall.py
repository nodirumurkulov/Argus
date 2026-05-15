"""Firewall status collector for ARGUS."""

from argus.collectors.base import BaseCollector
from argus.models import FirewallStatus


class FirewallCollector(BaseCollector):
    """Collect firewall status from ufw and iptables."""

    name = "firewall"

    @staticmethod
    def _merge_detected_backends(statuses: list[FirewallStatus]) -> list[str]:
        """Return all firewall backends detected during collection."""
        return [status.backend for status in statuses if status.backend]

    @staticmethod
    def _select_status(statuses: list[FirewallStatus]) -> FirewallStatus:
        """Prefer the first active backend, falling back to first detected backend."""
        detected = FirewallCollector._merge_detected_backends(statuses)
        for status in statuses:
            if status.active:
                status.detected_backends = detected
                return status
        for status in statuses:
            if status.backend:
                status.detected_backends = detected
                return status
        return FirewallStatus(detected_backends=detected)

    def collect(self) -> FirewallStatus:
        """Collect firewall status, trying ufw first then nftables then iptables."""
        statuses = [
            self._collect_ufw(),
            self._collect_nftables(),
            self._collect_iptables(),
        ]
        return self._select_status(statuses)

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

    def _collect_nftables(self) -> FirewallStatus:
        """Collect firewall rules from nftables."""
        output = self.safe_run_command(["nft", "list", "ruleset"])
        if output is None:
            return FirewallStatus()
        rules = [
            line.strip()
            for line in output.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not rules:
            return FirewallStatus()
        return FirewallStatus(
            active=bool(rules),
            backend="nftables",
            rules=rules[:50],
        )

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
