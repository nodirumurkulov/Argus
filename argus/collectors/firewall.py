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
        status = FirewallStatus(backend="ufw", detected_backends=["ufw"])
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
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
        default_policy = self._extract_nftables_input_policy(rules)
        return FirewallStatus(
            active=self._nftables_has_filtering_rules(rules),
            backend="nftables",
            detected_backends=["nftables"],
            rules=rules[:50],
            default_policy=default_policy,
        )

    @staticmethod
    def _nftables_has_filtering_rules(rules: list[str]) -> bool:
        """Return true when nftables output contains meaningful filter rules."""
        return any(
            " accept" in rule or " drop" in rule or " reject" in rule
            for rule in rules
        )

    @staticmethod
    def _extract_nftables_input_policy(rules: list[str]) -> str:
        """Extract the nftables input chain policy when present."""
        for rule in rules:
            if "hook input" in rule and "policy" in rule:
                parts = rule.split("policy", 1)[1].strip().split()
                if parts:
                    return parts[0].rstrip(";")
        return ""

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
        default_policy = self._extract_iptables_input_policy(rules)
        return FirewallStatus(
            active=self._iptables_has_active_policy_or_rules(rules, default_policy),
            backend="iptables",
            detected_backends=["iptables"],
            rules=rules,
            default_policy=default_policy,
        )

    @staticmethod
    def _extract_iptables_input_policy(rules: list[str]) -> str:
        """Extract the iptables INPUT default policy."""
        for rule in rules:
            if rule.startswith("-P INPUT"):
                return rule.split()[-1] if len(rule.split()) >= 3 else ""
        return ""

    @staticmethod
    def _iptables_has_active_policy_or_rules(rules: list[str], default_policy: str) -> bool:
        """Return true when iptables has filtering rules or a restrictive INPUT policy."""
        has_explicit_rules = any(rule for rule in rules if not rule.startswith("-P"))
        return has_explicit_rules or default_policy.upper() in {"DROP", "REJECT"}
