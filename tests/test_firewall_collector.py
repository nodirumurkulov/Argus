"""Firewall collector tests."""

from argus.analyzers.firewall import FirewallAnalyzer
from argus.collectors.firewall import FirewallCollector
from argus.models import FirewallStatus


class FakeFirewallCollector(FirewallCollector):
    """Firewall collector with deterministic command output."""

    def __init__(self, outputs: dict[tuple[str, ...], str | None]) -> None:
        self.outputs = outputs

    def safe_run_command(self, command: list[str]) -> str | None:
        return self.outputs.get(tuple(command))


def test_inactive_ufw_does_not_hide_active_nftables() -> None:
    """Inactive ufw should fall through to active nftables rules."""
    collector = FakeFirewallCollector(
        {
            ("ufw", "status", "verbose"): "Status: inactive\n",
            ("nft", "list", "ruleset"): (
                "table inet filter {\n"
                "chain input { type filter hook input priority 0; policy drop; }\n"
                "}\n"
            ),
            ("iptables", "-S"): None,
        }
    )

    status = collector.collect()

    assert status.active is True
    assert status.backend == "nftables"
    assert status.detected_backends == ["ufw", "nftables"]
    assert status.default_policy == "drop"


def test_inactive_ufw_does_not_hide_active_iptables() -> None:
    """Inactive ufw should fall through to active iptables rules."""
    collector = FakeFirewallCollector(
        {
            ("ufw", "status", "verbose"): "Status: inactive\n",
            ("nft", "list", "ruleset"): None,
            ("iptables", "-S"): "-P INPUT DROP\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n",
        }
    )

    status = collector.collect()

    assert status.active is True
    assert status.backend == "iptables"
    assert status.detected_backends == ["ufw", "iptables"]
    assert status.default_policy == "DROP"


def test_active_ufw_remains_preferred_over_later_backends() -> None:
    """Active ufw should remain the selected backend when others are also active."""
    collector = FakeFirewallCollector(
        {
            ("ufw", "status", "verbose"): "Status: active\nDefault: deny (incoming)\n",
            ("nft", "list", "ruleset"): (
                "table inet filter {\n"
                "chain input { type filter hook input priority 0; policy drop; }\n"
                "}\n"
            ),
            ("iptables", "-S"): "-P INPUT DROP\n",
        }
    )

    status = collector.collect()

    assert status.active is True
    assert status.backend == "ufw"
    assert status.detected_backends == ["ufw", "nftables", "iptables"]
    assert status.default_policy == "deny (incoming)"


def test_no_backend_returns_inactive_default_status() -> None:
    """Missing firewall commands should produce an inactive empty status."""
    collector = FakeFirewallCollector(
        {
            ("ufw", "status", "verbose"): None,
            ("nft", "list", "ruleset"): None,
            ("iptables", "-S"): None,
        }
    )

    status = collector.collect()

    assert status.active is False
    assert status.backend == ""
    assert status.detected_backends == []
    assert status.default_policy == ""


def test_iptables_accept_policy_without_rules_is_inactive() -> None:
    """A permissive iptables INPUT policy alone should not count as active filtering."""
    collector = FakeFirewallCollector(
        {
            ("ufw", "status", "verbose"): None,
            ("nft", "list", "ruleset"): None,
            ("iptables", "-S"): "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n",
        }
    )

    status = collector.collect()

    assert status.active is False
    assert status.backend == "iptables"
    assert status.detected_backends == ["iptables"]
    assert status.default_policy == "ACCEPT"


def test_iptables_explicit_rules_are_active() -> None:
    """Explicit iptables rules should count as active filtering."""
    collector = FakeFirewallCollector(
        {
            ("ufw", "status", "verbose"): None,
            ("nft", "list", "ruleset"): None,
            ("iptables", "-S"): "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j DROP\n",
        }
    )

    status = collector.collect()

    assert status.active is True
    assert status.backend == "iptables"
    assert status.default_policy == "ACCEPT"


def test_analyzer_does_not_report_disabled_when_fallback_backend_is_active() -> None:
    """Active fallback status should not produce a disabled firewall finding."""
    firewall = FirewallStatus(
        active=True,
        backend="nftables",
        detected_backends=["ufw", "nftables"],
        default_policy="drop",
    )

    findings = FirewallAnalyzer().analyze(firewall)

    assert [finding.id for finding in findings] == []
