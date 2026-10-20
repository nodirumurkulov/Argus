"""Security analysis engine — runs all analyzers against collected data."""

from rich.console import Console

from argus.analyzers.cron import CronAnalyzer
from argus.analyzers.firewall import FirewallAnalyzer
from argus.analyzers.kernel import KernelAnalyzer
from argus.analyzers.network import NetworkAnalyzer
from argus.analyzers.packages import PackageAnalyzer
from argus.analyzers.persistence import PersistenceAnalyzer
from argus.analyzers.ssh import SSHAnalyzer
from argus.analyzers.sudo import SudoAnalyzer
from argus.analyzers.systemd import SystemdAnalyzer
from argus.analyzers.users import UserAnalyzer
from argus.collectors.packages import PackageCollector
from argus.collectors.sudo import SudoCollector
from argus.models import Finding, HostData

console = Console()


def run_all_analyzers(host_data: HostData, verbose: bool = False) -> list[Finding]:
    """Run all security analyzers against collected host data."""
    all_findings: list[Finding] = []

    analyzers = [
        ("SSH", _analyze_ssh),
        ("Users", _analyze_users),
        ("Sudo", _analyze_sudo),
        ("Cron", _analyze_cron),
        ("Systemd", _analyze_systemd),
        ("Firewall", _analyze_firewall),
        ("Network", _analyze_network),
        ("Packages", _analyze_packages),
        ("Kernel", _analyze_kernel),
        ("Persistence", _analyze_persistence),
    ]

    for name, analyzer_fn in analyzers:
        try:
            findings = analyzer_fn(host_data)
            all_findings.extend(findings)
            if verbose:
                console.print(
                    f"  [dim]{name}:[/dim] {len(findings)} finding(s)"
                )
        except Exception as e:  # noqa: BLE001 - One failed analyzer must not stop the scan.
            if verbose:
                console.print(f"  [yellow]Warning:[/yellow] {name}: {e}")

    return all_findings


def _analyze_ssh(host_data: HostData) -> list[Finding]:
    return SSHAnalyzer().analyze(host_data.ssh_config)


def _analyze_users(host_data: HostData) -> list[Finding]:
    return UserAnalyzer().analyze(host_data.users)


def _analyze_sudo(host_data: HostData) -> list[Finding]:
    sudo_collector = SudoCollector()
    sudo_rules = sudo_collector.collect()
    writable = sudo_collector.get_writable_sudoers_files()
    return SudoAnalyzer().analyze(host_data.users, sudo_rules, writable)


def _analyze_cron(host_data: HostData) -> list[Finding]:
    return CronAnalyzer().analyze(host_data.cron_entries)


def _analyze_systemd(host_data: HostData) -> list[Finding]:
    return SystemdAnalyzer().analyze(host_data.systemd_services)


def _analyze_firewall(host_data: HostData) -> list[Finding]:
    return FirewallAnalyzer().analyze(host_data.firewall)


def _analyze_network(host_data: HostData) -> list[Finding]:
    return NetworkAnalyzer().analyze(host_data.network_connections)


def _analyze_packages(host_data: HostData) -> list[Finding]:
    pkg_collector = PackageCollector()
    security_status = pkg_collector.get_security_packages()
    return PackageAnalyzer().analyze(security_status)


def _analyze_kernel(host_data: HostData) -> list[Finding]:
    return KernelAnalyzer().analyze(host_data.sysctl_settings)


def _analyze_persistence(host_data: HostData) -> list[Finding]:
    return PersistenceAnalyzer().analyze(host_data.persistence_locations)
