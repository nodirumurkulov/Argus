"""Host data aggregation — combines all collectors into a single HostData."""

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from argus.collectors.cron import CronCollector
from argus.collectors.firewall import FirewallCollector
from argus.collectors.host import HostCollector
from argus.collectors.network import NetworkCollector
from argus.collectors.packages import PackageCollector
from argus.collectors.persistence import PersistenceCollector
from argus.collectors.ssh import SSHCollector
from argus.collectors.sudo import SudoCollector
from argus.collectors.systemd import SystemdCollector
from argus.collectors.users import UserCollector
from argus.models import HostData

console = Console()


def collect_host_data(verbose: bool = False) -> HostData:
    """Run all collectors and aggregate results into HostData."""
    host_collector = HostCollector()
    host_data = host_collector.collect()

    collectors = [
        ("SSH configuration", _collect_ssh, host_data),
        ("Local users", _collect_users, host_data),
        ("Sudo privileges", _collect_sudo, host_data),
        ("Open ports", _collect_network, host_data),
        ("Cron jobs", _collect_cron, host_data),
        ("Systemd services", _collect_systemd, host_data),
        ("Firewall status", _collect_firewall, host_data),
        ("Package inventory", _collect_packages, host_data),
        ("Persistence locations", _collect_persistence, host_data),
    ]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Collecting host data...", total=len(collectors))
        for description, collector_fn, data in collectors:
            progress.update(task, description=f"Collecting {description}...")
            try:
                collector_fn(data)
            except Exception as e:  # noqa: BLE001 - Keep collecting when one source fails.
                if verbose:
                    console.print(f"[yellow]Warning:[/yellow] {description}: {e}")
            progress.advance(task)
            console.print(f"  [green]✓[/green] {description}")

    return host_data


def _collect_ssh(host_data: HostData) -> None:
    host_data.ssh_config = SSHCollector().collect()


def _collect_users(host_data: HostData) -> None:
    host_data.users = UserCollector().collect()


def _collect_sudo(host_data: HostData) -> None:
    sudo_rules = SudoCollector().collect()
    for user in host_data.users:
        if user.username in sudo_rules:
            user.sudo_access = True
            rules = sudo_rules[user.username]
            user.sudo_nopasswd = any("NOPASSWD" in r for r in rules)
        for group in user.groups:
            group_key = f"%{group}"
            if group_key in sudo_rules:
                user.sudo_access = True
                rules = sudo_rules[group_key]
                if any("NOPASSWD" in r for r in rules):
                    user.sudo_nopasswd = True


def _collect_network(host_data: HostData) -> None:
    host_data.network_connections = NetworkCollector().collect()


def _collect_cron(host_data: HostData) -> None:
    host_data.cron_entries = CronCollector().collect()


def _collect_systemd(host_data: HostData) -> None:
    host_data.systemd_services = SystemdCollector().collect()


def _collect_firewall(host_data: HostData) -> None:
    host_data.firewall = FirewallCollector().collect()


def _collect_packages(host_data: HostData) -> None:
    host_data.packages = PackageCollector().collect()


def _collect_persistence(host_data: HostData) -> None:
    host_data.persistence_locations = PersistenceCollector().collect()
