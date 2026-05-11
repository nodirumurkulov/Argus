"""ARGUS CLI - Offline AI Defensive Security Assistant."""

from typing import Annotated

import typer
from rich.console import Console

from argus import __version__

app = typer.Typer(
    name="argus",
    help="ARGUS - Offline AI Defensive Security Assistant",
    add_completion=False,
    no_args_is_help=False,
)

console = Console()

config_app = typer.Typer(
    name="config",
    help="Manage ARGUS configuration.",
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")


BANNER = r"""
[cyan]
        ╔══════════════════════════════════════════════════════════════════╗
        ║                                                                ║
        ║     █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗                  ║
        ║    ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝                  ║
        ║    ███████║██████╔╝██║  ███╗██║   ██║███████╗                  ║
        ║    ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║                  ║
        ║    ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║                  ║
        ║    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝                  ║
        ║                                                                ║
        ╚══════════════════════════════════════════════════════════════════╝
[/cyan]
[bold red]          ◈ OFFLINE AI DEFENSIVE SECURITY ASSISTANT ◈[/bold red]
[dim]         ──────── DETECT • ANALYZE • HARDEN • DEFEND ────────[/dim]

[bold white]  ╭──────────────────────────────────────────────────────────────╮[/bold white]
[bold white]  │[/bold white] [italic cyan] "See everything. Understand everything. Secure everything." [/italic cyan] [bold white]│[/bold white]
[bold white]  │[/bold white]                                           [dim]— ARGUS[/dim]            [bold white]│[/bold white]
[bold white]  ╰──────────────────────────────────────────────────────────────╯[/bold white]

[bold red]  ┌─ CAPABILITIES ─────────────────────────────────────────────┐[/bold red]
[bold red]  │[/bold red]  [cyan]◉[/cyan]  Host Security Scanning         [dim]scan-host[/dim]              [bold red]│[/bold red]
[bold red]  │[/bold red]  [cyan]◉[/cyan]  Log Analysis & Threat Detection [dim]analyze-logs[/dim]          [bold red]│[/bold red]
[bold red]  │[/bold red]  [cyan]◉[/cyan]  Incident Investigation          [dim]investigate[/dim]           [bold red]│[/bold red]
[bold red]  │[/bold red]  [cyan]◉[/cyan]  Detection Rule Generation       [dim]generate-rule[/dim]         [bold red]│[/bold red]
[bold red]  │[/bold red]  [cyan]◉[/cyan]  Security Report Generation      [dim]report[/dim]                [bold red]│[/bold red]
[bold red]  │[/bold red]  [cyan]◉[/cyan]  Offline LLM Analysis            [dim]via Ollama[/dim]            [bold red]│[/bold red]
[bold red]  └─────────────────────────────────────────────────────────────┘[/bold red]

[bold cyan]  MODEL:[/bold cyan] [white]ollama (local)[/white]  │  [bold cyan]ENGINE:[/bold cyan] [white]rule-based + AI[/white]  │  [bold cyan]OS:[/bold cyan] [white]Linux[/white]

[dim green]  [argus@localhost ~]$  ready to defend. _[/dim green]
"""


def show_banner() -> None:
    """Display the ARGUS startup banner."""
    console.print(BANNER)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"[bold cyan]ARGUS[/bold cyan] version [bold]{__version__}[/bold]")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option("--version", "-v", callback=version_callback, is_eager=True,
                     help="Show ARGUS version and exit."),
    ] = False,
) -> None:
    """ARGUS - Offline AI Defensive Security Assistant.

    Local-first blue-team analysis for Linux.
    """
    if ctx.invoked_subcommand is None:
        show_banner()


@app.command()
def scan_host(
    output: Annotated[str | None, typer.Option("--output", "-o",
                      help="Output file path.")] = None,
    format: Annotated[str, typer.Option("--format", "-f",
                      help="Output format: markdown or json.")] = "markdown",
    no_llm: Annotated[bool, typer.Option("--no-llm",
                      help="Skip LLM enrichment.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose",
                       help="Show detailed output.")] = False,
) -> None:
    """Scan local host security posture.

    Collects and analyzes SSH config, users, sudo, network, cron, systemd,
    firewall, and persistence data.
    """
    from argus.analyzers.engine import run_all_analyzers
    from argus.collectors.aggregator import collect_host_data
    from argus.output import (
        render_findings_table,
        render_host_info,
        render_recommendations,
        render_summary_panel,
        write_json_output,
    )

    console.print("\n[bold cyan]╭────────────────────────────────────────────╮[/bold cyan]")
    console.print("[bold cyan]│[/bold cyan] [bold]ARGUS Host Security Scan[/bold]                   [bold cyan]│[/bold cyan]")
    console.print("[bold cyan]│[/bold cyan] [dim]Offline AI Defensive Security Assistant[/dim]    [bold cyan]│[/bold cyan]")
    console.print("[bold cyan]╰────────────────────────────────────────────╯[/bold cyan]\n")

    console.print("[bold]Collecting host data...[/bold]\n")
    host_data = collect_host_data(verbose=verbose)

    render_host_info(
        hostname=host_data.hostname,
        os_release=host_data.os_release,
        kernel_version=host_data.kernel_version,
        uptime=host_data.uptime,
    )

    console.print("\n[bold]Analyzing security posture...[/bold]\n")
    findings = run_all_analyzers(host_data, verbose=verbose)

    render_findings_table(findings)
    render_summary_panel(findings, hostname=host_data.hostname)
    render_recommendations(findings)

    if output:
        if format == "json":
            write_json_output(findings, output)
        else:
            console.print(f"\n[green]Report written to:[/green] {output}")

    console.print("[dim]Scan complete.[/dim]\n")


@app.command()
def analyze_logs(
    log_file: Annotated[str, typer.Argument(help="Path to log file to analyze.")],
    output: Annotated[str | None, typer.Option("--output", "-o",
                      help="Output file path.")] = None,
    format: Annotated[str, typer.Option("--format", "-f",
                      help="Output format: markdown or json.")] = "markdown",
    no_llm: Annotated[bool, typer.Option("--no-llm",
                      help="Skip LLM enrichment.")] = False,
) -> None:
    """Analyze Linux authentication and system logs.

    Detects brute-force attempts, password spraying, suspicious logins,
    sudo abuse, and more.
    """
    console.print(f"[bold cyan]ARGUS Log Analysis:[/bold cyan] {log_file}")
    console.print("[dim]This command will be fully implemented in a future update.[/dim]")


INVESTIGATION_CASES = [
    "ssh-compromise",
    "suspicious-user",
    "web-shell",
    "crypto-miner",
    "privilege-escalation",
    "persistence",
]


@app.command()
def investigate(
    case: Annotated[str, typer.Option("--case", "-c",
                    help="Investigation case type.")] = "",
) -> None:
    """Run guided incident investigation and triage.

    Supported cases: ssh-compromise, suspicious-user, web-shell,
    crypto-miner, privilege-escalation, persistence.
    """
    if not case:
        console.print("[bold cyan]Available investigation cases:[/bold cyan]")
        for c in INVESTIGATION_CASES:
            console.print(f"  [cyan]◉[/cyan]  {c}")
        console.print("\n[dim]Usage: argus investigate --case ssh-compromise[/dim]")
        return
    if case not in INVESTIGATION_CASES:
        console.print(f"[bold red]Unknown case:[/bold red] {case}")
        console.print(f"[dim]Available: {', '.join(INVESTIGATION_CASES)}[/dim]")
        raise typer.Exit(code=1)
    console.print(f"[bold cyan]ARGUS Investigation:[/bold cyan] {case}")
    console.print("[dim]This command will be fully implemented in a future update.[/dim]")


RULE_TYPES = ["sigma", "auditd", "yara", "suricata"]


@app.command()
def generate_rule(
    type: Annotated[str, typer.Option("--type", "-t",
                    help="Rule type: sigma, auditd, yara, suricata.")] = "sigma",
    scenario: Annotated[str | None, typer.Option("--scenario", "-s",
                        help="Scenario name, e.g. ssh-bruteforce.")] = None,
    from_file: Annotated[str | None, typer.Option("--from",
                         help="Generate rules from findings JSON file.")] = None,
) -> None:
    """Generate defensive detection rules.

    Supported types: Sigma, auditd, YARA, Suricata.
    """
    if type not in RULE_TYPES:
        console.print(f"[bold red]Unknown rule type:[/bold red] {type}")
        console.print(f"[dim]Available: {', '.join(RULE_TYPES)}[/dim]")
        raise typer.Exit(code=1)
    console.print(f"[bold cyan]ARGUS Rule Generation:[/bold cyan] {type}")
    console.print("[dim]This command will be fully implemented in a future update.[/dim]")


@app.command()
def report(
    input: Annotated[str, typer.Option("--input", "-i",
                     help="Input findings JSON file.")] = "",
    format: Annotated[str, typer.Option("--format", "-f",
                      help="Output format: markdown or json.")] = "markdown",
    output: Annotated[str | None, typer.Option("--output", "-o",
                      help="Output file path.")] = None,
) -> None:
    """Generate security reports from findings.

    Supports Markdown and JSON output formats.
    """
    console.print("[bold cyan]ARGUS Report Generation[/bold cyan]")
    console.print("[dim]This command will be fully implemented in a future update.[/dim]")


@config_app.command("init")
def config_init() -> None:
    """Initialize default ARGUS configuration file."""
    from argus.config import DEFAULT_CONFIG_PATH, generate_default_config

    try:
        path = generate_default_config()
        console.print(f"[bold green]Config created:[/bold green] {path}")
    except FileExistsError:
        console.print(f"[bold yellow]Config already exists:[/bold yellow] {DEFAULT_CONFIG_PATH}")
        console.print("[dim]Delete it first if you want to regenerate.[/dim]")


@config_app.command("show")
def config_show() -> None:
    """Display current ARGUS configuration."""
    import yaml

    from argus.config import DEFAULT_CONFIG_PATH, load_config

    config = load_config()
    console.print(f"[bold cyan]ARGUS Configuration[/bold cyan] [dim]({DEFAULT_CONFIG_PATH})[/dim]\n")
    config_yaml = yaml.dump(config.model_dump(), default_flow_style=False, sort_keys=False)
    console.print(f"[white]{config_yaml}[/white]")
