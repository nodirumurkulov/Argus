"""ARGUS CLI - Offline AI Defensive Security Assistant."""

from typing import Annotated

import typer
from rich.console import Console

from argus import __version__

app = typer.Typer(
    name="argus",
    help="ARGUS - Offline AI Defensive Security Assistant",
    add_completion=False,
    no_args_is_help=True,
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
) -> None:
    """Scan local host security posture.

    Collects and analyzes SSH config, users, sudo, network, cron, systemd,
    firewall, and persistence data.
    """
    console.print("[bold cyan]ARGUS Host Security Scan[/bold cyan]")
    console.print("[dim]This command will be fully implemented in a future update.[/dim]")
