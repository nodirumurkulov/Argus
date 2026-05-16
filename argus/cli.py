"""ARGUS CLI - Offline AI Defensive Security Assistant."""

from typing import Annotated

import typer
from rich.console import Console

from argus import __version__
from argus.models import Finding, SeverityLevel

app = typer.Typer(
    name="argus",
    help="ARGUS - Offline AI Defensive Security Assistant",
    add_completion=False,
    no_args_is_help=False,
)

console = Console()

VALID_OUTPUT_FORMATS = {"markdown", "json"}


def validate_output_format(value: str) -> str:
    """Validate CLI output format values."""
    normalized = value.lower()
    if normalized not in VALID_OUTPUT_FORMATS:
        allowed = ", ".join(sorted(VALID_OUTPUT_FORMATS))
        raise typer.BadParameter(f"must be one of: {allowed}")
    return normalized


def validate_severity(value: str | None) -> str | None:
    """Validate CLI severity filter values."""
    if value is None:
        return None
    normalized = value.lower()
    allowed = {severity.value for severity in SeverityLevel}
    if normalized not in allowed:
        raise typer.BadParameter(f"must be one of: {', '.join(sorted(allowed))}")
    return normalized


def filter_findings_by_severity(findings: list[Finding], severity: str | None) -> list[Finding]:
    """Filter findings by minimum severity."""
    if not severity:
        return findings
    severity_order = list(SeverityLevel)
    min_sev = SeverityLevel(severity)
    min_idx = severity_order.index(min_sev)
    return [finding for finding in findings if severity_order.index(finding.severity) <= min_idx]

config_app = typer.Typer(
    name="config",
    help="Manage ARGUS configuration.",
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")


BANNER = """
\033[31m
     █████╗  ██████╗   ██████╗ ██╗   ██╗ ██████╗
    ██╔══██╗ ██╔══██╗ ██╔════╝ ██║   ██║██╔════╝
    ███████║ ██████╔╝ ██║  ███╗██║   ██║╚█████╗
    ██╔══██║ ██╔══██╗ ██║   ██║██║   ██║ ╚═══██╗
    ██║  ██║ ██║  ██║ ╚██████╔╝╚██████╔╝██████╔╝
    ╚═╝  ╚═╝ ╚═╝  ╚═╝  ╚═════╝  ╚═════╝ ╚═════╝
\033[0m
    \033[90mARGUS // Offline Blue-Team Security Assistant  |  Rules + Local AI  |  Linux\033[0m
    \033[90m─────────────────────────────────────────────────────────────────────\033[0m

    \033[34m[*]\033[0m Mission: collect evidence, detect risk, and produce remediation
    \033[32m[+]\033[0m Mode: read-only local host analysis
    \033[33m[!]\033[0m Defensive only: harden, triage, report

    \033[90m┌─ COMMAND CENTER ───────────────────────────────────────────────┐\033[0m
      \033[32m[1]\033[0m  scan-host      Audit SSH, users, sudo, ports, firewall
      \033[32m[2]\033[0m  analyze-logs   Detect brute-force, spraying, root logins
      \033[32m[3]\033[0m  report         Export findings as Markdown or JSON
      \033[32m[4]\033[0m  config         Manage local ARGUS settings
    \033[90m└─────────────────────────────────────────────────────────────────┘\033[0m

    \033[90mExamples\033[0m
      \033[36margus scan-host --severity high\033[0m
      \033[36margus analyze-logs /var/log/auth.log --severity medium\033[0m
      \033[36margus report --input findings.json --output report.md\033[0m

    \033[31margus>\033[0m ready to defend.
"""


def show_banner() -> None:
    """Display the ARGUS startup banner."""
    console.clear()
    print(BANNER)


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
                      callback=validate_output_format,
                      help="Output format: markdown or json.")] = "markdown",
    no_llm: Annotated[bool, typer.Option("--no-llm",
                      help="Skip LLM enrichment.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose",
                       help="Show detailed output.")] = False,
    severity: Annotated[str | None, typer.Option("--severity", "-s",
                         callback=validate_severity,
                         help="Filter by minimum severity: critical, high, medium, low, info.")] = None,
) -> None:
    """Scan local host security posture.

    Collects and analyzes SSH config, users, sudo, network, cron, systemd,
    firewall, and persistence data.
    """
    from argus.analyzers.engine import run_all_analyzers
    from argus.collectors.aggregator import collect_host_data
    from argus.output import (
        render_collector_stats,
        render_findings_table,
        render_host_info,
        render_recommendations,
        render_summary_panel,
        write_json_output,
        write_markdown_output,
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
    render_collector_stats(
        users_count=len(host_data.users),
        ports_count=len(host_data.network_connections),
        services_count=len(host_data.systemd_services),
        packages_count=len(host_data.packages),
        cron_count=len(host_data.cron_entries),
    )

    console.print("\n[bold]Analyzing security posture...[/bold]\n")
    findings = run_all_analyzers(host_data, verbose=verbose)

    if severity:
        findings = filter_findings_by_severity(findings, severity)

    render_findings_table(findings)
    render_summary_panel(findings, hostname=host_data.hostname)
    render_recommendations(findings)

    if output:
        if format == "json":
            write_json_output(findings, output)
        else:
            write_markdown_output(findings, output, hostname=host_data.hostname)

    console.print("[dim]Scan complete.[/dim]\n")


@app.command()
def analyze_logs(
    log_file: Annotated[str, typer.Argument(help="Path to log file or directory to analyze.")],
    output: Annotated[str | None, typer.Option("--output", "-o",
                       help="Output file path.")] = None,
    format: Annotated[str, typer.Option("--format", "-f",
                      callback=validate_output_format,
                      help="Output format: markdown or json.")] = "markdown",
    no_llm: Annotated[bool, typer.Option("--no-llm",
                       help="Skip LLM enrichment.")] = False,
    severity: Annotated[str | None, typer.Option("--severity", "-s",
                          callback=validate_severity,
                          help="Filter by minimum severity: critical, high, medium, low, info.")] = None,
    discover_rotated: Annotated[bool, typer.Option("--discover-rotated", "-r",
                                 help="Also read rotated archives (.1, .2.gz, etc.) automatically.")] = False,
    max_lines: Annotated[int, typer.Option("--max-lines", "-m",
                           help="Maximum lines to read per file.")] = 200_000,
) -> None:
    """Analyze Linux authentication and system logs.

    Detects brute-force attempts, password spraying, suspicious logins,
    sudo abuse, and more. Supports plain and .gz compressed log files.
    """
    from pathlib import Path

    from argus.analyzers.auth_logs import AuthLogAnalyzer
    from argus.collectors.logs import LogCollector
    from argus.output import (
        render_findings_table,
        render_recommendations,
        render_summary_panel,
        write_json_output,
        write_markdown_output,
    )

    console.print("\n[bold cyan]╭────────────────────────────────────────────╮[/bold cyan]")
    console.print("[bold cyan]│[/bold cyan] [bold]ARGUS Log Analysis[/bold]                        [bold cyan]│[/bold cyan]")
    console.print("[bold cyan]│[/bold cyan] [dim]Offline AI Defensive Security Assistant[/dim]    [bold cyan]│[/bold cyan]")
    console.print("[bold cyan]╰────────────────────────────────────────────╯[/bold cyan]\n")

    log_path = Path(log_file)
    if not log_path.exists():
        console.print(f"[bold red]Error:[/bold red] Log file not found: {log_file}")
        raise typer.Exit(code=1)

    if log_path.is_dir():
        log_files = sorted(str(p) for p in log_path.iterdir() if p.is_file())
        if not log_files:
            console.print("[yellow]No files found in directory.[/yellow]")
            raise typer.Exit()
        console.print(f"[bold]Analyzing {len(log_files)} files in:[/bold] {log_file}\n")
        collector = LogCollector()
        merged_lines: list[str] = []
        for lf in log_files:
            lines = collector._read_log(lf, max_lines)
            if lines:
                merged_lines.extend(lines)
        log_lines = merged_lines
    else:
        console.print(f"[bold]Analyzing:[/bold] {log_file}\n")
        collector = LogCollector()
        log_lines = collector.collect(
            log_path=str(log_path),
            max_lines=max_lines,
            discover_rotated=discover_rotated,
        )

    if not log_lines:
        console.print("[yellow]No log entries found.[/yellow]")
        raise typer.Exit()

    source_desc = log_file
    if discover_rotated:
        rotated = LogCollector.discover_rotated_paths(str(log_path))
        if rotated:
            source_desc = f"{log_file} + {len(rotated)} rotated archive(s)"
    console.print(f"  [green]✓[/green] Read {len(log_lines)} log entries from {source_desc}\n")

    analyzer = AuthLogAnalyzer()
    findings = analyzer.analyze(log_lines)
    findings = filter_findings_by_severity(findings, severity)

    render_findings_table(findings)
    render_summary_panel(findings)
    render_recommendations(findings)

    if output:
        if format == "json":
            write_json_output(findings, output)
        else:
            write_markdown_output(findings, output)

    console.print("[dim]Analysis complete.[/dim]\n")


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
    output: Annotated[str | None, typer.Option("--output", "-o",
                      help="Output file path.")] = None,
) -> None:
    """Generate defensive detection rules.

    Supported types: Sigma, auditd, YARA, Suricata.
    """
    if type not in RULE_TYPES:
        console.print(f"[bold red]Unknown rule type:[/bold red] {type}")
        console.print(f"[dim]Available: {', '.join(RULE_TYPES)}[/dim]")
        raise typer.Exit(code=1)
    if type != "sigma":
        console.print(f"[bold yellow]{type} generation is not implemented yet.[/bold yellow]")
        console.print("[dim]Available now: sigma[/dim]")
        raise typer.Exit(code=1)
    if from_file:
        console.print("[bold yellow]Generating rules from findings JSON is not implemented yet.[/bold yellow]")
        raise typer.Exit(code=1)

    from pathlib import Path

    from argus.detections import (
        UnknownSigmaScenario,
        get_sigma_rule,
        render_sigma_yaml,
        supported_sigma_scenarios,
    )

    if not scenario:
        console.print("[bold cyan]Available Sigma scenarios:[/bold cyan]")
        for name, description in supported_sigma_scenarios().items():
            console.print(f"  [cyan]{name}[/cyan]  [dim]{description}[/dim]")
        console.print("\n[dim]Usage: argus generate-rule --type sigma --scenario ssh-bruteforce[/dim]")
        return

    try:
        rule = get_sigma_rule(scenario)
    except UnknownSigmaScenario:
        console.print(f"[bold red]Unknown Sigma scenario:[/bold red] {scenario}")
        console.print(f"[dim]Available: {', '.join(supported_sigma_scenarios())}[/dim]")
        raise typer.Exit(code=1) from None

    rendered = render_sigma_yaml(rule)
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered)
        console.print(f"[green]Sigma rule written to:[/green] {output}")
        return
    print(rendered)


@app.command()
def report(
    input: Annotated[str, typer.Option("--input", "-i",
                      help="Input findings JSON file.")] = "",
    format: Annotated[str, typer.Option("--format", "-f",
                      callback=validate_output_format,
                      help="Output format: markdown or json.")] = "markdown",
    output: Annotated[str | None, typer.Option("--output", "-o",
                      help="Output file path.")] = None,
) -> None:
    """Generate security reports from findings.

    Supports Markdown and JSON output formats.
    """
    import json
    from pathlib import Path

    from pydantic import ValidationError

    from argus.output import (
        render_findings_table,
        render_recommendations,
        render_summary_panel,
        write_json_output,
        write_markdown_output,
    )

    if not input:
        console.print("[bold red]Error:[/bold red] --input is required.")
        raise typer.Exit(code=1)

    input_path = Path(input)
    if not input_path.is_file():
        console.print(f"[bold red]Error:[/bold red] Findings file not found: {input}")
        raise typer.Exit(code=1)

    try:
        data = json.loads(input_path.read_text())
        findings_data = data.get("findings") if isinstance(data, dict) else None
        if not isinstance(findings_data, list):
            raise ValueError("expected a JSON object with a findings list")
        findings = [Finding(**finding) for finding in findings_data]
    except (json.JSONDecodeError, ValidationError, ValueError) as exc:
        console.print(f"[bold red]Error:[/bold red] Invalid findings JSON: {exc}")
        raise typer.Exit(code=1) from exc

    console.print("[bold cyan]ARGUS Report Generation[/bold cyan]")
    if output:
        if format == "json":
            write_json_output(findings, output)
        else:
            write_markdown_output(findings, output)
    else:
        render_findings_table(findings)
        render_summary_panel(findings)
        render_recommendations(findings)


@app.command("compare-reports")
def compare_reports(
    baseline: Annotated[str, typer.Option("--baseline", "-b",
                         help="Baseline ARGUS JSON report.")],
    current: Annotated[str, typer.Option("--current", "-c",
                      help="Current ARGUS JSON report.")],
) -> None:
    """Compare two ARGUS JSON reports and show finding drift."""
    import json

    from pydantic import ValidationError

    from argus.drift import compare_report_files
    from argus.output import render_drift_section, render_drift_summary

    if not baseline or not current:
        console.print("[bold red]Error:[/bold red] --baseline and --current are required.")
        raise typer.Exit(code=1)

    try:
        result = compare_report_files(baseline, current)
    except (FileNotFoundError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        console.print(f"[bold red]Error:[/bold red] Invalid report input: {exc}")
        raise typer.Exit(code=1) from exc
    render_drift_summary(result.summary())
    render_drift_section("New Findings", result.new)
    render_drift_section("Resolved Findings", result.resolved)
    render_drift_section("Unchanged Findings", result.unchanged)


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
