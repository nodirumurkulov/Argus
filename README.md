# ARGUS

A command-line assistant for defensive security on Linux. Runs locally, with optional AI analysis.

<pre style="background: #0d1117; color: #8b949e; padding: 16px; border-radius: 6px; line-height: 1.3; overflow-x: auto;">

<span style="color: #cc0000;">     █████╗  ██████╗   ██████╗ ██╗   ██╗ ██████╗
    ██╔══██╗ ██╔══██╗ ██╔════╝ ██║   ██║██╔════╝
    ███████║ ██████╔╝ ██║  ███╗██║   ██║╚█████╗
    ██╔══██║ ██╔══██╗ ██║   ██║██║   ██║ ╚═══██╗
    ██║  ██║ ██║  ██║ ╚██████╔╝╚██████╔╝██████╔╝
    ╚═╝  ╚═╝ ╚═╝  ╚═╝  ╚═════╝  ╚═════╝ ╚═════╝</span>

    <span style="color: #8b949e;">ARGUS // Offline Blue-Team Security Assistant  |  Rules + Local AI  |  Linux
    ─────────────────────────────────────────────────────────────────────</span>

    <span style="color: #0066cc;">[*]</span> Purpose: collect evidence, find risks, and suggest fixes
    <span style="color: #0066cc;">[+]</span> Mode: read-only local host analysis
    <span style="color: #cc0000;">[!]</span> Defensive only: harden, triage, report

    <span style="color: #8b949e;">┌─ COMMAND CENTER ───────────────────────────────────────────────┐</span>
      <span style="color: #0066cc;">[1]</span>  scan-host      Audit SSH, users, sudo, ports, firewall
      <span style="color: #0066cc;">[2]</span>  analyze-logs   Detect brute-force, spraying, root logins
      <span style="color: #0066cc;">[3]</span>  report         Export findings as Markdown or JSON
      <span style="color: #0066cc;">[4]</span>  config         Manage local ARGUS settings
    <span style="color: #8b949e;">└─────────────────────────────────────────────────────────────────┘</span>

    <span style="color: #8b949e;">Examples</span>
      <span style="color: #0066cc;">argus scan-host --severity high</span>
      <span style="color: #0066cc;">argus analyze-logs /var/log/auth.log --severity medium</span>
      <span style="color: #0066cc;">argus report --input findings.json --output report.md</span>

    <span style="color: #cc0000;">argus></span> ready to defend.
</pre>

## What is ARGUS?

ARGUS is an open-source Python CLI for checking Linux hosts and investigating suspicious activity. It's built for system administrators, blue teams, SOC analysts, and people running homelabs.

Use it to review host configuration, analyze authentication logs, and write reports with findings and suggested fixes. It also supports defensive detection rules and maps findings to MITRE ATT&CK.

ARGUS focuses on host hardening, log analysis, incident response, and detection engineering. It does not include tools for exploitation or credential attacks.

## Features

| Feature | Command | Description |
|---------|---------|-------------|
| Host Security Scan | `argus scan-host` | Analyze SSH, users, sudo, ports, cron, systemd, firewall |
| Log Analysis | `argus analyze-logs` | Detect brute-force, spraying, suspicious logins |
| Incident Investigation | `argus investigate` | Guided triage for common incident types |
| Detection Rules | `argus generate-rule` | Generate Sigma, auditd, YARA, Suricata rules |
| Report Generation | `argus report` | Markdown and JSON security reports |
| Configuration | `argus config` | Manage ARGUS settings |

### How it works

ARGUS runs locally without cloud APIs, telemetry, or API keys. Rule-based checks work without a language model. You can optionally use a local model through [Ollama](https://ollama.ai/) for AI analysis.

Findings include MITRE ATT&CK mappings. The CLI displays results in Rich tables with colored output, and reports can be saved as Markdown or JSON.

## Supported platforms

| Platform | Status |
|----------|--------|
| Debian / Ubuntu | Primary |
| Kali Linux | Primary |
| Parrot OS | Primary |
| Other Debian-based | Supported |
| Fedora / Arch | Planned |
| macOS (read-only) | Planned |

## Installation

### Requirements

- Python 3.11+
- pip

### Install from source

```bash
git clone https://github.com/nodirumurkulov/Argus.git
cd Argus
pip install -e .
```

### Verify installation

```bash
argus --version
argus --help
```

## Quick start

### Run a host security scan

```bash
argus scan-host
argus scan-host --output report.md
argus scan-host --format json --output findings.json
argus scan-host --no-llm
```

### Analyze authentication logs

```bash
argus analyze-logs /var/log/auth.log
argus analyze-logs /var/log/auth.log --severity high
argus analyze-logs /var/log/auth.log --output auth-report.md
```

### Investigate an incident

```bash
argus investigate --case ssh-compromise
argus investigate --case suspicious-user
argus investigate --case privilege-escalation
```

### Generate detection rules

```bash
argus generate-rule --type sigma --scenario ssh-bruteforce
argus generate-rule --type sigma --scenario password-spraying
argus generate-rule --type sigma --scenario root-login --output root-login.yml
```

The initial Sigma scenarios are:

- `ssh-bruteforce`: repeated SSH password failures
- `password-spraying`: failed SSH attempts against multiple usernames
- `root-login`: direct successful SSH login as root
- `successful-after-failures`: successful SSH login after repeated failures

### Generate a report

```bash
argus report --input findings.json --format markdown
argus report --input findings.json --format markdown --output report.md
argus report --input findings.json --format json
```

## Ollama setup (optional)

To use a local language model with ARGUS, install [Ollama](https://ollama.ai/) and configure it below. You can skip this setup if you only need rule-based analysis.

### Install Ollama

```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

### Pull a model

```bash
ollama pull llama3.1:8b
```

### Configure ARGUS

```bash
argus config init
```

Default LLM configuration (`~/.config/argus/config.yaml`):

```yaml
llm:
  provider: ollama
  base_url: http://localhost:11434
  model: llama3.1:8b
  temperature: 0.2
  timeout: 120
  enabled: true
```

## Security checks

### SSH

- Root login enabled
- Password authentication enabled
- Empty password login
- Weak ciphers configured
- Listening on all interfaces

### Users

- UID 0 users other than root
- Empty password fields
- Recently created users
- Service accounts with login shells

### Sudo

- Passwordless sudo
- Broad sudo access
- Writable sudoers include files

### Persistence

- Suspicious cron entries
- Unusual systemd services
- Writable systemd unit files
- Shell scripts in startup paths

### Network

- Unexpected listening services
- Services bound to 0.0.0.0
- Risky ports exposed

### Authentication logs

- SSH brute-force attempts
- Password spraying
- Successful login after repeated failures
- Sudo abuse
- Suspicious root login

## Severity levels

| Level | Description |
|-------|-------------|
| **CRITICAL** | Immediate action required |
| **HIGH** | Significant security risk |
| **MEDIUM** | Notable misconfiguration |
| **LOW** | Minor concern |
| **INFO** | Informational note |

## Project structure

```
argus/
  argus/
    __init__.py          # Package info
    cli.py               # CLI commands (typer + rich)
    config.py            # Configuration management
    models.py            # Pydantic data models
    output.py            # Rich output and report writers
    collectors/          # Host data collectors
    analyzers/           # Security analyzers
    detections/          # Detection rule generators
    mitre/               # MITRE ATT&CK mapping
    templates/           # Report templates (Jinja2)
  tests/                 # Test suite
  examples/              # Sample data and reports
  docs/                  # Documentation assets
```

## Roadmap

### MVP (current)

- [x] Python package with CLI
- [x] CLI with typer and Rich
- [x] Data models and configuration
- [x] Host security scanning
- [x] Authentication log analysis
- [x] Markdown and JSON reports
- [x] CLI option validation
- [x] GitHub Actions CI
- [ ] Ollama LLM integration
- [ ] Sigma rule generation
- [ ] auditd rule generation
- [x] MITRE ATT&CK mapping for core findings
- [x] Initial unit tests

### Future

- [ ] YARA rule generation
- [ ] Suricata rule generation
- [ ] TUI dashboard (textual)
- [ ] Wazuh integration
- [ ] OSQuery integration
- [ ] Zeek log support
- [ ] Docker image
- [ ] Web dashboard
- [ ] Multi-host collector
- [ ] Baseline drift detection

## Contributing

To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'feat: add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a pull request

### Development setup

```bash
git clone https://github.com/nodirumurkulov/Argus.git
cd Argus
pip install -e ".[dev]"
pytest
```

### Code style

- Python 3.11+
- Type hints required
- Ruff for linting
- Conventional commits

## Defensive use

ARGUS is built for defensive security. It does not provide:

- Exploit execution
- Brute-force tooling
- Credential attacks
- Reverse shell generation
- Payload generation
- Vulnerability exploitation
- Automatic privilege escalation
- Persistence creation

Its defensive features include:

- Defensive detection rules
- Hardening advice
- Incident response steps
- Forensic triage guidance
- Log analysis
- Local configuration review
- Read-only security posture checks

## License

Released under the [MIT License](LICENSE).
