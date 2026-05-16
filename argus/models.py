"""ARGUS data models for findings, reports, and host data."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from argus.fingerprints import generate_finding_fingerprint


REPORT_SCHEMA_VERSION = "1.0"


class SeverityLevel(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single security finding produced by an analyzer."""

    id: str = Field(description="Unique finding identifier, e.g. ARGUS-SSH-001")
    title: str = Field(description="Short human-readable title")
    severity: SeverityLevel = Field(description="Finding severity level")
    category: str = Field(description="Finding category, e.g. ssh, users, network")
    description: str = Field(description="Detailed description of the finding")
    evidence: list[str] = Field(default_factory=list, description="Evidence strings")
    fingerprint: str = Field(default="", description="Stable finding fingerprint")
    recommendation: str = Field(default="", description="Remediation recommendation")
    mitre: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    references: list[str] = Field(default_factory=list, description="External reference URLs")
    llm_summary: str | None = Field(default=None, description="LLM-generated summary")

    def model_post_init(self, __context: object) -> None:
        """Populate a stable fingerprint when callers do not provide one."""
        if self.fingerprint:
            return
        self.fingerprint = generate_finding_fingerprint(
            finding_id=self.id,
            category=self.category,
            title=self.title,
            severity=self.severity.value,
            evidence=self.evidence,
        )


class UserInfo(BaseModel):
    """Information about a local system user."""

    username: str
    uid: int
    gid: int
    home: str
    shell: str
    gecos: str = ""
    has_password: bool = True
    password_empty: bool = False
    groups: list[str] = Field(default_factory=list)
    sudo_access: bool = False
    sudo_nopasswd: bool = False
    last_login: str | None = None


class NetworkConnection(BaseModel):
    """A listening network connection/port."""

    protocol: str = Field(description="tcp, udp, tcp6, udp6")
    local_address: str
    local_port: int
    state: str = "LISTEN"
    process_name: str | None = None
    pid: int | None = None


class CronEntry(BaseModel):
    """A cron job entry."""

    user: str
    schedule: str
    command: str
    source_file: str = ""


class SystemdService(BaseModel):
    """A systemd service unit."""

    name: str
    unit_file: str
    state: str = ""
    enabled: bool = False
    description: str = ""
    exec_start: str = ""
    user: str = ""
    writable: bool = False


class PackageInfo(BaseModel):
    """An installed system package."""

    name: str
    version: str
    architecture: str = ""
    description: str = ""


class SSHConfig(BaseModel):
    """Parsed SSH server configuration."""

    permit_root_login: str = "unknown"
    password_authentication: str = "unknown"
    permit_empty_passwords: str = "unknown"
    port: int = 22
    listen_address: str = ""
    max_auth_tries: int = 6
    login_grace_time: int = 120
    ciphers: list[str] = Field(default_factory=list)
    kex_algorithms: list[str] = Field(default_factory=list)
    protocol: str = ""
    x11_forwarding: str = "unknown"
    source: str = ""
    raw_config: dict[str, str] = Field(default_factory=dict)


class FirewallStatus(BaseModel):
    """Firewall status information."""

    active: bool = False
    backend: str = ""
    detected_backends: list[str] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)
    default_policy: str = ""


class HostData(BaseModel):
    """Aggregated host security data from all collectors."""

    hostname: str = ""
    kernel_version: str = ""
    os_release: str = ""
    uptime: str = ""
    ssh_config: SSHConfig = Field(default_factory=SSHConfig)
    users: list[UserInfo] = Field(default_factory=list)
    network_connections: list[NetworkConnection] = Field(default_factory=list)
    cron_entries: list[CronEntry] = Field(default_factory=list)
    systemd_services: list[SystemdService] = Field(default_factory=list)
    packages: list[PackageInfo] = Field(default_factory=list)
    firewall: FirewallStatus = Field(default_factory=FirewallStatus)
    sysctl_settings: dict[str, str] = Field(default_factory=dict)
    persistence_locations: list[str] = Field(default_factory=list)


class Report(BaseModel):
    """A complete ARGUS security report."""

    schema_version: str = REPORT_SCHEMA_VERSION
    title: str = "ARGUS Security Report"
    generated_at: datetime = Field(default_factory=datetime.now)
    hostname: str = ""
    scan_type: str = ""
    findings: list[Finding] = Field(default_factory=list)
    executive_summary: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    detection_rules: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == SeverityLevel.INFO)
