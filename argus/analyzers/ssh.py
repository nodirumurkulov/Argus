"""SSH configuration security analyzer for ARGUS."""

from argus.analyzers.base import BaseAnalyzer
from argus.models import Finding, SSHConfig


class SSHAnalyzer(BaseAnalyzer):
    """Analyze SSH server configuration for security issues."""

    name = "ssh"
    category = "ssh"

    def analyze(self, ssh_config: SSHConfig) -> list[Finding]:
        """Analyze SSH configuration and return findings."""
        findings: list[Finding] = []
        self._check_root_login(ssh_config, findings)
        self._check_password_auth(ssh_config, findings)
        self._check_empty_passwords(ssh_config, findings)
        self._check_listen_address(ssh_config, findings)
        self._check_x11_forwarding(ssh_config, findings)
        self._check_max_auth_tries(ssh_config, findings)
        return findings

    def _check_root_login(
        self, config: SSHConfig, findings: list[Finding]
    ) -> None:
        """Check if root login is enabled over SSH."""
        if config.permit_root_login.lower() in ("yes", "without-password", "forced-commands-only"):
            severity = "high" if config.permit_root_login.lower() == "yes" else "medium"
            findings.append(self._make_finding(
                finding_id="ARGUS-SSH-001",
                title="SSH root login is enabled",
                severity=severity,
                description=(
                    "Root login over SSH is enabled. This increases the blast radius "
                    "of credential compromise and is a common brute-force target."
                ),
                evidence=[f"PermitRootLogin {config.permit_root_login}"],
                recommendation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload SSH.",
                mitre=["T1078", "T1021.004"],
            ))
