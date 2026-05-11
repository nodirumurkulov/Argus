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
        self._check_weak_ciphers(ssh_config, findings)
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

    def _check_password_auth(
        self, config: SSHConfig, findings: list[Finding]
    ) -> None:
        """Check if password authentication is enabled."""
        if config.password_authentication.lower() == "yes":
            findings.append(self._make_finding(
                finding_id="ARGUS-SSH-002",
                title="SSH password authentication is enabled",
                severity="medium",
                description=(
                    "Password authentication is enabled for SSH. This increases "
                    "exposure to brute-force and credential stuffing attacks."
                ),
                evidence=[f"PasswordAuthentication {config.password_authentication}"],
                recommendation="Disable SSH password authentication and use key-based login.",
                mitre=["T1110"],
            ))

    def _check_empty_passwords(
        self, config: SSHConfig, findings: list[Finding]
    ) -> None:
        """Check if empty password login is permitted."""
        if config.permit_empty_passwords.lower() == "yes":
            findings.append(self._make_finding(
                finding_id="ARGUS-SSH-003",
                title="SSH allows login with empty passwords",
                severity="critical",
                description=(
                    "SSH is configured to allow login with empty passwords. "
                    "Any account without a password can be accessed remotely."
                ),
                evidence=[f"PermitEmptyPasswords {config.permit_empty_passwords}"],
                recommendation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config.",
                mitre=["T1078"],
            ))

    def _check_listen_address(
        self, config: SSHConfig, findings: list[Finding]
    ) -> None:
        """Check if SSH is listening on all interfaces."""
        if config.listen_address in ("0.0.0.0", "", "::"):
            findings.append(self._make_finding(
                finding_id="ARGUS-SSH-004",
                title="SSH listening on all interfaces",
                severity="info",
                description=(
                    "SSH is listening on all network interfaces. Consider "
                    "restricting to specific interfaces if not needed."
                ),
                evidence=[f"ListenAddress {config.listen_address or '0.0.0.0 (default)'}"],
                recommendation="Bind SSH to specific interfaces using ListenAddress.",
                mitre=["T1021.004"],
            ))

    def _check_x11_forwarding(
        self, config: SSHConfig, findings: list[Finding]
    ) -> None:
        """Check if X11 forwarding is enabled."""
        if config.x11_forwarding.lower() == "yes":
            findings.append(self._make_finding(
                finding_id="ARGUS-SSH-005",
                title="SSH X11 forwarding is enabled",
                severity="low",
                description=(
                    "X11 forwarding is enabled. This can be exploited for "
                    "keylogging or display hijacking if compromised."
                ),
                evidence=[f"X11Forwarding {config.x11_forwarding}"],
                recommendation="Disable X11 forwarding unless specifically required.",
                mitre=["T1056"],
            ))

    def _check_max_auth_tries(
        self, config: SSHConfig, findings: list[Finding]
    ) -> None:
        """Check if MaxAuthTries is set too high."""
        if config.max_auth_tries > 6:
            findings.append(self._make_finding(
                finding_id="ARGUS-SSH-006",
                title="SSH MaxAuthTries is set too high",
                severity="low",
                description=(
                    f"MaxAuthTries is set to {config.max_auth_tries}. "
                    "High values increase brute-force window."
                ),
                evidence=[f"MaxAuthTries {config.max_auth_tries}"],
                recommendation="Set MaxAuthTries to 3 or lower.",
                mitre=["T1110"],
            ))

    def _check_weak_ciphers(
        self, config: SSHConfig, findings: list[Finding]
    ) -> None:
        """Check for weak SSH ciphers."""
        weak_ciphers = {
            "arcfour", "arcfour128", "arcfour256",
            "3des-cbc", "blowfish-cbc", "cast128-cbc",
            "aes128-cbc", "aes192-cbc", "aes256-cbc",
        }
        if not config.ciphers:
            return
        found_weak = [c for c in config.ciphers if c in weak_ciphers]
        if found_weak:
            findings.append(self._make_finding(
                finding_id="ARGUS-SSH-007",
                title="Weak SSH ciphers configured",
                severity="medium",
                description=(
                    f"Weak ciphers are configured: {', '.join(found_weak)}. "
                    "CBC-mode ciphers are vulnerable to padding oracle attacks."
                ),
                evidence=[f"Cipher: {c}" for c in found_weak],
                recommendation="Remove weak ciphers. Use aes256-gcm, chacha20-poly1305.",
                mitre=["T1040"],
            ))
