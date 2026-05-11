"""Authentication log analyzer for ARGUS."""

import re
from collections import Counter

from argus.analyzers.base import BaseAnalyzer
from argus.models import Finding


class AuthLogAnalyzer(BaseAnalyzer):
    """Analyze authentication logs for suspicious activity."""

    name = "auth_logs"
    category = "auth"

    FAILED_LOGIN_RE = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)"
    )
    ACCEPTED_LOGIN_RE = re.compile(
        r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)"
    )
    NEW_USER_RE = re.compile(
        r"useradd\[\d+\]: new user: name=(\S+),"
    )
    SUDO_FAILURE_RE = re.compile(
        r"sudo:\s+(\S+)\s+:.*incorrect password attempt"
    )

    def analyze(self, log_lines: list[str]) -> list[Finding]:
        """Analyze auth log lines and return findings."""
        findings: list[Finding] = []
        self._check_brute_force(log_lines, findings)
        self._check_password_spraying(log_lines, findings)
        self._check_successful_after_failures(log_lines, findings)
        self._check_new_users(log_lines, findings)
        self._check_sudo_failures(log_lines, findings)
        self._check_root_login(log_lines, findings)
        self._check_multiple_source_ips(log_lines, findings)
        return findings

    def _check_brute_force(
        self, lines: list[str], findings: list[Finding]
    ) -> None:
        """Detect brute-force attempts (many failures from same IP)."""
        ip_failures: Counter[str] = Counter()
        for line in lines:
            match = self.FAILED_LOGIN_RE.search(line)
            if match:
                ip_failures[match.group(2)] += 1

        for ip, count in ip_failures.most_common():
            if count >= 5:
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-AUTH-001-{ip}",
                    title=f"SSH brute-force from {ip} ({count} failures)",
                    severity="high" if count >= 10 else "medium",
                    description=(
                        f"Detected {count} failed SSH login attempts from {ip}. "
                        "This is a potential brute-force attack."
                    ),
                    evidence=[f"Failed attempts: {count} from {ip}"],
                    recommendation=f"Block IP {ip} with: sudo ufw deny from {ip}",
                    mitre=["T1110.001"],
                ))

    def _check_password_spraying(
        self, lines: list[str], findings: list[Finding]
    ) -> None:
        """Detect password spraying (same IP, many usernames)."""
        ip_users: dict[str, set[str]] = {}
        for line in lines:
            match = self.FAILED_LOGIN_RE.search(line)
            if match:
                user, ip = match.group(1), match.group(2)
                ip_users.setdefault(ip, set()).add(user)

        for ip, users in ip_users.items():
            if len(users) >= 4:
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-AUTH-002-{ip}",
                    title=f"Password spraying from {ip} ({len(users)} users)",
                    severity="high",
                    description=(
                        f"IP {ip} attempted login with {len(users)} different "
                        f"usernames: {', '.join(sorted(users)[:10])}"
                    ),
                    evidence=[f"Targeted users: {', '.join(sorted(users))}"],
                    recommendation=f"Block IP {ip} and review targeted accounts.",
                    mitre=["T1110.003"],
                ))

    def _check_successful_after_failures(
        self, lines: list[str], findings: list[Finding]
    ) -> None:
        """Detect successful logins that follow multiple failures."""
        ip_failures: Counter[str] = Counter()
        for line in lines:
            fail_match = self.FAILED_LOGIN_RE.search(line)
            if fail_match:
                ip_failures[fail_match.group(2)] += 1
                continue
            success_match = self.ACCEPTED_LOGIN_RE.search(line)
            if success_match:
                ip = success_match.group(2)
                user = success_match.group(1)
                if ip_failures.get(ip, 0) >= 3:
                    findings.append(self._make_finding(
                        finding_id=f"ARGUS-AUTH-003-{ip}",
                        title=f"Successful login from {ip} after {ip_failures[ip]} failures",
                        severity="critical",
                        description=(
                            f"User '{user}' successfully logged in from {ip} after "
                            f"{ip_failures[ip]} failed attempts. This may indicate "
                            "a successful brute-force attack."
                        ),
                        evidence=[
                            f"Failed attempts: {ip_failures[ip]}",
                            f"Successful user: {user}",
                            f"Source IP: {ip}",
                        ],
                        recommendation=(
                            f"Investigate session for {user} from {ip}. "
                            "Check for unauthorized access."
                        ),
                        mitre=["T1110", "T1078"],
                    ))

    def _check_new_users(
        self, lines: list[str], findings: list[Finding]
    ) -> None:
        """Detect new user creation events."""
        for line in lines:
            match = self.NEW_USER_RE.search(line)
            if match:
                username = match.group(1)
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-AUTH-004-{username}",
                    title=f"New user created: {username}",
                    severity="medium",
                    description=(
                        f"A new user account '{username}' was created. "
                        "Verify this was an authorized action."
                    ),
                    evidence=[line.strip()],
                    recommendation=f"Verify user '{username}' was created intentionally.",
                    mitre=["T1136.001"],
                ))

    def _check_sudo_failures(
        self, lines: list[str], findings: list[Finding]
    ) -> None:
        """Detect sudo authentication failures."""
        sudo_failures: Counter[str] = Counter()
        for line in lines:
            match = self.SUDO_FAILURE_RE.search(line)
            if match:
                sudo_failures[match.group(1)] += 1

        for user, count in sudo_failures.most_common():
            if count >= 3:
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-AUTH-005-{user}",
                    title=f"Sudo failures for user '{user}' ({count} attempts)",
                    severity="medium",
                    description=(
                        f"User '{user}' had {count} failed sudo attempts. "
                        "This may indicate privilege escalation attempts."
                    ),
                    evidence=[f"Failed sudo: {count} attempts by {user}"],
                    recommendation=f"Review sudo access for user '{user}'.",
                    mitre=["T1548.003"],
                ))

    def _check_root_login(
        self, lines: list[str], findings: list[Finding]
    ) -> None:
        """Detect direct root login events."""
        for line in lines:
            match = self.ACCEPTED_LOGIN_RE.search(line)
            if match and match.group(1) == "root":
                ip = match.group(2)
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-AUTH-006-{ip}",
                    title=f"Direct root SSH login from {ip}",
                    severity="high",
                    description=(
                        f"Root user logged in directly via SSH from {ip}. "
                        "Direct root access should be disabled."
                    ),
                    evidence=[line.strip()],
                    recommendation="Disable root SSH login. Use sudo instead.",
                    mitre=["T1078"],
                ))

    def _check_multiple_source_ips(
        self, lines: list[str], findings: list[Finding]
    ) -> None:
        """Detect users logging in from multiple different IPs."""
        user_ips: dict[str, set[str]] = {}
        for line in lines:
            match = self.ACCEPTED_LOGIN_RE.search(line)
            if match:
                user, ip = match.group(1), match.group(2)
                user_ips.setdefault(user, set()).add(ip)

        for user, ips in user_ips.items():
            if len(ips) >= 3:
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-AUTH-007-{user}",
                    title=f"User '{user}' logged in from {len(ips)} different IPs",
                    severity="medium",
                    description=(
                        f"User '{user}' has successful logins from {len(ips)} "
                        f"different source IPs: {', '.join(sorted(ips))}"
                    ),
                    evidence=[f"IPs: {', '.join(sorted(ips))}"],
                    recommendation=f"Verify all login sources for '{user}' are authorized.",
                    mitre=["T1078"],
                ))
