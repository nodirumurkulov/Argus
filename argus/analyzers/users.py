"""User account security analyzer for ARGUS."""

from argus.analyzers.base import BaseAnalyzer
from argus.models import Finding, UserInfo


NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/bin/false", "/sbin/nologin"}


class UserAnalyzer(BaseAnalyzer):
    """Analyze local user accounts for security issues."""

    name = "users"
    category = "users"

    def analyze(self, users: list[UserInfo]) -> list[Finding]:
        """Analyze user accounts and return findings."""
        findings: list[Finding] = []
        self._check_uid_zero(users, findings)
        self._check_empty_passwords(users, findings)
        self._check_service_accounts_with_shells(users, findings)
        return findings

    def _check_uid_zero(
        self, users: list[UserInfo], findings: list[Finding]
    ) -> None:
        """Check for non-root users with UID 0."""
        uid_zero = [u for u in users if u.uid == 0 and u.username != "root"]
        for user in uid_zero:
            findings.append(self._make_finding(
                finding_id=f"ARGUS-USR-001-{user.username}",
                title=f"Non-root user '{user.username}' has UID 0",
                severity="critical",
                description=(
                    f"User '{user.username}' has UID 0, which grants root-level "
                    "privileges. This is a common persistence technique."
                ),
                evidence=[f"{user.username}:x:{user.uid}:{user.gid}"],
                recommendation=f"Investigate user '{user.username}' and remove if unauthorized.",
                mitre=["T1098"],
            ))

    def _check_empty_passwords(
        self, users: list[UserInfo], findings: list[Finding]
    ) -> None:
        """Check for users with empty password fields."""
        empty_pwd = [
            u for u in users
            if u.password_empty and u.shell not in NOLOGIN_SHELLS
        ]
        for user in empty_pwd:
            findings.append(self._make_finding(
                finding_id=f"ARGUS-USR-002-{user.username}",
                title=f"User '{user.username}' has an empty password",
                severity="high",
                description=(
                    f"User '{user.username}' has no password set and has a login shell "
                    f"({user.shell}). Anyone can log in as this user."
                ),
                evidence=[f"{user.username} shell={user.shell} password=empty"],
                recommendation=f"Set a strong password or disable login for '{user.username}'.",
                mitre=["T1078"],
            ))

    def _check_service_accounts_with_shells(
        self, users: list[UserInfo], findings: list[Finding]
    ) -> None:
        """Check for service accounts with interactive login shells."""
        service_uid_range = range(100, 1000)
        for user in users:
            if (
                user.uid in service_uid_range
                and user.shell not in NOLOGIN_SHELLS
                and user.username not in ("nobody",)
            ):
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-USR-003-{user.username}",
                    title=f"Service account '{user.username}' has a login shell",
                    severity="low",
                    description=(
                        f"Service account '{user.username}' (UID {user.uid}) has shell "
                        f"'{user.shell}'. Service accounts should not have interactive shells."
                    ),
                    evidence=[f"{user.username}:uid={user.uid}:shell={user.shell}"],
                    recommendation=f"Set shell to /usr/sbin/nologin for '{user.username}'.",
                    mitre=["T1078.003"],
                ))
