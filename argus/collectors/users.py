"""User and group information collector for ARGUS."""

from pathlib import Path

from argus.collectors.base import BaseCollector
from argus.models import UserInfo


class UserCollector(BaseCollector):
    """Collect local user and group information."""

    name = "users"

    def collect(self) -> list[UserInfo]:
        """Collect all local user information."""
        users = self._parse_passwd()
        groups = self._parse_groups()
        shadow_status = self._parse_shadow()
        self._enrich_users(users, groups, shadow_status)
        return users

    def _parse_passwd(self) -> list[UserInfo]:
        """Parse /etc/passwd for user accounts."""
        raw = self.safe_read_file("/etc/passwd")
        if raw is None:
            return []
        users = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            users.append(UserInfo(
                username=parts[0],
                uid=int(parts[2]),
                gid=int(parts[3]),
                gecos=parts[4],
                home=parts[5],
                shell=parts[6],
            ))
        return users

    def _parse_groups(self) -> dict[str, list[str]]:
        """Parse /etc/group to map usernames to their groups."""
        raw = self.safe_read_file("/etc/group")
        if raw is None:
            return {}
        user_groups: dict[str, list[str]] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue
            group_name = parts[0]
            members = parts[3].split(",") if parts[3] else []
            for member in members:
                member = member.strip()
                if member:
                    user_groups.setdefault(member, []).append(group_name)
        return user_groups

    def _parse_shadow(self) -> dict[str, str]:
        """Parse /etc/shadow for password status. Returns username -> password_field."""
        raw = self.safe_read_file("/etc/shadow")
        if raw is None:
            return {}
        shadow: dict[str, str] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                shadow[parts[0]] = parts[1]
        return shadow

    def _enrich_users(
        self,
        users: list[UserInfo],
        groups: dict[str, list[str]],
        shadow: dict[str, str],
    ) -> None:
        """Enrich user records with group membership and password status."""
        nologin_shells = {"/usr/sbin/nologin", "/bin/false", "/sbin/nologin"}
        for user in users:
            user.groups = groups.get(user.username, [])
            pwd_field = shadow.get(user.username, "")
            if pwd_field == "":
                user.password_empty = True
                user.has_password = False
            elif pwd_field.startswith("!") or pwd_field.startswith("*"):
                user.has_password = False
            else:
                user.has_password = True
            if user.shell not in nologin_shells:
                pass  # has a login shell — analyzers will check this

    def collect_last_logins(self) -> list[dict[str, str]]:
        """Collect recent login history using the last command."""
        output = self.safe_run_command(["last", "-n", "50", "--time-format", "iso"])
        if output is None:
            return []
        logins: list[dict[str, str]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("wtmp") or line.startswith("reboot"):
                continue
            parts = line.split()
            if len(parts) >= 3:
                logins.append({
                    "user": parts[0],
                    "terminal": parts[1],
                    "source": parts[2] if len(parts) > 2 else "",
                    "raw": line,
                })
        return logins
