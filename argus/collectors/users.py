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
