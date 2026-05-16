"""SSH configuration collector for ARGUS."""

from pathlib import Path

from argus.collectors.base import BaseCollector
from argus.models import SSHConfig

SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"


def _normalize_key(key: str) -> str:
    """Normalize sshd directive names for internal lookups."""
    return key.strip().lower()


def _strip_inline_comment(line: str) -> str:
    """Remove unquoted sshd_config comments from a line."""
    return line.split("#", 1)[0].strip()


def _parse_directive(line: str) -> tuple[str, str] | None:
    """Parse one sshd_config directive line."""
    cleaned = _strip_inline_comment(line)
    if not cleaned:
        return None
    parts = cleaned.split(None, 1)
    if len(parts) != 2:
        return None
    return _normalize_key(parts[0]), parts[1].strip()


def _normalize_scalar(value: str) -> str:
    """Normalize simple sshd scalar values."""
    return value.strip().strip('"\'').lower()


class SSHCollector(BaseCollector):
    """Collect and parse SSH server configuration."""

    name = "ssh"

    def collect(self) -> SSHConfig:
        """Read and parse sshd_config into an SSHConfig model."""
        raw = self.safe_read_file(SSHD_CONFIG_PATH)
        if raw is None:
            return SSHConfig()
        return self._parse_config(raw)

    def _parse_config(self, raw: str) -> SSHConfig:
        """Parse raw sshd_config content into structured data."""
        config_dict: dict[str, str] = {}
        for line in raw.splitlines():
            directive = _parse_directive(line)
            if directive is None:
                continue
            key, value = directive
            config_dict[key] = value
        return self._build_ssh_config(config_dict)

    def _build_ssh_config(self, config_dict: dict[str, str]) -> SSHConfig:
        """Build SSHConfig model from parsed config dictionary."""
        config = SSHConfig(raw_config=config_dict)
        config.permit_root_login = _normalize_scalar(
            config_dict.get("permitrootlogin", "unknown")
        )
        config.password_authentication = _normalize_scalar(
            config_dict.get("passwordauthentication", "unknown")
        )
        config.permit_empty_passwords = config_dict.get(
            "permitemptypasswords", "unknown"
        )
        self._parse_port_and_address(config, config_dict)
        self._parse_crypto_settings(config, config_dict)
        self._parse_auth_limits(config, config_dict)
        return config

    def _parse_port_and_address(
        self, config: SSHConfig, config_dict: dict[str, str]
    ) -> None:
        """Extract Port and ListenAddress settings."""
        port_str = config_dict.get("port", "22")
        try:
            config.port = int(port_str)
        except ValueError:
            config.port = 22
        config.listen_address = config_dict.get("listenaddress", "")

    def _parse_crypto_settings(
        self, config: SSHConfig, config_dict: dict[str, str]
    ) -> None:
        """Extract cipher and key exchange algorithm settings."""
        ciphers_str = config_dict.get("ciphers", "")
        if ciphers_str:
            config.ciphers = [c.strip() for c in ciphers_str.split(",")]
        kex_str = config_dict.get("kexalgorithms", "")
        if kex_str:
            config.kex_algorithms = [k.strip() for k in kex_str.split(",")]

    def _parse_auth_limits(
        self, config: SSHConfig, config_dict: dict[str, str]
    ) -> None:
        """Extract MaxAuthTries, LoginGraceTime, and X11Forwarding."""
        max_auth = config_dict.get("maxauthtries", "6")
        try:
            config.max_auth_tries = int(max_auth)
        except ValueError:
            config.max_auth_tries = 6
        grace_time = config_dict.get("logingracetime", "120")
        try:
            config.login_grace_time = int(grace_time)
        except ValueError:
            config.login_grace_time = 120
        config.x11_forwarding = config_dict.get("x11forwarding", "unknown")
        config.protocol = config_dict.get("protocol", "")

    def collect_authorized_keys(self) -> dict[str, list[str]]:
        """Collect SSH authorized_keys for all users."""
        passwd = self.safe_read_file("/etc/passwd")
        if passwd is None:
            return {}
        keys_by_user: dict[str, list[str]] = {}
        for line in passwd.splitlines():
            parts = line.strip().split(":")
            if len(parts) < 6:
                continue
            username = parts[0]
            home = parts[5]
            auth_keys_path = Path(home) / ".ssh" / "authorized_keys"
            if auth_keys_path.is_file():
                content = self.safe_read_file(str(auth_keys_path))
                if content:
                    keys = [
                        k.strip() for k in content.splitlines()
                        if k.strip() and not k.strip().startswith("#")
                    ]
                    if keys:
                        keys_by_user[username] = keys
        return keys_by_user
