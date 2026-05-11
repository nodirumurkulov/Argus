"""SSH configuration collector for ARGUS."""

from argus.collectors.base import BaseCollector
from argus.models import SSHConfig

SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"


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
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                config_dict[parts[0].lower()] = parts[1]
        return self._build_ssh_config(config_dict)

    def _build_ssh_config(self, config_dict: dict[str, str]) -> SSHConfig:
        """Build SSHConfig model from parsed config dictionary."""
        config = SSHConfig(raw_config=config_dict)
        config.permit_root_login = config_dict.get("permitrootlogin", "unknown")
        config.password_authentication = config_dict.get(
            "passwordauthentication", "unknown"
        )
        config.permit_empty_passwords = config_dict.get(
            "permitemptypasswords", "unknown"
        )
        self._parse_port_and_address(config, config_dict)
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
