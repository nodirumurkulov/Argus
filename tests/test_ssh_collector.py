"""SSH collector parsing tests."""

from argus.collectors.ssh import SSHCollector


class FakeSSHCollector(SSHCollector):
    """SSH collector with deterministic command and file output."""

    def __init__(self, commands: dict[tuple[str, ...], str | None] | None = None) -> None:
        self.commands = commands or {}

    def safe_run_command(self, command: list[str]) -> str | None:
        return self.commands.get(tuple(command))


def test_ssh_parser_strips_inline_comments() -> None:
    """Fallback parser should ignore comments after directive values."""
    config = SSHCollector()._parse_config("PasswordAuthentication yes # temporary\n")

    assert config.password_authentication == "yes"


def test_ssh_parser_normalizes_boolean_values() -> None:
    """Fallback parser should normalize case for analyzer-facing values."""
    config = SSHCollector()._parse_config(
        "PermitRootLogin YES\n"
        "PermitEmptyPasswords No\n"
        "X11Forwarding YES\n"
    )

    assert config.permit_root_login == "yes"
    assert config.permit_empty_passwords == "no"
    assert config.x11_forwarding == "yes"


def test_ssh_parser_normalizes_algorithm_lists() -> None:
    """Fallback parser should normalize comma-separated algorithm lists."""
    config = SSHCollector()._parse_config(
        "Ciphers AES128-CBC, chacha20-poly1305@openssh.com\n"
        "KexAlgorithms Diffie-Hellman-Group1-SHA1, curve25519-sha256\n"
    )

    assert config.ciphers == ["aes128-cbc", "chacha20-poly1305@openssh.com"]
    assert config.kex_algorithms == ["diffie-hellman-group1-sha1", "curve25519-sha256"]


def test_ssh_collector_prefers_effective_sshd_output() -> None:
    """Collector should prefer sshd -T output when it is available."""
    collector = FakeSSHCollector({("sshd", "-T"): "passwordauthentication no\n"})

    config = collector.collect()

    assert config.source == "sshd -T"
    assert config.password_authentication == "no"
