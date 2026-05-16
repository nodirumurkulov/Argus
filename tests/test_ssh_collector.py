"""SSH collector parsing tests."""

from argus.collectors.ssh import SSHCollector


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
