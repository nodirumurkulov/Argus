"""SSH collector parsing tests."""

from argus.collectors.ssh import SSHCollector


def test_ssh_parser_strips_inline_comments() -> None:
    """Fallback parser should ignore comments after directive values."""
    config = SSHCollector()._parse_config("PasswordAuthentication yes # temporary\n")

    assert config.password_authentication == "yes"
