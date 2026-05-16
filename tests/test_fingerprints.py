"""Finding fingerprint tests."""

from argus.fingerprints import normalize_fingerprint_value


def test_fingerprint_value_normalization() -> None:
    """Whitespace and casing should not change normalized values."""
    assert normalize_fingerprint_value("  PasswordAuthentication   YES ") == (
        "passwordauthentication yes"
    )
