"""Finding fingerprint tests."""

from argus.fingerprints import (
    normalize_fingerprint_evidence,
    normalize_fingerprint_value,
)


def test_fingerprint_value_normalization() -> None:
    """Whitespace and casing should not change normalized values."""
    assert normalize_fingerprint_value("  PasswordAuthentication   YES ") == (
        "passwordauthentication yes"
    )


def test_fingerprint_evidence_normalization_is_deterministic() -> None:
    """Evidence normalization should sort and deduplicate values."""
    evidence = [" Port 22 ", "port 22", "PasswordAuthentication YES"]

    assert normalize_fingerprint_evidence(evidence) == [
        "passwordauthentication yes",
        "port 22",
    ]
