"""Finding fingerprint tests."""

from argus.fingerprints import (
    generate_finding_fingerprint,
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


def test_generated_fingerprint_is_stable_for_same_issue() -> None:
    """The same logical issue should produce the same fingerprint."""
    first = generate_finding_fingerprint(
        finding_id="ARGUS-SSH-002",
        category="ssh",
        title="SSH password authentication is enabled",
        severity="medium",
        evidence=["PasswordAuthentication yes"],
    )
    second = generate_finding_fingerprint(
        finding_id="argus-ssh-002",
        category="SSH",
        title="ssh password authentication is enabled",
        severity="MEDIUM",
        evidence=["  passwordauthentication   YES "],
    )

    assert first == second
