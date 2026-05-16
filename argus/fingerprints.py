"""Stable finding fingerprint helpers."""

FINDING_FINGERPRINT_VERSION = "v1"


def normalize_fingerprint_value(value: str) -> str:
    """Normalize a string before it contributes to a fingerprint."""
    return " ".join(value.strip().lower().split())


def normalize_fingerprint_evidence(evidence: list[str]) -> list[str]:
    """Normalize evidence while dropping empty values."""
    normalized = [
        normalized
        for item in evidence
        if (normalized := normalize_fingerprint_value(item))
    ]
    return sorted(dict.fromkeys(normalized))
