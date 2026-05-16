"""Stable finding fingerprint helpers."""

FINDING_FINGERPRINT_VERSION = "v1"


def normalize_fingerprint_value(value: str) -> str:
    """Normalize a string before it contributes to a fingerprint."""
    return " ".join(value.strip().lower().split())
