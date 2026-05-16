"""Stable finding fingerprint helpers."""

import hashlib

FINDING_FINGERPRINT_VERSION = "v1"
FINGERPRINT_PART_SEPARATOR = "\x1f"


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


def build_fingerprint_material(
    finding_id: str,
    category: str,
    title: str,
    severity: str,
    evidence: list[str],
) -> str:
    """Build deterministic material for a finding fingerprint."""
    parts = [
        FINDING_FINGERPRINT_VERSION,
        normalize_fingerprint_value(finding_id),
        normalize_fingerprint_value(category),
        normalize_fingerprint_value(title),
        normalize_fingerprint_value(severity),
        *normalize_fingerprint_evidence(evidence),
    ]
    return FINGERPRINT_PART_SEPARATOR.join(parts)


def hash_fingerprint_material(material: str) -> str:
    """Hash fingerprint material into a compact stable identifier."""
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def generate_finding_fingerprint(
    finding_id: str,
    category: str,
    title: str,
    severity: str,
    evidence: list[str],
) -> str:
    """Generate a stable fingerprint for a finding."""
    material = build_fingerprint_material(
        finding_id=finding_id,
        category=category,
        title=title,
        severity=severity,
        evidence=evidence,
    )
    return f"{FINDING_FINGERPRINT_VERSION}:{hash_fingerprint_material(material)}"
