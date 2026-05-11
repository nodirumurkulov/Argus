"""Shared test fixtures for ARGUS test suite."""

import pytest


@pytest.fixture
def sample_finding_data() -> dict:
    """Return sample finding data for testing."""
    return {
        "id": "ARGUS-SSH-001",
        "title": "SSH password authentication is enabled",
        "severity": "medium",
        "category": "ssh",
        "description": "Password authentication increases exposure to brute-force attacks.",
        "evidence": ["PasswordAuthentication yes"],
        "recommendation": "Disable SSH password authentication and use key-based login.",
        "mitre": ["T1110"],
        "references": [],
    }
