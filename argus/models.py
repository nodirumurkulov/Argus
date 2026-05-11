"""ARGUS data models for findings, reports, and host data."""

from enum import Enum

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single security finding produced by an analyzer."""

    id: str = Field(description="Unique finding identifier, e.g. ARGUS-SSH-001")
    title: str = Field(description="Short human-readable title")
    severity: SeverityLevel = Field(description="Finding severity level")
    category: str = Field(description="Finding category, e.g. ssh, users, network")
    description: str = Field(description="Detailed description of the finding")
    evidence: list[str] = Field(default_factory=list, description="Evidence strings")
    recommendation: str = Field(default="", description="Remediation recommendation")
    mitre: list[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    references: list[str] = Field(default_factory=list, description="External reference URLs")
    llm_summary: str | None = Field(default=None, description="LLM-generated summary")
