"""Baseline and drift detection helpers."""

from pydantic import BaseModel, Field

from argus.models import Finding


class DriftResult(BaseModel):
    """Finding-level drift between baseline and current reports."""

    new: list[Finding] = Field(default_factory=list)
    resolved: list[Finding] = Field(default_factory=list)
    unchanged: list[Finding] = Field(default_factory=list)
