"""ARGUS configuration management."""

from pathlib import Path

from pydantic import BaseModel, Field


DEFAULT_CONFIG_DIR = Path.home() / ".config" / "argus"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.yaml"


class LLMConfig(BaseModel):
    """LLM provider configuration."""

    provider: str = "ollama"
    base_url: str = "http://localhost:11434"
    model: str = "llama3.1:8b"
    temperature: float = 0.2
    timeout: int = 120
    enabled: bool = True
