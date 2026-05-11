"""ARGUS configuration management."""

from pathlib import Path

import yaml
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


class OutputConfig(BaseModel):
    """Output configuration."""

    default_format: str = "markdown"
    output_dir: str = "."
    colorize: bool = True
    verbose: bool = False


class ArgusConfig(BaseModel):
    """Root ARGUS configuration."""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    scan_timeout: int = 300
    log_level: str = "info"


def load_config(config_path: Path | None = None) -> ArgusConfig:
    """Load configuration from YAML file. Returns defaults if file doesn't exist."""
    path = config_path or DEFAULT_CONFIG_PATH
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return ArgusConfig(**data)
    return ArgusConfig()
