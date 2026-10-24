"""Configuration settings for the AI Safety & Compliance Readiness Pipeline."""

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"


class PipelineConfig(BaseModel):
    # Target application configuration
    target_mode: str = Field(
        default_factory=lambda: os.getenv("TARGET_MODE", "simulated"),
        description="'simulated' (unit-test fixture) or 'external' (live OpenAI/Ollama model)"
    )
    target_api_url: Optional[str] = Field(
        default_factory=lambda: os.getenv("TARGET_API_URL", "http://localhost:11434/v1/chat/completions"),
        description="OpenAI-compatible API URL"
    )
    target_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("TARGET_API_KEY", None),
        description="Optional API key for external model"
    )
    target_model_name: str = Field(
        default_factory=lambda: os.getenv("TARGET_MODEL_NAME", "llama3"),
        description="Model identifier"
    )

    # Hardening / Guardrail settings
    enable_input_guardrail: bool = True
    enable_output_guardrail: bool = True
    active_locales: list[str] = Field(default_factory=lambda: ["US", "UK", "IN", "Global"])

    # File paths
    red_team_data_path: Path = DATA_DIR / "red_team_probes.json"
    pii_benchmark_path: Path = DATA_DIR / "synthetic_pii_benchmark.json"
    output_dir: Path = ARTIFACTS_DIR


# Ensure artifacts directory exists
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
