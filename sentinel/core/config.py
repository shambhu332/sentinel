"""SENTINEL configuration loader.

Loads settings from .env file and environment variables via pydantic-settings.
API keys are stored as SecretStr so they never leak into logs, repr, or tracebacks.
"""
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from .env and environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # LLM credentials
    cerebras_api_key: SecretStr = Field(default=SecretStr(""), alias="CEREBRAS_API_KEY")
    groq_api_key: SecretStr = Field(default=SecretStr(""), alias="GROQ_API_KEY")
    mistral_api_key: SecretStr = Field(default=SecretStr(""), alias="MISTRAL_API_KEY")
    github_token: SecretStr = Field(default=SecretStr(""), alias="GITHUB_TOKEN")
    ollama_host: str = Field(default="http://localhost:11434", alias="OLLAMA_HOST")

    # Runtime
    log_level: str = Field(default="INFO", alias="SENTINEL_LOG_LEVEL")
    workspace: Path = Field(default=Path("./workspace"), alias="SENTINEL_WORKSPACE")
    max_apk_size_mb: int = Field(default=500, alias="SENTINEL_MAX_APK_SIZE_MB", ge=1, le=2048)
    scan_timeout_seconds: int = Field(
        default=1800, alias="SENTINEL_SCAN_TIMEOUT_SECONDS", ge=60, le=86400
    )

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v.upper()

    @field_validator("workspace")
    @classmethod
    def _validate_workspace(cls, v: Path) -> Path:
        resolved = v.expanduser().resolve()
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved

    def has_cerebras_key(self) -> bool:
        return bool(self.cerebras_api_key.get_secret_value().strip())


_settings: Settings | None = None


def get_settings() -> Settings:
    """Lazy singleton accessor."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Reset singleton (test use only)."""
    global _settings
    _settings = None