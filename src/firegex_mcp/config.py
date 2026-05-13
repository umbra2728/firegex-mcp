"""Runtime configuration loaded from FIREGEX_MCP_* env vars."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class FiregexSettings(BaseSettings):
    """Settings for the Firegex MCP server.

    All variables use the FIREGEX_MCP_ prefix. PASSWORD is required.
    """

    model_config = SettingsConfigDict(
        env_prefix="FIREGEX_MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    base_url: HttpUrl = Field(default=HttpUrl("http://localhost:4444"))
    password: str
    timeout_seconds: float = Field(default=30.0, gt=0)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
