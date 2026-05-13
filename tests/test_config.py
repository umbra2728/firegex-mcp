"""Tests for FiregexSettings env loading."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from firegex_mcp.config import FiregexSettings


def test_required_password_missing() -> None:
    with pytest.raises(ValidationError) as exc:
        FiregexSettings()
    assert "password" in str(exc.value).lower()


def test_defaults_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIREGEX_MCP_PASSWORD", "p")
    s = FiregexSettings()
    assert str(s.base_url) == "http://localhost:4444/"
    assert s.timeout_seconds == 30
    assert s.verify_ssl is True
    assert s.log_level == "INFO"


def test_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIREGEX_MCP_PASSWORD", "p")
    monkeypatch.setenv("FIREGEX_MCP_BASE_URL", "https://firegex.local:4444")
    monkeypatch.setenv("FIREGEX_MCP_TIMEOUT_SECONDS", "5")
    monkeypatch.setenv("FIREGEX_MCP_VERIFY_SSL", "false")
    monkeypatch.setenv("FIREGEX_MCP_LOG_LEVEL", "DEBUG")
    s = FiregexSettings()
    assert str(s.base_url) == "https://firegex.local:4444/"
    assert s.timeout_seconds == 5
    assert s.verify_ssl is False
    assert s.log_level == "DEBUG"


def test_invalid_log_level_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIREGEX_MCP_PASSWORD", "p")
    monkeypatch.setenv("FIREGEX_MCP_LOG_LEVEL", "VERBOSE")
    with pytest.raises(ValidationError):
        FiregexSettings()


def test_timeout_must_be_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIREGEX_MCP_PASSWORD", "p")
    monkeypatch.setenv("FIREGEX_MCP_TIMEOUT_SECONDS", "0")
    with pytest.raises(ValidationError):
        FiregexSettings()
