"""Shared pytest fixtures."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wipe FIREGEX_MCP_* env vars before each test so tests are deterministic."""
    for key in list(os.environ):
        if key.startswith("FIREGEX_MCP_"):
            monkeypatch.delenv(key, raising=False)
