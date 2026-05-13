# firegex-mcp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an MCP server that wraps the Firegex REST API (four modules: nfregex, nfproxy, firewall, porthijack + system endpoints), so an LLM can drive CTF defence end-to-end.

**Architecture:** FastMCP over stdio. Async httpx client with auto-JWT lifecycle (login on first use, single retry on 401, `asyncio.Lock` against login storms). Pydantic v2 DTOs mirror the upstream snake_case JSON. Regex base64 is handled inside the client; the tool boundary stays plain-text. Two upload tools for nfproxy Python filters: inline `code: str` and `path: str`. Layout mirrors the neighbouring `packmate-mcp` project.

**Tech Stack:** Python ≥3.10, `mcp[cli]≥1.2.0` (FastMCP), `httpx`, `pydantic` v2, `pydantic-settings`, `pytest`+`pytest-asyncio`+`respx`, `ruff`, `mypy` (strict), `uv` for tooling, hatchling build backend, GitHub Actions + PyPI Trusted Publishing.

**Spec:** `docs/superpowers/specs/2026-05-13-firegex-mcp-design.md`.

---

## Notes

- Tests come first in every task. The flow is red → green → commit.
- Every code block is complete — copy/paste should produce working code.
- Working directory: `/Users/ismailgaleev/0xb00b5/firegex-mcp` (the outer repo). The inner `firegex/` directory is upstream Firegex and is **read-only reference material** — never modify it.
- Commit messages follow Conventional Commits.
- All Python files start with `from __future__ import annotations` so type hints stay forward-compatible on 3.10.
- `pytest` runs with `asyncio_mode=auto`, so `@pytest.mark.asyncio` is not required (kept on `async def` tests for clarity).

---

## File structure (locked in)

```
firegex-mcp/
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── .env.example
├── .gitignore
├── .github/workflows/{ci.yml,release.yml}
├── docs/superpowers/
│   ├── specs/2026-05-13-firegex-mcp-design.md   (already written)
│   └── plans/2026-05-13-firegex-mcp.md          (this file)
├── src/firegex_mcp/
│   ├── __init__.py
│   ├── __main__.py
│   ├── config.py
│   ├── client.py
│   ├── models.py
│   ├── server.py
│   └── tools/
│       ├── __init__.py
│       ├── system.py
│       ├── nfregex.py
│       ├── nfproxy.py
│       ├── firewall.py
│       └── porthijack.py
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── test_config.py
    ├── test_models.py
    ├── test_client.py
    └── test_tools.py
```

Each file has one responsibility. `client.py` will be the largest (~400 lines including 48 methods); everything else stays small. If `tests/test_client.py` grows past ~600 lines during implementation, split into `test_client_auth.py` + per-module files — but keep it together for now to mirror packmate-mcp.

---

## Task 1: Bootstrap project layout

**Files:**
- Create: `pyproject.toml` (overwrites the existing stub)
- Create: `.gitignore`
- Create: `.env.example`
- Delete: `main.py` (the stub print)
- Create: `src/firegex_mcp/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Write `.gitignore`**

```gitignore
# Python
__pycache__/
*.py[oc]
*.egg-info/
build/
dist/

# Virtual environments
.venv/
.env

# Tooling
.coverage
.coverage.*
.pytest_cache/
.mypy_cache/
.ruff_cache/

# IDE
.idea/
.vscode/

# OS
.DS_Store

# Local sibling clone of the Firegex upstream repo used as reference material,
# not part of this package.
/firegex/
```

- [ ] **Step 2: Write `.env.example`**

```
# Copy to .env and fill in real values. Never commit .env.
FIREGEX_MCP_BASE_URL=http://localhost:4444
FIREGEX_MCP_PASSWORD=change-me
FIREGEX_MCP_TIMEOUT_SECONDS=30
FIREGEX_MCP_VERIFY_SSL=true
FIREGEX_MCP_LOG_LEVEL=INFO
```

- [ ] **Step 3: Write `pyproject.toml`**

```toml
[project]
name = "firegex-mcp"
version = "0.1.0"
description = "MCP server for Firegex — CTF regex/proxy firewall"
readme = "README.md"
requires-python = ">=3.10"
license = { text = "MIT" }
authors = [{ name = "Ismail Galeev" }]
keywords = ["mcp", "firegex", "ctf", "firewall", "netfilter"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security",
]
dependencies = [
    "mcp[cli]>=1.2.0",
    "httpx>=0.27",
    "pydantic>=2.0",
    "pydantic-settings>=2.0",
]

[project.scripts]
firegex-mcp = "firegex_mcp.__main__:main"

[project.urls]
Homepage = "https://github.com/umbra2728/firegex-mcp"
Issues = "https://github.com/umbra2728/firegex-mcp/issues"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/firegex_mcp"]

[dependency-groups]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-cov>=5.0",
    "respx>=0.21",
    "ruff>=0.6",
    "mypy>=1.10",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "I", "W", "UP", "B", "ASYNC"]

[tool.mypy]
python_version = "3.10"
strict = true
files = ["src/firegex_mcp"]
```

- [ ] **Step 4: Delete the stub `main.py`**

```bash
rm main.py
```

- [ ] **Step 5: Create `src/firegex_mcp/__init__.py`**

```python
"""Firegex MCP server."""

from importlib.metadata import version

__version__ = version("firegex-mcp")
```

- [ ] **Step 6: Create `tests/__init__.py` (empty file)**

```bash
touch tests/__init__.py
```

- [ ] **Step 7: Create `tests/conftest.py`**

```python
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
```

- [ ] **Step 8: Sync dependencies and verify package is importable**

Run:
```bash
uv sync --dev
uv run python -c "import firegex_mcp; print(firegex_mcp.__version__)"
```
Expected: prints `0.1.0`.

- [ ] **Step 9: Commit**

```bash
git add pyproject.toml .gitignore .env.example src tests
git rm main.py
git commit -m "feat: bootstrap firegex-mcp project layout"
```

---

## Task 2: FiregexSettings (config)

**Files:**
- Create: `src/firegex_mcp/config.py`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_config.py`:

```python
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
```

- [ ] **Step 2: Run tests — they should fail**

Run:
```bash
uv run pytest tests/test_config.py -v
```
Expected: FAIL (`ModuleNotFoundError: No module named 'firegex_mcp.config'`).

- [ ] **Step 3: Implement `src/firegex_mcp/config.py`**

```python
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
    verify_ssl: bool = True
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
```

- [ ] **Step 4: Run tests — they should pass**

Run:
```bash
uv run pytest tests/test_config.py -v
```
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/firegex_mcp/config.py tests/test_config.py
git commit -m "feat(config): FiregexSettings with env-loading"
```

---

## Task 3: Enums + small DTOs

**Files:**
- Create: `src/firegex_mcp/models.py` (first slice)
- Test: `tests/test_models.py` (first slice)

- [ ] **Step 1: Write failing tests**

`tests/test_models.py`:

```python
"""Tests for pydantic models mirroring Firegex DTOs."""

from __future__ import annotations

import base64

from firegex_mcp.models import (
    AppStatus,
    FwAction,
    FwMode,
    FwProto,
    FwTable,
    IpInterface,
    NfproxyProtocol,
    Protocol,
    RegexMode,
    ServiceStatus,
    StatusMessageModel,
    StatusModel,
)


def test_app_status_values() -> None:
    assert {e.value for e in AppStatus} == {"init", "run"}


def test_protocol_values() -> None:
    assert {e.value for e in Protocol} == {"tcp", "udp"}


def test_nfproxy_protocol_values() -> None:
    assert {e.value for e in NfproxyProtocol} == {"tcp", "http"}


def test_regex_mode_values() -> None:
    assert {e.value for e in RegexMode} == {"C", "S", "B"}


def test_service_status_values() -> None:
    assert {e.value for e in ServiceStatus} == {"active", "stop", "pause"}


def test_fw_action_values() -> None:
    assert {e.value for e in FwAction} == {"accept", "drop", "reject"}


def test_fw_mode_values() -> None:
    assert {e.value for e in FwMode} == {"in", "out", "forward"}


def test_fw_table_values() -> None:
    assert {e.value for e in FwTable} == {"filter", "mangle"}


def test_fw_proto_values() -> None:
    assert {e.value for e in FwProto} == {"tcp", "udp", "both", "any"}


def test_status_model_round_trip() -> None:
    s = StatusModel.model_validate({"status": "run", "loggined": True, "version": "1.2.3"})
    assert s.status == AppStatus.RUN
    assert s.loggined is True
    assert s.version == "1.2.3"


def test_status_message_round_trip() -> None:
    m = StatusMessageModel.model_validate({"status": "ok"})
    assert m.status == "ok"


def test_ip_interface_round_trip() -> None:
    i = IpInterface.model_validate({"name": "eth0", "addr": "10.0.0.1/24"})
    assert i.name == "eth0"
    assert i.addr == "10.0.0.1/24"
```

(`base64` is imported here but used by later tests in Task 4; safe to leave.)

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_models.py -v
```
Expected: FAIL (`ModuleNotFoundError: No module named 'firegex_mcp.models'`).

- [ ] **Step 3: Implement `src/firegex_mcp/models.py`**

```python
"""Pydantic models matching Firegex REST DTOs.

Source of truth: firegex/backend/{utils/models.py, routers/*.py, modules/*/models.py}.
Firegex's API uses snake_case JSON, so no alias generator is needed.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


# ---------- enums ----------


class AppStatus(str, Enum):
    INIT = "init"
    RUN = "run"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class NfproxyProtocol(str, Enum):
    TCP = "tcp"
    HTTP = "http"


class RegexMode(str, Enum):
    CLIENT = "C"
    SERVER = "S"
    BOTH = "B"


class ServiceStatus(str, Enum):
    ACTIVE = "active"
    STOP = "stop"
    PAUSE = "pause"


class FwAction(str, Enum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"


class FwMode(str, Enum):
    IN = "in"
    OUT = "out"
    FORWARD = "forward"


class FwTable(str, Enum):
    FILTER = "filter"
    MANGLE = "mangle"


class FwProto(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    BOTH = "both"
    ANY = "any"


# ---------- base ----------


class _Base(BaseModel):
    """Base model that allows both alias and field-name population."""

    model_config = ConfigDict(populate_by_name=True, use_enum_values=False)


# ---------- shared DTOs ----------


class StatusModel(_Base):
    status: AppStatus
    loggined: bool
    version: str


class StatusMessageModel(_Base):
    status: str


class IpInterface(_Base):
    name: str
    addr: str
```

- [ ] **Step 4: Run — should pass**

```bash
uv run pytest tests/test_models.py -v
```
Expected: 12 passed.

- [ ] **Step 5: Commit**

```bash
git add src/firegex_mcp/models.py tests/test_models.py
git commit -m "feat(models): enums and shared status/interface DTOs"
```

---

## Task 4: Per-module DTOs (nfregex, nfproxy, firewall, porthijack)

**Files:**
- Modify: `src/firegex_mcp/models.py`
- Modify: `tests/test_models.py`

- [ ] **Step 1: Append failing tests to `tests/test_models.py`**

```python
from firegex_mcp.models import (
    FirewallSettings,
    NfproxyService,
    NfregexService,
    PortHijackService,
    PyFilterModel,
    RegexModel,
    RuleFormAdd,
    RuleInfo,
    RuleModel,
)


def test_nfregex_service_round_trip() -> None:
    s = NfregexService.model_validate(
        {
            "service_id": "abc",
            "status": "active",
            "port": 8080,
            "name": "vuln",
            "proto": "tcp",
            "ip_int": "0.0.0.0",
            "n_regex": 2,
            "n_packets": 5,
            "fail_open": False,
        }
    )
    assert s.port == 8080
    assert s.status == ServiceStatus.ACTIVE
    assert s.proto == Protocol.TCP


def test_nfproxy_service_round_trip() -> None:
    s = NfproxyService.model_validate(
        {
            "service_id": "abc",
            "status": "stop",
            "port": 80,
            "name": "http",
            "proto": "http",
            "ip_int": "::",
            "n_filters": 1,
            "edited_packets": 0,
            "blocked_packets": 0,
            "fail_open": True,
        }
    )
    assert s.proto == NfproxyProtocol.HTTP


def test_port_hijack_service_round_trip() -> None:
    s = PortHijackService.model_validate(
        {
            "service_id": "abc",
            "active": True,
            "public_port": 22,
            "proxy_port": 2222,
            "name": "ssh",
            "proto": "tcp",
            "ip_src": "0.0.0.0",
            "ip_dst": "127.0.0.1",
        }
    )
    assert s.public_port == 22
    assert s.proxy_port == 2222


def test_regex_model_decodes_base64() -> None:
    encoded = base64.b64encode(b"flag\\{[^}]+\\}").decode()
    r = RegexModel.model_validate(
        {
            "regex": encoded,
            "mode": "B",
            "id": 1,
            "service_id": "abc",
            "n_packets": 0,
            "is_case_sensitive": True,
            "active": True,
        }
    )
    assert r.regex == "flag\\{[^}]+\\}"
    assert r.mode == RegexMode.BOTH


def test_regex_model_passthrough_when_already_plain() -> None:
    # If a caller constructs RegexModel directly with plain text, accept it.
    r = RegexModel(
        regex="flag\\{[^}]+\\}",
        mode=RegexMode.BOTH,
        id=1,
        service_id="abc",
        n_packets=0,
        is_case_sensitive=True,
        active=True,
    )
    assert r.regex == "flag\\{[^}]+\\}"


def test_pyfilter_model_round_trip() -> None:
    f = PyFilterModel.model_validate(
        {
            "name": "block_flag",
            "service_id": "abc",
            "blocked_packets": 3,
            "edited_packets": 1,
            "active": True,
        }
    )
    assert f.name == "block_flag"
    assert f.blocked_packets == 3


def test_rule_model_round_trip() -> None:
    r = RuleModel.model_validate(
        {
            "active": True,
            "name": "drop-bad",
            "proto": "tcp",
            "table": "filter",
            "src": "10.0.0.0/8",
            "dst": "0.0.0.0/0",
            "port_src_from": 1,
            "port_src_to": 65535,
            "port_dst_from": 22,
            "port_dst_to": 22,
            "action": "drop",
            "mode": "in",
        }
    )
    assert r.action == FwAction.DROP
    assert r.mode == FwMode.IN


def test_rule_info_round_trip() -> None:
    info = RuleInfo.model_validate(
        {
            "rules": [],
            "policy": "accept",
            "enabled": True,
        }
    )
    assert info.policy == FwAction.ACCEPT


def test_rule_form_add_round_trip() -> None:
    form = RuleFormAdd(rules=[], policy=FwAction.DROP)
    assert form.policy == FwAction.DROP


def test_firewall_settings_round_trip() -> None:
    s = FirewallSettings.model_validate(
        {
            "keep_rules": True,
            "allow_loopback": True,
            "allow_established": True,
            "allow_icmp": True,
            "multicast_dns": False,
            "allow_upnp": False,
            "drop_invalid": True,
            "allow_dhcp": False,
        }
    )
    assert s.keep_rules is True
    assert s.allow_dhcp is False
```

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_models.py -v
```
Expected: ImportError on the new symbols.

- [ ] **Step 3: Extend `src/firegex_mcp/models.py` with the per-module DTOs**

Append after the existing `IpInterface` class:

```python
# ---------- regex base64 helper ----------


def _b64decode_str(value: str) -> str:
    """Decode a base64-encoded UTF-8 string. Pass plain text through unchanged.

    Firegex stores regexes base64-encoded in JSON. Callers who construct
    RegexModel directly may pass plain text; we accept both so model_validate
    on raw API output and direct construction work the same way.
    """
    import base64
    import binascii

    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return value


# ---------- nfregex ----------


class NfregexService(_Base):
    service_id: str
    status: ServiceStatus
    port: int
    name: str
    proto: Protocol
    ip_int: str
    n_regex: int = 0
    n_packets: int = 0
    fail_open: bool = False


class RegexModel(_Base):
    """Regex row. `regex` is exposed as plain text; on the wire it's base64."""

    regex: str
    mode: RegexMode
    id: int
    service_id: str
    n_packets: int = 0
    is_case_sensitive: bool
    active: bool

    @classmethod
    def model_validate(cls, obj, *args, **kwargs):  # type: ignore[override]
        # Decode the regex field if it came from the API as base64.
        if isinstance(obj, dict) and "regex" in obj and isinstance(obj["regex"], str):
            obj = {**obj, "regex": _b64decode_str(obj["regex"])}
        return super().model_validate(obj, *args, **kwargs)


# ---------- nfproxy ----------


class NfproxyService(_Base):
    service_id: str
    status: ServiceStatus
    port: int
    name: str
    proto: NfproxyProtocol
    ip_int: str
    n_filters: int = 0
    edited_packets: int = 0
    blocked_packets: int = 0
    fail_open: bool = True


class PyFilterModel(_Base):
    name: str
    service_id: str
    blocked_packets: int = 0
    edited_packets: int = 0
    active: bool = True


# ---------- firewall ----------


class FirewallSettings(_Base):
    keep_rules: bool
    allow_loopback: bool
    allow_established: bool
    allow_icmp: bool
    multicast_dns: bool
    allow_upnp: bool
    drop_invalid: bool
    allow_dhcp: bool


class RuleModel(_Base):
    active: bool
    name: str
    proto: FwProto
    table: FwTable
    src: str
    dst: str
    port_src_from: int
    port_src_to: int
    port_dst_from: int
    port_dst_to: int
    action: FwAction
    mode: FwMode


class RuleInfo(_Base):
    rules: list[RuleModel]
    policy: FwAction
    enabled: bool


class RuleFormAdd(_Base):
    rules: list[RuleModel]
    policy: FwAction


# ---------- porthijack ----------


class PortHijackService(_Base):
    service_id: str
    active: bool
    public_port: int
    proxy_port: int
    name: str
    proto: Protocol
    ip_src: str
    ip_dst: str
```

- [ ] **Step 4: Run — should pass**

```bash
uv run pytest tests/test_models.py -v
```
Expected: all tests pass (22 total).

- [ ] **Step 5: Commit**

```bash
git add src/firegex_mcp/models.py tests/test_models.py
git commit -m "feat(models): per-module DTOs and base64 regex handling"
```

---

## Task 5: Client exception hierarchy + transport

**Files:**
- Create: `src/firegex_mcp/client.py`
- Test: `tests/test_client.py` (first slice)

- [ ] **Step 1: Write failing tests for exceptions and HTTP status mapping**

`tests/test_client.py`:

```python
"""Tests for FiregexClient HTTP layer."""

from __future__ import annotations

import httpx
import pytest
import respx

from firegex_mcp.client import (
    FiregexAuthError,
    FiregexClient,
    FiregexConnectionError,
    FiregexError,
    FiregexNotFoundError,
    FiregexNotInitializedError,
    FiregexServerError,
    FiregexValidationError,
)
from firegex_mcp.config import FiregexSettings


def _settings() -> FiregexSettings:
    return FiregexSettings(password="p")


# ---------- exceptions ----------


def test_exception_hierarchy() -> None:
    for sub in (
        FiregexAuthError,
        FiregexConnectionError,
        FiregexNotFoundError,
        FiregexNotInitializedError,
        FiregexValidationError,
        FiregexServerError,
    ):
        assert issubclass(sub, FiregexError)


def test_exceptions_carry_messages() -> None:
    e = FiregexNotFoundError("Regex 42 not found.")
    assert str(e) == "Regex 42 not found."


# ---------- _request status mapping ----------


@pytest.mark.asyncio
async def test_request_maps_401_to_auth_error() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(return_value=httpx.Response(200, json={
                "status": "run", "loggined": False, "version": "1.0"}))
            mock.post("/api/login").mock(return_value=httpx.Response(401))
            with pytest.raises(FiregexAuthError) as exc:
                await client.get_status_authed()
            assert "Wrong password" in str(exc.value)


@pytest.mark.asyncio
async def test_request_maps_404_to_not_found() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/x").mock(return_value=httpx.Response(404))
            with pytest.raises(FiregexNotFoundError):
                await client._request("GET", "/x", authed=False)


@pytest.mark.asyncio
async def test_request_maps_400_to_validation_error_with_body() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.post("/x").mock(return_value=httpx.Response(400, text="bad regex"))
            with pytest.raises(FiregexValidationError) as exc:
                await client._request("POST", "/x", authed=False)
            assert "bad regex" in str(exc.value)


@pytest.mark.asyncio
async def test_request_maps_500_to_server_error() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/x").mock(return_value=httpx.Response(500, text="boom"))
            with pytest.raises(FiregexServerError) as exc:
                await client._request("GET", "/x", authed=False)
            assert "500" in str(exc.value)
            assert "boom" in str(exc.value)


@pytest.mark.asyncio
async def test_request_maps_connection_error() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/x").mock(side_effect=httpx.ConnectError("refused"))
            with pytest.raises(FiregexConnectionError) as exc:
                await client._request("GET", "/x", authed=False)
            assert "Cannot reach Firegex" in str(exc.value)


@pytest.mark.asyncio
async def test_request_maps_timeout() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/x").mock(side_effect=httpx.TimeoutException("slow"))
            with pytest.raises(FiregexConnectionError) as exc:
                await client._request("GET", "/x", authed=False)
            assert "timed out" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_not_initialized_when_status_init() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(return_value=httpx.Response(200, json={
                "status": "init", "loggined": False, "version": "1.0"}))
            with pytest.raises(FiregexNotInitializedError):
                await client.get_status_authed()
```

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_client.py -v
```
Expected: ImportError.

- [ ] **Step 3: Implement the client core**

`src/firegex_mcp/client.py`:

```python
"""Async HTTP client for Firegex's REST API."""

from __future__ import annotations

import asyncio
import logging
from types import TracebackType
from typing import Any

import httpx

from firegex_mcp.config import FiregexSettings
from firegex_mcp.models import AppStatus, StatusModel

log = logging.getLogger(__name__)


# ---------- exceptions ----------


class FiregexError(Exception):
    """Base for all errors raised by FiregexClient."""


class FiregexConnectionError(FiregexError):
    """Network failure: cannot reach Firegex, or request timed out."""


class FiregexAuthError(FiregexError):
    """HTTP 401/403 or bad password during /api/login."""


class FiregexNotInitializedError(FiregexError):
    """Server responded with status='init' — call set_password first."""


class FiregexNotFoundError(FiregexError):
    """HTTP 404 — resource does not exist."""


class FiregexValidationError(FiregexError):
    """HTTP 4xx (other than 401/403/404) — Firegex rejected the request."""


class FiregexServerError(FiregexError):
    """HTTP 5xx — Firegex internal error."""


# ---------- client ----------


_PUBLIC_PATHS = frozenset({"/api/status", "/api/login", "/api/set-password"})


class FiregexClient:
    """Thin async client over Firegex's REST API.

    Use as an async context manager:
        async with FiregexClient(settings) as client:
            services = await client.list_nfregex_services()

    Auto-JWT lifecycle: the first protected request triggers
    /api/status + /api/login. A 401 on a protected path triggers exactly one
    re-login + retry; a second 401 raises FiregexAuthError.
    """

    def __init__(self, settings: FiregexSettings) -> None:
        self._settings = settings
        self._http: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._auth_lock: asyncio.Lock = asyncio.Lock()

    async def __aenter__(self) -> FiregexClient:
        self._http = httpx.AsyncClient(
            base_url=str(self._settings.base_url).rstrip("/"),
            timeout=self._settings.timeout_seconds,
            verify=self._settings.verify_ssl,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ---------- request helper ----------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        authed: bool = True,
        _retried: bool = False,
    ) -> httpx.Response:
        assert self._http is not None, "FiregexClient must be used as async context manager"
        headers: dict[str, str] = {}
        if authed and path not in _PUBLIC_PATHS:
            if self._token is None:
                await self._ensure_logged_in()
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            response = await self._http.request(
                method, path, json=json, params=params, data=data, headers=headers
            )
        except httpx.TimeoutException as e:
            raise FiregexConnectionError(
                f"Request to {method} {path} timed out after "
                f"{self._settings.timeout_seconds}s."
            ) from e
        except httpx.ConnectError as e:
            raise FiregexConnectionError(
                f"Cannot reach Firegex at {self._settings.base_url}. "
                "Is the server running?"
            ) from e
        except httpx.HTTPError as e:
            raise FiregexConnectionError(f"HTTP error: {e}") from e

        if response.status_code == 401:
            if path == "/api/login":
                raise FiregexAuthError(
                    "Wrong password. Check FIREGEX_MCP_PASSWORD."
                )
            if not _retried and authed:
                log.warning("401 on %s %s — re-logging in", method, path)
                self._token = None
                await self._ensure_logged_in()
                return await self._request(
                    method, path, json=json, params=params, data=data,
                    authed=authed, _retried=True,
                )
            raise FiregexAuthError(
                "Could not validate credentials after re-login."
            )
        if response.status_code == 403:
            raise FiregexAuthError(f"Forbidden: {response.text}")
        if response.status_code == 404:
            raise FiregexNotFoundError(f"Resource not found: {method} {path}")
        if 400 <= response.status_code < 500:
            raise FiregexValidationError(
                f"Firegex rejected request ({response.status_code}): {response.text}"
            )
        if response.status_code >= 500:
            raise FiregexServerError(
                f"Firegex server error ({response.status_code}). "
                f"Body: {response.text}"
            )
        return response

    # ---------- auth ----------

    async def _ensure_logged_in(self) -> None:
        async with self._auth_lock:
            if self._token is not None:
                return
            status = await self.get_status()
            if status.status == AppStatus.INIT:
                raise FiregexNotInitializedError(
                    "Firegex is uninitialized. Call set_password first."
                )
            r = await self._request(
                "POST",
                "/api/login",
                data={
                    "username": "firegex",
                    "password": self._settings.password,
                    "grant_type": "password",
                },
                authed=False,
            )
            self._token = r.json()["access_token"]
            log.info("Logged in to Firegex")

    async def get_status(self) -> StatusModel:
        r = await self._request("GET", "/api/status", authed=False)
        return StatusModel.model_validate(r.json())

    async def get_status_authed(self) -> StatusModel:
        """Force the auth lifecycle to run, then return the (now-authed) status."""
        await self._ensure_logged_in()
        return await self.get_status()
```

- [ ] **Step 4: Run — should pass**

```bash
uv run pytest tests/test_client.py -v
```
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add src/firegex_mcp/client.py tests/test_client.py
git commit -m "feat(client): exception hierarchy and HTTP transport"
```

---

## Task 6: Client auth lifecycle (login, retry, lock)

**Files:**
- Modify: `tests/test_client.py`

(Implementation already in place from Task 5 — we now verify the lifecycle behaviours.)

- [ ] **Step 1: Append the auth-lifecycle tests**

```python
import base64
import asyncio


@pytest.mark.asyncio
async def test_login_caches_token_and_attaches_bearer() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(return_value=httpx.Response(
                200, json={"status": "run", "loggined": False, "version": "1.0"}))
            login = mock.post("/api/login").mock(return_value=httpx.Response(
                200, json={"access_token": "TKN", "token_type": "bearer"}))
            target = mock.get("/api/anywhere").mock(return_value=httpx.Response(200, json=[]))

            await client._request("GET", "/api/anywhere")
            assert login.call_count == 1
            assert target.calls[0].request.headers["Authorization"] == "Bearer TKN"

            # Second call must NOT re-login.
            await client._request("GET", "/api/anywhere")
            assert login.call_count == 1


@pytest.mark.asyncio
async def test_login_form_sends_password_field() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(return_value=httpx.Response(
                200, json={"status": "run", "loggined": False, "version": "1.0"}))
            login = mock.post("/api/login").mock(return_value=httpx.Response(
                200, json={"access_token": "TKN", "token_type": "bearer"}))
            mock.get("/api/anywhere").mock(return_value=httpx.Response(200, json=[]))

            await client._request("GET", "/api/anywhere")
            body = login.calls[0].request.read().decode()
            assert "password=p" in body
            assert "grant_type=password" in body


@pytest.mark.asyncio
async def test_401_triggers_one_retry() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(return_value=httpx.Response(
                200, json={"status": "run", "loggined": False, "version": "1.0"}))
            login = mock.post("/api/login").mock(return_value=httpx.Response(
                200, json={"access_token": "TKN", "token_type": "bearer"}))
            target = mock.get("/api/anywhere").mock(side_effect=[
                httpx.Response(401),
                httpx.Response(200, json=[]),
            ])

            await client._request("GET", "/api/anywhere")
            assert login.call_count == 2  # initial + after-401
            assert target.call_count == 2


@pytest.mark.asyncio
async def test_double_401_raises_auth_error() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(return_value=httpx.Response(
                200, json={"status": "run", "loggined": False, "version": "1.0"}))
            mock.post("/api/login").mock(return_value=httpx.Response(
                200, json={"access_token": "TKN", "token_type": "bearer"}))
            mock.get("/api/anywhere").mock(return_value=httpx.Response(401))
            with pytest.raises(FiregexAuthError) as exc:
                await client._request("GET", "/api/anywhere")
            assert "after re-login" in str(exc.value)


@pytest.mark.asyncio
async def test_concurrent_first_calls_share_one_login() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(return_value=httpx.Response(
                200, json={"status": "run", "loggined": False, "version": "1.0"}))
            login = mock.post("/api/login").mock(return_value=httpx.Response(
                200, json={"access_token": "TKN", "token_type": "bearer"}))
            mock.get("/api/anywhere").mock(return_value=httpx.Response(200, json=[]))

            await asyncio.gather(*(
                client._request("GET", "/api/anywhere") for _ in range(5)
            ))
            assert login.call_count == 1


@pytest.mark.asyncio
async def test_public_paths_skip_login() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            status = mock.get("/api/status").mock(return_value=httpx.Response(
                200, json={"status": "run", "loggined": False, "version": "1.0"}))
            login = mock.post("/api/login").mock()  # should never be called
            await client.get_status()
            assert status.called
            assert not login.called
```

- [ ] **Step 2: Run — they should already pass thanks to Task 5 implementation**

```bash
uv run pytest tests/test_client.py -v
```
Expected: 14 passed.

- [ ] **Step 3: Commit**

```bash
git add tests/test_client.py
git commit -m "test(client): auth lifecycle (login cache, retry, lock)"
```

---

## Task 7: Client — system methods

**Files:**
- Modify: `src/firegex_mcp/client.py`
- Modify: `tests/test_client.py`

- [ ] **Step 1: Append failing tests**

```python
from firegex_mcp.models import IpInterface


@pytest.mark.asyncio
async def test_set_password() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            route = mock.post("/api/set-password").mock(return_value=httpx.Response(
                200, json={"status": "ok", "access_token": "T"}))
            result = await client.set_password("newpass")
            assert result == {"status": "ok", "access_token": "T"}
            body = route.calls[0].request.read().decode()
            assert '"password":"newpass"' in body


@pytest.mark.asyncio
async def test_change_password() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(return_value=httpx.Response(
                200, json={"status": "run", "loggined": False, "version": "1.0"}))
            mock.post("/api/login").mock(return_value=httpx.Response(
                200, json={"access_token": "T", "token_type": "bearer"}))
            route = mock.post("/api/change-password").mock(return_value=httpx.Response(
                200, json={"status": "ok", "access_token": "T2"}))
            await client.change_password("new", expire=True)
            body = route.calls[0].request.read().decode()
            assert '"password":"new"' in body
            assert '"expire":true' in body
            assert client._token is None  # cleared after expire=True


@pytest.mark.asyncio
async def test_change_password_keeps_token_when_no_expire() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(return_value=httpx.Response(
                200, json={"status": "run", "loggined": False, "version": "1.0"}))
            mock.post("/api/login").mock(return_value=httpx.Response(
                200, json={"access_token": "T", "token_type": "bearer"}))
            mock.post("/api/change-password").mock(return_value=httpx.Response(
                200, json={"status": "ok", "access_token": "T"}))
            await client.change_password("new", expire=False)
            assert client._token == "T"


@pytest.mark.asyncio
async def test_list_interfaces() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(return_value=httpx.Response(
                200, json={"status": "run", "loggined": False, "version": "1.0"}))
            mock.post("/api/login").mock(return_value=httpx.Response(
                200, json={"access_token": "T", "token_type": "bearer"}))
            mock.get("/api/interfaces").mock(return_value=httpx.Response(
                200, json=[{"name": "eth0", "addr": "10.0.0.1"}]))
            ifs = await client.list_interfaces()
            assert ifs == [IpInterface(name="eth0", addr="10.0.0.1")]


@pytest.mark.asyncio
async def test_reset_firegex() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            mock.get("/api/status").mock(return_value=httpx.Response(
                200, json={"status": "run", "loggined": False, "version": "1.0"}))
            mock.post("/api/login").mock(return_value=httpx.Response(
                200, json={"access_token": "T", "token_type": "bearer"}))
            route = mock.post("/api/reset").mock(return_value=httpx.Response(
                200, json={"status": "ok"}))
            await client.reset(delete=True)
            body = route.calls[0].request.read().decode()
            assert '"delete":true' in body
```

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_client.py -v
```
Expected: `AttributeError: 'FiregexClient' object has no attribute 'set_password'` (and similar).

- [ ] **Step 3: Add the system methods to `src/firegex_mcp/client.py`**

Append (after `get_status_authed`):

```python
    # ---------- system ----------

    async def set_password(self, password: str) -> dict[str, Any]:
        r = await self._request(
            "POST", "/api/set-password",
            json={"password": password},
            authed=False,
        )
        return dict(r.json())

    async def change_password(self, password: str, expire: bool = True) -> dict[str, Any]:
        r = await self._request(
            "POST", "/api/change-password",
            json={"password": password, "expire": expire},
        )
        if expire:
            # Server rotated the JWT secret — our cached token is now invalid.
            self._token = None
        return dict(r.json())

    async def list_interfaces(self) -> list[IpInterface]:
        r = await self._request("GET", "/api/interfaces")
        return [IpInterface.model_validate(x) for x in r.json()]

    async def reset(self, delete: bool) -> dict[str, Any]:
        r = await self._request(
            "POST", "/api/reset",
            json={"delete": delete},
        )
        return dict(r.json())
```

Add `from firegex_mcp.models import IpInterface` to the existing imports (replace the line `from firegex_mcp.models import AppStatus, StatusModel` with:

```python
from firegex_mcp.models import AppStatus, IpInterface, StatusModel
```

- [ ] **Step 4: Run — should pass**

```bash
uv run pytest tests/test_client.py -v
```
Expected: 19 passed.

- [ ] **Step 5: Commit**

```bash
git add src/firegex_mcp/client.py tests/test_client.py
git commit -m "feat(client): system endpoints (password, interfaces, reset)"
```

---

## Task 8: Client — nfregex methods

**Files:**
- Modify: `src/firegex_mcp/client.py`
- Modify: `tests/test_client.py`

- [ ] **Step 1: Append failing tests**

Helper used in this and later sections; add at the top of the new section:

```python
from firegex_mcp.models import (
    NfregexService,
    RegexMode,
    RegexModel,
)


def _nfregex_service_json(sid: str = "abc") -> dict:
    return {
        "service_id": sid, "status": "active", "port": 8080,
        "name": "vuln", "proto": "tcp", "ip_int": "0.0.0.0",
        "n_regex": 0, "n_packets": 0, "fail_open": False,
    }


async def _logged_in(mock: respx.Router) -> None:
    mock.get("/api/status").mock(return_value=httpx.Response(
        200, json={"status": "run", "loggined": False, "version": "1.0"}))
    mock.post("/api/login").mock(return_value=httpx.Response(
        200, json={"access_token": "T", "token_type": "bearer"}))


@pytest.mark.asyncio
async def test_list_nfregex_services() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfregex/services").mock(return_value=httpx.Response(
                200, json=[_nfregex_service_json()]))
            svcs = await client.list_nfregex_services()
            assert len(svcs) == 1
            assert isinstance(svcs[0], NfregexService)


@pytest.mark.asyncio
async def test_get_nfregex_service() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfregex/services/abc").mock(return_value=httpx.Response(
                200, json=_nfregex_service_json()))
            s = await client.get_nfregex_service("abc")
            assert s.service_id == "abc"


@pytest.mark.asyncio
async def test_add_nfregex_service() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.post("/api/nfregex/services").mock(return_value=httpx.Response(
                200, json={"status": "ok", "service_id": "abc"}))
            r = await client.add_nfregex_service(
                name="vuln", port=8080, proto="tcp", ip_int="0.0.0.0", fail_open=False,
            )
            assert r["service_id"] == "abc"
            body = route.calls[0].request.read().decode()
            assert '"port":8080' in body
            assert '"proto":"tcp"' in body


@pytest.mark.asyncio
async def test_start_stop_delete_nfregex_service() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            r_start = mock.post("/api/nfregex/services/abc/start").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            r_stop = mock.post("/api/nfregex/services/abc/stop").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            r_del = mock.delete("/api/nfregex/services/abc").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            await client.start_nfregex_service("abc")
            await client.stop_nfregex_service("abc")
            await client.delete_nfregex_service("abc")
            assert r_start.called and r_stop.called and r_del.called


@pytest.mark.asyncio
async def test_rename_nfregex_service() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.put("/api/nfregex/services/abc/rename").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            await client.rename_nfregex_service("abc", "newname")
            body = route.calls[0].request.read().decode()
            assert '"name":"newname"' in body


@pytest.mark.asyncio
async def test_update_nfregex_service_settings() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.put("/api/nfregex/services/abc/settings").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            await client.update_nfregex_service_settings(
                "abc", port=9090, fail_open=True,
            )
            body = route.calls[0].request.read().decode()
            assert '"port":9090' in body
            assert '"fail_open":true' in body
            assert "proto" not in body  # unset fields omitted


@pytest.mark.asyncio
async def test_list_regexes_decodes_base64() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            encoded = base64.b64encode(b"flag\\{[^}]+\\}").decode()
            mock.get("/api/nfregex/services/abc/regexes").mock(
                return_value=httpx.Response(200, json=[{
                    "regex": encoded, "mode": "B", "id": 1, "service_id": "abc",
                    "n_packets": 0, "is_case_sensitive": True, "active": True,
                }]))
            rxs = await client.list_regexes("abc")
            assert len(rxs) == 1
            assert rxs[0].regex == "flag\\{[^}]+\\}"


@pytest.mark.asyncio
async def test_add_regex_encodes_base64() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.post("/api/nfregex/regexes").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            await client.add_regex(
                service_id="abc", regex="flag\\{[^}]+\\}",
                mode=RegexMode.BOTH, is_case_sensitive=True, active=True,
            )
            body = route.calls[0].request.read().decode()
            sent_b64 = base64.b64encode(b"flag\\{[^}]+\\}").decode()
            assert f'"regex":"{sent_b64}"' in body
            assert '"mode":"B"' in body


@pytest.mark.asyncio
async def test_regex_enable_disable_delete() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            r_get = mock.get("/api/nfregex/regexes/7").mock(return_value=httpx.Response(
                200, json={
                    "regex": base64.b64encode(b"x").decode(), "mode": "C",
                    "id": 7, "service_id": "abc",
                    "n_packets": 0, "is_case_sensitive": False, "active": True,
                }))
            r_en = mock.post("/api/nfregex/regexes/7/enable").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            r_dis = mock.post("/api/nfregex/regexes/7/disable").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            r_del = mock.delete("/api/nfregex/regexes/7").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            got = await client.get_regex(7)
            assert isinstance(got, RegexModel) and got.id == 7
            await client.enable_regex(7)
            await client.disable_regex(7)
            await client.delete_regex(7)
            assert r_get.called and r_en.called and r_dis.called and r_del.called


@pytest.mark.asyncio
async def test_nfregex_metrics_returns_text() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfregex/metrics").mock(return_value=httpx.Response(
                200, text='firegex_blocked_packets{...} 5'))
            t = await client.get_nfregex_metrics()
            assert "firegex_blocked_packets" in t
```

- [ ] **Step 2: Run — should fail (no methods)**

```bash
uv run pytest tests/test_client.py -v
```

- [ ] **Step 3: Add the nfregex client methods**

Append to `src/firegex_mcp/client.py` (and extend the existing models import to include `NfregexService, RegexMode, RegexModel`):

```python
    # ---------- nfregex: services ----------

    async def list_nfregex_services(self) -> list[NfregexService]:
        r = await self._request("GET", "/api/nfregex/services")
        return [NfregexService.model_validate(x) for x in r.json()]

    async def get_nfregex_service(self, service_id: str) -> NfregexService:
        r = await self._request("GET", f"/api/nfregex/services/{service_id}")
        return NfregexService.model_validate(r.json())

    async def add_nfregex_service(
        self, *, name: str, port: int, proto: str, ip_int: str, fail_open: bool = False,
    ) -> dict[str, Any]:
        r = await self._request(
            "POST", "/api/nfregex/services",
            json={"name": name, "port": port, "proto": proto,
                  "ip_int": ip_int, "fail_open": fail_open},
        )
        return dict(r.json())

    async def start_nfregex_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfregex/services/{service_id}/start")
        return dict(r.json())

    async def stop_nfregex_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfregex/services/{service_id}/stop")
        return dict(r.json())

    async def delete_nfregex_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("DELETE", f"/api/nfregex/services/{service_id}")
        return dict(r.json())

    async def rename_nfregex_service(self, service_id: str, name: str) -> dict[str, Any]:
        r = await self._request(
            "PUT", f"/api/nfregex/services/{service_id}/rename",
            json={"name": name},
        )
        return dict(r.json())

    async def update_nfregex_service_settings(
        self,
        service_id: str,
        *,
        port: int | None = None,
        proto: str | None = None,
        ip_int: str | None = None,
        fail_open: bool | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if port is not None: body["port"] = port
        if proto is not None: body["proto"] = proto
        if ip_int is not None: body["ip_int"] = ip_int
        if fail_open is not None: body["fail_open"] = fail_open
        r = await self._request(
            "PUT", f"/api/nfregex/services/{service_id}/settings", json=body,
        )
        return dict(r.json())

    # ---------- nfregex: regexes ----------

    async def list_regexes(self, service_id: str) -> list[RegexModel]:
        r = await self._request("GET", f"/api/nfregex/services/{service_id}/regexes")
        return [RegexModel.model_validate(x) for x in r.json()]

    async def get_regex(self, regex_id: int) -> RegexModel:
        r = await self._request("GET", f"/api/nfregex/regexes/{regex_id}")
        return RegexModel.model_validate(r.json())

    async def add_regex(
        self,
        *,
        service_id: str,
        regex: str,
        mode: RegexMode | str,
        is_case_sensitive: bool,
        active: bool = True,
    ) -> dict[str, Any]:
        import base64 as _b64
        encoded = _b64.b64encode(regex.encode("utf-8")).decode("ascii")
        r = await self._request(
            "POST", "/api/nfregex/regexes",
            json={
                "service_id": service_id, "regex": encoded,
                "mode": mode.value if isinstance(mode, RegexMode) else mode,
                "is_case_sensitive": is_case_sensitive, "active": active,
            },
        )
        return dict(r.json())

    async def enable_regex(self, regex_id: int) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfregex/regexes/{regex_id}/enable")
        return dict(r.json())

    async def disable_regex(self, regex_id: int) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfregex/regexes/{regex_id}/disable")
        return dict(r.json())

    async def delete_regex(self, regex_id: int) -> dict[str, Any]:
        r = await self._request("DELETE", f"/api/nfregex/regexes/{regex_id}")
        return dict(r.json())

    async def get_nfregex_metrics(self) -> str:
        r = await self._request("GET", "/api/nfregex/metrics")
        return r.text
```

Update the models import line:

```python
from firegex_mcp.models import (
    AppStatus,
    IpInterface,
    NfregexService,
    RegexMode,
    RegexModel,
    StatusModel,
)
```

- [ ] **Step 4: Run — should pass**

```bash
uv run pytest tests/test_client.py -v
```
Expected: 29 passed.

- [ ] **Step 5: Commit**

```bash
git add src/firegex_mcp/client.py tests/test_client.py
git commit -m "feat(client): nfregex services + regex CRUD with base64 wrap"
```

---

## Task 9: Client — nfproxy methods

**Files:**
- Modify: `src/firegex_mcp/client.py`
- Modify: `tests/test_client.py`

- [ ] **Step 1: Append failing tests**

```python
from firegex_mcp.models import NfproxyService, PyFilterModel


def _nfproxy_service_json(sid: str = "abc") -> dict:
    return {
        "service_id": sid, "status": "active", "port": 80,
        "name": "http", "proto": "http", "ip_int": "0.0.0.0",
        "n_filters": 0, "edited_packets": 0, "blocked_packets": 0,
        "fail_open": True,
    }


@pytest.mark.asyncio
async def test_nfproxy_services_crud() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfproxy/services").mock(return_value=httpx.Response(
                200, json=[_nfproxy_service_json()]))
            mock.get("/api/nfproxy/services/abc").mock(return_value=httpx.Response(
                200, json=_nfproxy_service_json()))
            add = mock.post("/api/nfproxy/services").mock(return_value=httpx.Response(
                200, json={"status": "ok", "service_id": "abc"}))
            mock.post("/api/nfproxy/services/abc/start").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            mock.post("/api/nfproxy/services/abc/stop").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            mock.delete("/api/nfproxy/services/abc").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            rename = mock.put("/api/nfproxy/services/abc/rename").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            update = mock.put("/api/nfproxy/services/abc/settings").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))

            assert isinstance((await client.list_nfproxy_services())[0], NfproxyService)
            assert (await client.get_nfproxy_service("abc")).service_id == "abc"
            await client.add_nfproxy_service(
                name="http", port=80, proto="http", ip_int="0.0.0.0",
            )
            assert add.called
            await client.start_nfproxy_service("abc")
            await client.stop_nfproxy_service("abc")
            await client.delete_nfproxy_service("abc")
            await client.rename_nfproxy_service("abc", "n2")
            assert '"name":"n2"' in rename.calls[0].request.read().decode()
            await client.update_nfproxy_service_settings("abc", port=8080)
            assert '"port":8080' in update.calls[0].request.read().decode()


@pytest.mark.asyncio
async def test_list_and_toggle_pyfilters() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfproxy/services/abc/pyfilters").mock(
                return_value=httpx.Response(200, json=[{
                    "name": "drop_flag", "service_id": "abc",
                    "blocked_packets": 0, "edited_packets": 0, "active": True,
                }]))
            en = mock.post("/api/nfproxy/services/abc/pyfilters/drop_flag/enable").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            dis = mock.post("/api/nfproxy/services/abc/pyfilters/drop_flag/disable").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            filters = await client.list_pyfilters("abc")
            assert filters[0].name == "drop_flag"
            assert isinstance(filters[0], PyFilterModel)
            await client.enable_pyfilter("abc", "drop_flag")
            await client.disable_pyfilter("abc", "drop_flag")
            assert en.called and dis.called


@pytest.mark.asyncio
async def test_get_and_set_pyfilter_code() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/nfproxy/services/abc/code").mock(return_value=httpx.Response(
                200, text="@pyfilter\ndef f(): pass\n"))
            put = mock.put("/api/nfproxy/services/abc/code").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            code = await client.get_pyfilter_code("abc")
            assert "@pyfilter" in code
            await client.set_pyfilter_code("abc", "new code")
            body = put.calls[0].request.read().decode()
            assert '"code":"new code"' in body
```

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_client.py -v
```

- [ ] **Step 3: Append nfproxy methods**

Add to `src/firegex_mcp/client.py` and extend models import with `NfproxyService, PyFilterModel`:

```python
    # ---------- nfproxy: services ----------

    async def list_nfproxy_services(self) -> list[NfproxyService]:
        r = await self._request("GET", "/api/nfproxy/services")
        return [NfproxyService.model_validate(x) for x in r.json()]

    async def get_nfproxy_service(self, service_id: str) -> NfproxyService:
        r = await self._request("GET", f"/api/nfproxy/services/{service_id}")
        return NfproxyService.model_validate(r.json())

    async def add_nfproxy_service(
        self, *, name: str, port: int, proto: str, ip_int: str, fail_open: bool = True,
    ) -> dict[str, Any]:
        r = await self._request(
            "POST", "/api/nfproxy/services",
            json={"name": name, "port": port, "proto": proto,
                  "ip_int": ip_int, "fail_open": fail_open},
        )
        return dict(r.json())

    async def start_nfproxy_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfproxy/services/{service_id}/start")
        return dict(r.json())

    async def stop_nfproxy_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/nfproxy/services/{service_id}/stop")
        return dict(r.json())

    async def delete_nfproxy_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("DELETE", f"/api/nfproxy/services/{service_id}")
        return dict(r.json())

    async def rename_nfproxy_service(self, service_id: str, name: str) -> dict[str, Any]:
        r = await self._request(
            "PUT", f"/api/nfproxy/services/{service_id}/rename",
            json={"name": name},
        )
        return dict(r.json())

    async def update_nfproxy_service_settings(
        self,
        service_id: str,
        *,
        port: int | None = None,
        ip_int: str | None = None,
        fail_open: bool | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if port is not None: body["port"] = port
        if ip_int is not None: body["ip_int"] = ip_int
        if fail_open is not None: body["fail_open"] = fail_open
        r = await self._request(
            "PUT", f"/api/nfproxy/services/{service_id}/settings", json=body,
        )
        return dict(r.json())

    # ---------- nfproxy: pyfilters ----------

    async def list_pyfilters(self, service_id: str) -> list[PyFilterModel]:
        r = await self._request("GET", f"/api/nfproxy/services/{service_id}/pyfilters")
        return [PyFilterModel.model_validate(x) for x in r.json()]

    async def enable_pyfilter(self, service_id: str, filter_name: str) -> dict[str, Any]:
        r = await self._request(
            "POST",
            f"/api/nfproxy/services/{service_id}/pyfilters/{filter_name}/enable",
        )
        return dict(r.json())

    async def disable_pyfilter(self, service_id: str, filter_name: str) -> dict[str, Any]:
        r = await self._request(
            "POST",
            f"/api/nfproxy/services/{service_id}/pyfilters/{filter_name}/disable",
        )
        return dict(r.json())

    async def get_pyfilter_code(self, service_id: str) -> str:
        r = await self._request("GET", f"/api/nfproxy/services/{service_id}/code")
        return r.text

    async def set_pyfilter_code(self, service_id: str, code: str) -> dict[str, Any]:
        r = await self._request(
            "PUT", f"/api/nfproxy/services/{service_id}/code",
            json={"code": code},
        )
        return dict(r.json())
```

- [ ] **Step 4: Run — should pass**

```bash
uv run pytest tests/test_client.py -v
```
Expected: 32 passed.

- [ ] **Step 5: Commit**

```bash
git add src/firegex_mcp/client.py tests/test_client.py
git commit -m "feat(client): nfproxy services + pyfilters + code I/O"
```

---

## Task 10: Client — firewall methods

**Files:**
- Modify: `src/firegex_mcp/client.py`
- Modify: `tests/test_client.py`

- [ ] **Step 1: Append failing tests**

```python
from firegex_mcp.models import FirewallSettings, FwAction, RuleInfo, RuleModel, FwProto, FwMode, FwTable


@pytest.mark.asyncio
async def test_firewall_settings_get_set() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/firewall/settings").mock(return_value=httpx.Response(
                200, json={"keep_rules": True, "allow_loopback": True,
                           "allow_established": True, "allow_icmp": True,
                           "multicast_dns": False, "allow_upnp": False,
                           "drop_invalid": True, "allow_dhcp": False}))
            put = mock.put("/api/firewall/settings").mock(return_value=httpx.Response(
                200, json={"status": "ok"}))
            s = await client.get_firewall_settings()
            assert isinstance(s, FirewallSettings)
            assert s.keep_rules is True
            await client.set_firewall_settings(s)
            body = put.calls[0].request.read().decode()
            assert '"keep_rules":true' in body


@pytest.mark.asyncio
async def test_firewall_enable_disable() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            en = mock.post("/api/firewall/enable").mock(return_value=httpx.Response(
                200, json={"status": "ok"}))
            dis = mock.post("/api/firewall/disable").mock(return_value=httpx.Response(
                200, json={"status": "ok"}))
            await client.enable_firewall()
            await client.disable_firewall()
            assert en.called and dis.called


@pytest.mark.asyncio
async def test_list_firewall_rules() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/firewall/rules").mock(return_value=httpx.Response(
                200, json={"rules": [], "policy": "accept", "enabled": True}))
            info = await client.list_firewall_rules()
            assert isinstance(info, RuleInfo)
            assert info.policy == FwAction.ACCEPT


@pytest.mark.asyncio
async def test_replace_firewall_rules() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.post("/api/firewall/rules").mock(return_value=httpx.Response(
                200, json={"status": "ok"}))
            rule = RuleModel(
                active=True, name="drop-bad", proto=FwProto.TCP, table=FwTable.FILTER,
                src="0.0.0.0/0", dst="10.0.0.1",
                port_src_from=1, port_src_to=65535,
                port_dst_from=22, port_dst_to=22,
                action=FwAction.DROP, mode=FwMode.IN,
            )
            await client.replace_firewall_rules(policy=FwAction.ACCEPT, rules=[rule])
            body = route.calls[0].request.read().decode()
            assert '"policy":"accept"' in body
            assert '"name":"drop-bad"' in body
```

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_client.py -v
```

- [ ] **Step 3: Append firewall methods**

Extend models import with `FirewallSettings, FwAction, RuleFormAdd, RuleInfo, RuleModel`. Append to `client.py`:

```python
    # ---------- firewall ----------

    async def get_firewall_settings(self) -> FirewallSettings:
        r = await self._request("GET", "/api/firewall/settings")
        return FirewallSettings.model_validate(r.json())

    async def set_firewall_settings(self, settings: FirewallSettings) -> dict[str, Any]:
        r = await self._request(
            "PUT", "/api/firewall/settings",
            json=settings.model_dump(mode="json"),
        )
        return dict(r.json())

    async def enable_firewall(self) -> dict[str, Any]:
        r = await self._request("POST", "/api/firewall/enable")
        return dict(r.json())

    async def disable_firewall(self) -> dict[str, Any]:
        r = await self._request("POST", "/api/firewall/disable")
        return dict(r.json())

    async def list_firewall_rules(self) -> RuleInfo:
        r = await self._request("GET", "/api/firewall/rules")
        return RuleInfo.model_validate(r.json())

    async def replace_firewall_rules(
        self, *, policy: FwAction, rules: list[RuleModel],
    ) -> dict[str, Any]:
        form = RuleFormAdd(rules=rules, policy=policy)
        r = await self._request(
            "POST", "/api/firewall/rules",
            json=form.model_dump(mode="json"),
        )
        return dict(r.json())
```

- [ ] **Step 4: Run — should pass**

```bash
uv run pytest tests/test_client.py -v
```
Expected: 36 passed.

- [ ] **Step 5: Commit**

```bash
git add src/firegex_mcp/client.py tests/test_client.py
git commit -m "feat(client): firewall settings, enable/disable, rule replace"
```

---

## Task 11: Client — porthijack methods

**Files:**
- Modify: `src/firegex_mcp/client.py`
- Modify: `tests/test_client.py`

- [ ] **Step 1: Append failing tests**

```python
from firegex_mcp.models import PortHijackService


def _phj_service_json(sid: str = "abc") -> dict:
    return {
        "service_id": sid, "active": True, "public_port": 22,
        "proxy_port": 2222, "name": "ssh", "proto": "tcp",
        "ip_src": "0.0.0.0", "ip_dst": "127.0.0.1",
    }


@pytest.mark.asyncio
async def test_porthijack_services_crud() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            mock.get("/api/porthijack/services").mock(return_value=httpx.Response(
                200, json=[_phj_service_json()]))
            mock.get("/api/porthijack/services/abc").mock(return_value=httpx.Response(
                200, json=_phj_service_json()))
            add = mock.post("/api/porthijack/services").mock(return_value=httpx.Response(
                200, json={"status": "ok", "service_id": "abc"}))
            mock.post("/api/porthijack/services/abc/start").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            mock.post("/api/porthijack/services/abc/stop").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            mock.delete("/api/porthijack/services/abc").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            rename = mock.put("/api/porthijack/services/abc/rename").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))

            svcs = await client.list_phj_services()
            assert isinstance(svcs[0], PortHijackService)
            assert (await client.get_phj_service("abc")).service_id == "abc"
            await client.add_phj_service(
                name="ssh", public_port=22, proxy_port=2222,
                proto="tcp", ip_src="0.0.0.0", ip_dst="127.0.0.1",
            )
            assert add.called
            body = add.calls[0].request.read().decode()
            assert '"public_port":22' in body
            assert '"proxy_port":2222' in body
            await client.start_phj_service("abc")
            await client.stop_phj_service("abc")
            await client.delete_phj_service("abc")
            await client.rename_phj_service("abc", "n2")
            assert '"name":"n2"' in rename.calls[0].request.read().decode()


@pytest.mark.asyncio
async def test_porthijack_change_destination() -> None:
    async with FiregexClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:4444") as mock:
            await _logged_in(mock)
            route = mock.put("/api/porthijack/services/abc/change-destination").mock(
                return_value=httpx.Response(200, json={"status": "ok"}))
            await client.change_phj_destination("abc", ip_dst="127.0.0.2", proxy_port=3333)
            body = route.calls[0].request.read().decode()
            assert '"ip_dst":"127.0.0.2"' in body
            assert '"proxy_port":3333' in body
```

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_client.py -v
```

- [ ] **Step 3: Append porthijack methods**

Extend models import with `PortHijackService`. Append to `client.py`:

```python
    # ---------- porthijack ----------

    async def list_phj_services(self) -> list[PortHijackService]:
        r = await self._request("GET", "/api/porthijack/services")
        return [PortHijackService.model_validate(x) for x in r.json()]

    async def get_phj_service(self, service_id: str) -> PortHijackService:
        r = await self._request("GET", f"/api/porthijack/services/{service_id}")
        return PortHijackService.model_validate(r.json())

    async def add_phj_service(
        self,
        *,
        name: str,
        public_port: int,
        proxy_port: int,
        proto: str,
        ip_src: str,
        ip_dst: str,
    ) -> dict[str, Any]:
        r = await self._request(
            "POST", "/api/porthijack/services",
            json={"name": name, "public_port": public_port, "proxy_port": proxy_port,
                  "proto": proto, "ip_src": ip_src, "ip_dst": ip_dst},
        )
        return dict(r.json())

    async def start_phj_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/porthijack/services/{service_id}/start")
        return dict(r.json())

    async def stop_phj_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("POST", f"/api/porthijack/services/{service_id}/stop")
        return dict(r.json())

    async def delete_phj_service(self, service_id: str) -> dict[str, Any]:
        r = await self._request("DELETE", f"/api/porthijack/services/{service_id}")
        return dict(r.json())

    async def rename_phj_service(self, service_id: str, name: str) -> dict[str, Any]:
        r = await self._request(
            "PUT", f"/api/porthijack/services/{service_id}/rename",
            json={"name": name},
        )
        return dict(r.json())

    async def change_phj_destination(
        self, service_id: str, *, ip_dst: str, proxy_port: int,
    ) -> dict[str, Any]:
        r = await self._request(
            "PUT", f"/api/porthijack/services/{service_id}/change-destination",
            json={"ip_dst": ip_dst, "proxy_port": proxy_port},
        )
        return dict(r.json())
```

- [ ] **Step 4: Run — should pass**

```bash
uv run pytest tests/test_client.py -v
```
Expected: 38 passed.

- [ ] **Step 5: Verify mypy is clean**

```bash
uv run mypy src
```
Expected: `Success: no issues found`.

- [ ] **Step 6: Commit**

```bash
git add src/firegex_mcp/client.py tests/test_client.py
git commit -m "feat(client): porthijack services + change_destination"
```

---

## Task 12: Server + entrypoint scaffolding

**Files:**
- Create: `src/firegex_mcp/server.py`
- Create: `src/firegex_mcp/__main__.py`
- Create: `src/firegex_mcp/tools/__init__.py` (with placeholder `register_all`)

- [ ] **Step 1: Create `src/firegex_mcp/tools/__init__.py` (empty register_all for now)**

```python
"""Tool registration for MCP server.

Each submodule exposes a `register(mcp, client)` function that attaches its tools
to the FastMCP instance using the shared FiregexClient.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient


def register_all(mcp: FastMCP, client: FiregexClient) -> None:
    # Submodules wired in Tasks 13-17.
    pass
```

- [ ] **Step 2: Create `src/firegex_mcp/server.py`**

```python
"""FastMCP server wiring.

Builds the FastMCP instance, the FiregexClient, registers all tools, and runs
over stdio.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.config import FiregexSettings
from firegex_mcp.tools import register_all

log = logging.getLogger(__name__)


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def build_server() -> FastMCP:
    """Construct a FastMCP server with all tools registered."""
    settings = FiregexSettings()  # type: ignore[call-arg]
    _configure_logging(settings.log_level)
    log.info("Connecting to Firegex at %s", settings.base_url)

    @asynccontextmanager
    async def lifespan(_server: FastMCP) -> AsyncIterator[None]:
        async with FiregexClient(settings) as client:
            register_all(mcp, client)
            yield

    mcp = FastMCP("firegex", lifespan=lifespan)
    return mcp


def run() -> None:
    """Entrypoint: build the server and run it over stdio."""
    server = build_server()
    server.run(transport="stdio")
```

- [ ] **Step 3: Create `src/firegex_mcp/__main__.py`**

```python
"""CLI entrypoint: `firegex-mcp` and `python -m firegex_mcp`."""

from __future__ import annotations

import sys

from firegex_mcp.server import run


def main() -> None:
    try:
        run()
    except Exception as e:  # noqa: BLE001 — top-level fence
        print(f"firegex-mcp failed to start: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Verify the entry-point starts (and shuts down on EOF)**

Run:
```bash
FIREGEX_MCP_PASSWORD=test uv run python -c "from firegex_mcp.server import build_server; build_server()"
```
Expected: prints log line `Connecting to Firegex at http://localhost:4444/`, no exception.

- [ ] **Step 5: Run all tests + mypy**

```bash
uv run pytest -v
uv run mypy src
uv run ruff check src tests
```
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/firegex_mcp/server.py src/firegex_mcp/__main__.py src/firegex_mcp/tools/__init__.py
git commit -m "feat(server): FastMCP lifespan scaffold + stdio entrypoint"
```

---

## Task 13: Tools — system

**Files:**
- Create: `src/firegex_mcp/tools/system.py`
- Create: `tests/test_tools.py` (first slice)
- Modify: `src/firegex_mcp/tools/__init__.py`

- [ ] **Step 1: Write failing tests**

`tests/test_tools.py`:

```python
"""Integration tests for MCP tools.

We import the registered tool callables directly from FastMCP and exercise them
against a mocked Firegex HTTP API. The FastMCP tool registry stores tools in
`_tool_manager._tools`; each entry exposes the underlying coroutine as `.fn`.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio
import respx
from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.config import FiregexSettings


@pytest_asyncio.fixture
async def client() -> AsyncIterator[FiregexClient]:
    async with FiregexClient(FiregexSettings(password="p")) as c:
        yield c


def _mcp() -> FastMCP:
    return FastMCP("firegex-test")


def _tool_fn(mcp: FastMCP, name: str):
    return mcp._tool_manager._tools[name].fn


async def _logged_in(mock: respx.Router) -> None:
    mock.get("/api/status").mock(return_value=httpx.Response(
        200, json={"status": "run", "loggined": False, "version": "1.0"}))
    mock.post("/api/login").mock(return_value=httpx.Response(
        200, json={"access_token": "T", "token_type": "bearer"}))


# ---------- system ----------


@pytest.mark.asyncio
async def test_get_firegex_status_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.system import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "get_firegex_status")

    with respx.mock(base_url="http://localhost:4444") as mock:
        mock.get("/api/status").mock(return_value=httpx.Response(
            200, json={"status": "run", "loggined": False, "version": "1.0"}))
        result = await fn()
        assert result["status"] == "run"
        assert result["version"] == "1.0"


@pytest.mark.asyncio
async def test_set_password_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.system import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_password")

    with respx.mock(base_url="http://localhost:4444") as mock:
        route = mock.post("/api/set-password").mock(return_value=httpx.Response(
            200, json={"status": "ok", "access_token": "T"}))
        await fn(password="secret")
        assert route.called


@pytest.mark.asyncio
async def test_list_interfaces_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.system import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_interfaces")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/interfaces").mock(return_value=httpx.Response(
            200, json=[{"name": "lo", "addr": "127.0.0.1"}]))
        ifs = await fn()
        assert ifs[0].name == "lo"


@pytest.mark.asyncio
async def test_reset_firegex_tool_requires_explicit_flag(client: FiregexClient) -> None:
    from firegex_mcp.tools.system import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "reset_firegex")

    # The `delete` parameter has no default; the schema requires it.
    with pytest.raises(TypeError):
        await fn()


@pytest.mark.asyncio
async def test_reset_firegex_tool_passes_delete(client: FiregexClient) -> None:
    from firegex_mcp.tools.system import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "reset_firegex")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.post("/api/reset").mock(return_value=httpx.Response(
            200, json={"status": "ok"}))
        await fn(delete=False)
        body = route.calls[0].request.read().decode()
        assert '"delete":false' in body
```

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_tools.py -v
```
Expected: ImportError.

- [ ] **Step 3: Implement `src/firegex_mcp/tools/system.py`**

```python
"""MCP tools for Firegex system endpoints (status, password, interfaces, reset)."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.models import IpInterface, StatusModel


def register(mcp: FastMCP, client: FiregexClient) -> None:
    @mcp.tool()
    async def get_firegex_status() -> StatusModel:
        """Return Firegex global status: `init` (no password yet) or `run`.

        Also reports the API version and whether the current session is logged in.
        """
        return await client.get_status()

    @mcp.tool()
    async def set_password(password: str) -> dict[str, Any]:
        """Set the initial Firegex password. Only valid while status == 'init'."""
        return await client.set_password(password)

    @mcp.tool()
    async def change_password(password: str, expire: bool = True) -> dict[str, Any]:
        """Change the Firegex password (status == 'run' only).

        `expire=True` rotates the server JWT secret, invalidating all current
        sessions; the MCP client transparently re-logs in on the next call.
        """
        return await client.change_password(password, expire=expire)

    @mcp.tool()
    async def list_interfaces() -> list[IpInterface]:
        """List the IPv4 and IPv6 interfaces visible to Firegex."""
        return await client.list_interfaces()

    @mcp.tool()
    async def reset_firegex(delete: bool) -> dict[str, Any]:
        """Reset Firegex's nftables state.

        DANGEROUS when `delete=True`: this also wipes all SQLite databases
        (services, regexes, rules). Use `delete=False` to only flush nftables
        rules and reload the saved config.
        """
        return await client.reset(delete=delete)

    @mcp.tool()
    async def login_probe() -> dict[str, Any]:
        """Force the auth lifecycle and return the (now-authenticated) status.

        Useful for verifying connectivity, credentials, and that the server has
        been initialised. Raises `FiregexNotInitializedError` when status='init'.
        """
        status = await client.get_status_authed()
        return status.model_dump(mode="json")
```

- [ ] **Step 4: Wire it into `tools/__init__.py`**

Replace `tools/__init__.py`:

```python
"""Tool registration for MCP server."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.tools import system


def register_all(mcp: FastMCP, client: FiregexClient) -> None:
    system.register(mcp, client)
```

- [ ] **Step 5: Run — should pass**

```bash
uv run pytest tests/test_tools.py -v
```
Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add src/firegex_mcp/tools/system.py src/firegex_mcp/tools/__init__.py tests/test_tools.py
git commit -m "feat(tools): system tools (status, password, interfaces, reset)"
```

---

## Task 14: Tools — nfregex

**Files:**
- Create: `src/firegex_mcp/tools/nfregex.py`
- Modify: `src/firegex_mcp/tools/__init__.py`
- Modify: `tests/test_tools.py`

- [ ] **Step 1: Append failing tests**

```python
# ---------- nfregex ----------


@pytest.mark.asyncio
async def test_nfregex_services_listed(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfregex import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_nfregex_services")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/nfregex/services").mock(return_value=httpx.Response(
            200, json=[{
                "service_id": "abc", "status": "active", "port": 8080,
                "name": "vuln", "proto": "tcp", "ip_int": "0.0.0.0",
                "n_regex": 0, "n_packets": 0, "fail_open": False,
            }]))
        svcs = await fn()
        assert svcs[0].service_id == "abc"


@pytest.mark.asyncio
async def test_add_regex_tool_encodes_b64(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfregex import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "add_regex")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.post("/api/nfregex/regexes").mock(return_value=httpx.Response(
            200, json={"status": "ok"}))
        await fn(
            service_id="abc", regex="flag\\{.+\\}", mode="B",
            is_case_sensitive=True, active=True,
        )
        body = route.calls[0].request.read().decode()
        expected = base64.b64encode(b"flag\\{.+\\}").decode()
        assert f'"regex":"{expected}"' in body


@pytest.mark.asyncio
async def test_list_regexes_decodes_b64_via_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfregex import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_regexes")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        encoded = base64.b64encode(b"x").decode()
        mock.get("/api/nfregex/services/abc/regexes").mock(return_value=httpx.Response(
            200, json=[{
                "regex": encoded, "mode": "C", "id": 1, "service_id": "abc",
                "n_packets": 0, "is_case_sensitive": False, "active": True,
            }]))
        rxs = await fn(service_id="abc")
        assert rxs[0].regex == "x"


@pytest.mark.asyncio
async def test_get_nfregex_metrics_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfregex import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "get_nfregex_metrics")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/nfregex/metrics").mock(return_value=httpx.Response(
            200, text='firegex_blocked_packets{...} 7'))
        t = await fn()
        assert "firegex_blocked_packets" in t
```

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_tools.py -v
```

- [ ] **Step 3: Implement `src/firegex_mcp/tools/nfregex.py`**

```python
"""MCP tools for Firegex nfregex (kernel-side PCRE2 regex filter)."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.models import NfregexService, Protocol, RegexMode, RegexModel


def register(mcp: FastMCP, client: FiregexClient) -> None:
    @mcp.tool()
    async def list_nfregex_services() -> list[NfregexService]:
        """List nfregex services (one Firegex service = one TCP/UDP port being filtered)."""
        return await client.list_nfregex_services()

    @mcp.tool()
    async def get_nfregex_service(service_id: str) -> NfregexService:
        """Get a single nfregex service by id."""
        return await client.get_nfregex_service(service_id)

    @mcp.tool()
    async def add_nfregex_service(
        name: str,
        port: int,
        proto: Protocol,
        ip_int: str,
        fail_open: bool = False,
    ) -> dict[str, Any]:
        """Register a new nfregex service.

        `proto` must be 'tcp' or 'udp'. `ip_int` is the bind interface
        (IPv4/IPv6 literal, '0.0.0.0' for all). `fail_open=True` means traffic
        flows when the regex engine cannot start.
        """
        return await client.add_nfregex_service(
            name=name, port=port,
            proto=proto.value if isinstance(proto, Protocol) else proto,
            ip_int=ip_int, fail_open=fail_open,
        )

    @mcp.tool()
    async def start_nfregex_service(service_id: str) -> dict[str, Any]:
        """Start the nfregex engine for this service."""
        return await client.start_nfregex_service(service_id)

    @mcp.tool()
    async def stop_nfregex_service(service_id: str) -> dict[str, Any]:
        """Stop the nfregex engine for this service (traffic flows through unfiltered)."""
        return await client.stop_nfregex_service(service_id)

    @mcp.tool()
    async def delete_nfregex_service(service_id: str) -> dict[str, Any]:
        """Delete a service and all its regexes."""
        return await client.delete_nfregex_service(service_id)

    @mcp.tool()
    async def rename_nfregex_service(service_id: str, name: str) -> dict[str, Any]:
        """Rename a service."""
        return await client.rename_nfregex_service(service_id, name)

    @mcp.tool()
    async def update_nfregex_service_settings(
        service_id: str,
        port: int | None = None,
        proto: Protocol | None = None,
        ip_int: str | None = None,
        fail_open: bool | None = None,
    ) -> dict[str, Any]:
        """Change service settings (causes a restart). Only provided fields are updated."""
        return await client.update_nfregex_service_settings(
            service_id,
            port=port,
            proto=proto.value if isinstance(proto, Protocol) else proto,
            ip_int=ip_int,
            fail_open=fail_open,
        )

    @mcp.tool()
    async def list_regexes(service_id: str) -> list[RegexModel]:
        """List regexes attached to a service. The `regex` field is plain text."""
        return await client.list_regexes(service_id)

    @mcp.tool()
    async def get_regex(regex_id: int) -> RegexModel:
        """Get a single regex by numeric id."""
        return await client.get_regex(regex_id)

    @mcp.tool()
    async def add_regex(
        service_id: str,
        regex: str,
        mode: RegexMode,
        is_case_sensitive: bool,
        active: bool = True,
    ) -> dict[str, Any]:
        """Add a PCRE2 regex to a service.

        `regex` is plain text (the client base64-encodes for the wire).
        `mode`: 'C' = client→server only, 'S' = server→client only, 'B' = both.
        """
        return await client.add_regex(
            service_id=service_id, regex=regex,
            mode=mode.value if isinstance(mode, RegexMode) else mode,
            is_case_sensitive=is_case_sensitive, active=active,
        )

    @mcp.tool()
    async def enable_regex(regex_id: int) -> dict[str, Any]:
        """Enable a previously-disabled regex without deleting it."""
        return await client.enable_regex(regex_id)

    @mcp.tool()
    async def disable_regex(regex_id: int) -> dict[str, Any]:
        """Disable a regex (kept in DB, not applied)."""
        return await client.disable_regex(regex_id)

    @mcp.tool()
    async def delete_regex(regex_id: int) -> dict[str, Any]:
        """Permanently delete a regex."""
        return await client.delete_regex(regex_id)

    @mcp.tool()
    async def get_nfregex_metrics() -> str:
        """Prometheus-format metrics for the nfregex module (blocked_packets, active)."""
        return await client.get_nfregex_metrics()
```

- [ ] **Step 4: Wire into `tools/__init__.py`**

```python
"""Tool registration for MCP server."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.tools import nfregex, system


def register_all(mcp: FastMCP, client: FiregexClient) -> None:
    system.register(mcp, client)
    nfregex.register(mcp, client)
```

- [ ] **Step 5: Run — should pass**

```bash
uv run pytest tests/test_tools.py -v
```
Expected: 9 passed.

- [ ] **Step 6: Commit**

```bash
git add src/firegex_mcp/tools/nfregex.py src/firegex_mcp/tools/__init__.py tests/test_tools.py
git commit -m "feat(tools): nfregex services + regex CRUD + metrics"
```

---

## Task 15: Tools — nfproxy (incl. set_pyfilter_code_from_file)

**Files:**
- Create: `src/firegex_mcp/tools/nfproxy.py`
- Modify: `src/firegex_mcp/tools/__init__.py`
- Modify: `tests/test_tools.py`

- [ ] **Step 1: Append failing tests**

```python
import pathlib


# ---------- nfproxy ----------


@pytest.mark.asyncio
async def test_nfproxy_services_listed(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfproxy import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_nfproxy_services")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/nfproxy/services").mock(return_value=httpx.Response(
            200, json=[{
                "service_id": "abc", "status": "active", "port": 80,
                "name": "http", "proto": "http", "ip_int": "0.0.0.0",
                "n_filters": 0, "edited_packets": 0, "blocked_packets": 0,
                "fail_open": True,
            }]))
        svcs = await fn()
        assert svcs[0].port == 80


@pytest.mark.asyncio
async def test_set_pyfilter_code_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfproxy import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_pyfilter_code")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.put("/api/nfproxy/services/abc/code").mock(
            return_value=httpx.Response(200, json={"status": "ok"}))
        await fn(service_id="abc", code="print('x')")
        body = route.calls[0].request.read().decode()
        assert '"code":"print(\'x\')"' in body


@pytest.mark.asyncio
async def test_set_pyfilter_code_from_file_tool(
    client: FiregexClient, tmp_path: pathlib.Path,
) -> None:
    from firegex_mcp.tools.nfproxy import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_pyfilter_code_from_file")

    f = tmp_path / "filter.py"
    f.write_text("from firegex.nfproxy import pyfilter\n", encoding="utf-8")

    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.put("/api/nfproxy/services/abc/code").mock(
            return_value=httpx.Response(200, json={"status": "ok"}))
        await fn(service_id="abc", path=str(f))
        body = route.calls[0].request.read().decode()
        assert "from firegex.nfproxy" in body


@pytest.mark.asyncio
async def test_set_pyfilter_code_from_file_missing(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfproxy import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_pyfilter_code_from_file")
    with pytest.raises(FileNotFoundError):
        await fn(service_id="abc", path="/nonexistent/filter.py")


@pytest.mark.asyncio
async def test_set_pyfilter_code_from_file_too_large(
    client: FiregexClient, tmp_path: pathlib.Path,
) -> None:
    from firegex_mcp.tools.nfproxy import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_pyfilter_code_from_file")
    f = tmp_path / "big.py"
    f.write_bytes(b"x" * (1024 * 1024 + 1))  # 1 MiB + 1
    with pytest.raises(ValueError, match="too large"):
        await fn(service_id="abc", path=str(f))


@pytest.mark.asyncio
async def test_pyfilter_enable_disable_tools(client: FiregexClient) -> None:
    from firegex_mcp.tools.nfproxy import register
    mcp = _mcp()
    register(mcp, client)
    en_fn = _tool_fn(mcp, "enable_pyfilter")
    dis_fn = _tool_fn(mcp, "disable_pyfilter")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        en = mock.post("/api/nfproxy/services/abc/pyfilters/f/enable").mock(
            return_value=httpx.Response(200, json={"status": "ok"}))
        dis = mock.post("/api/nfproxy/services/abc/pyfilters/f/disable").mock(
            return_value=httpx.Response(200, json={"status": "ok"}))
        await en_fn(service_id="abc", filter_name="f")
        await dis_fn(service_id="abc", filter_name="f")
        assert en.called and dis.called
```

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_tools.py -v
```

- [ ] **Step 3: Implement `src/firegex_mcp/tools/nfproxy.py`**

```python
"""MCP tools for Firegex nfproxy (Python-pluggable inline proxy)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.models import NfproxyProtocol, NfproxyService, PyFilterModel

_PYFILTER_MAX_BYTES = 1024 * 1024  # 1 MiB


def register(mcp: FastMCP, client: FiregexClient) -> None:
    @mcp.tool()
    async def list_nfproxy_services() -> list[NfproxyService]:
        """List nfproxy services (Python-pluggable inline proxy for TCP/HTTP)."""
        return await client.list_nfproxy_services()

    @mcp.tool()
    async def get_nfproxy_service(service_id: str) -> NfproxyService:
        """Get a single nfproxy service by id."""
        return await client.get_nfproxy_service(service_id)

    @mcp.tool()
    async def add_nfproxy_service(
        name: str,
        port: int,
        proto: NfproxyProtocol,
        ip_int: str,
        fail_open: bool = True,
    ) -> dict[str, Any]:
        """Register a new nfproxy service. `proto` is 'tcp' or 'http'."""
        return await client.add_nfproxy_service(
            name=name, port=port,
            proto=proto.value if isinstance(proto, NfproxyProtocol) else proto,
            ip_int=ip_int, fail_open=fail_open,
        )

    @mcp.tool()
    async def start_nfproxy_service(service_id: str) -> dict[str, Any]:
        """Start the nfproxy engine."""
        return await client.start_nfproxy_service(service_id)

    @mcp.tool()
    async def stop_nfproxy_service(service_id: str) -> dict[str, Any]:
        """Stop the nfproxy engine."""
        return await client.stop_nfproxy_service(service_id)

    @mcp.tool()
    async def delete_nfproxy_service(service_id: str) -> dict[str, Any]:
        """Delete a service and its filter code."""
        return await client.delete_nfproxy_service(service_id)

    @mcp.tool()
    async def rename_nfproxy_service(service_id: str, name: str) -> dict[str, Any]:
        """Rename a service."""
        return await client.rename_nfproxy_service(service_id, name)

    @mcp.tool()
    async def update_nfproxy_service_settings(
        service_id: str,
        port: int | None = None,
        ip_int: str | None = None,
        fail_open: bool | None = None,
    ) -> dict[str, Any]:
        """Change settings of an existing nfproxy service (causes restart)."""
        return await client.update_nfproxy_service_settings(
            service_id, port=port, ip_int=ip_int, fail_open=fail_open,
        )

    @mcp.tool()
    async def list_pyfilters(service_id: str) -> list[PyFilterModel]:
        """List Python filters discovered in the service code."""
        return await client.list_pyfilters(service_id)

    @mcp.tool()
    async def enable_pyfilter(service_id: str, filter_name: str) -> dict[str, Any]:
        """Enable a single pyfilter by name."""
        return await client.enable_pyfilter(service_id, filter_name)

    @mcp.tool()
    async def disable_pyfilter(service_id: str, filter_name: str) -> dict[str, Any]:
        """Disable a single pyfilter by name."""
        return await client.disable_pyfilter(service_id, filter_name)

    @mcp.tool()
    async def get_pyfilter_code(service_id: str) -> str:
        """Read the current Python filter source for a service (empty string if unset)."""
        return await client.get_pyfilter_code(service_id)

    @mcp.tool()
    async def set_pyfilter_code(service_id: str, code: str) -> dict[str, Any]:
        """Replace the Python filter source for a service.

        The code must import `pyfilter` from `firegex.nfproxy` and decorate one
        or more handlers. Firegex compiles the code on the server side and
        returns 400 on syntax/import errors.
        """
        return await client.set_pyfilter_code(service_id, code)

    @mcp.tool()
    async def set_pyfilter_code_from_file(service_id: str, path: str) -> dict[str, Any]:
        """Load Python filter code from a local file and push it to Firegex.

        The path is read on the machine running the MCP server. UTF-8 only.
        Files larger than 1 MiB are rejected.
        """
        p = Path(path).expanduser().resolve()
        if not p.is_file():
            raise FileNotFoundError(f"No such file: {p}")
        size = p.stat().st_size
        if size > _PYFILTER_MAX_BYTES:
            raise ValueError(
                f"File {p} is too large ({size} bytes; limit {_PYFILTER_MAX_BYTES})."
            )
        code = p.read_text(encoding="utf-8")
        return await client.set_pyfilter_code(service_id, code)
```

- [ ] **Step 4: Wire into `tools/__init__.py`**

```python
"""Tool registration for MCP server."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.tools import nfproxy, nfregex, system


def register_all(mcp: FastMCP, client: FiregexClient) -> None:
    system.register(mcp, client)
    nfregex.register(mcp, client)
    nfproxy.register(mcp, client)
```

- [ ] **Step 5: Run — should pass**

```bash
uv run pytest tests/test_tools.py -v
```
Expected: 15 passed.

- [ ] **Step 6: Commit**

```bash
git add src/firegex_mcp/tools/nfproxy.py src/firegex_mcp/tools/__init__.py tests/test_tools.py
git commit -m "feat(tools): nfproxy services + pyfilters + code I/O"
```

---

## Task 16: Tools — firewall

**Files:**
- Create: `src/firegex_mcp/tools/firewall.py`
- Modify: `src/firegex_mcp/tools/__init__.py`
- Modify: `tests/test_tools.py`

- [ ] **Step 1: Append failing tests**

```python
# ---------- firewall ----------


@pytest.mark.asyncio
async def test_list_firewall_rules_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.firewall import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_firewall_rules")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/firewall/rules").mock(return_value=httpx.Response(
            200, json={"rules": [], "policy": "drop", "enabled": False}))
        info = await fn()
        assert info.policy.value == "drop"
        assert info.enabled is False


@pytest.mark.asyncio
async def test_enable_disable_firewall_tools(client: FiregexClient) -> None:
    from firegex_mcp.tools.firewall import register
    mcp = _mcp()
    register(mcp, client)
    en_fn = _tool_fn(mcp, "enable_firewall")
    dis_fn = _tool_fn(mcp, "disable_firewall")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        en = mock.post("/api/firewall/enable").mock(return_value=httpx.Response(
            200, json={"status": "ok"}))
        dis = mock.post("/api/firewall/disable").mock(return_value=httpx.Response(
            200, json={"status": "ok"}))
        await en_fn()
        await dis_fn()
        assert en.called and dis.called


@pytest.mark.asyncio
async def test_replace_firewall_rules_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.firewall import register
    from firegex_mcp.models import FwAction, FwMode, FwProto, FwTable, RuleModel
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "replace_firewall_rules")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.post("/api/firewall/rules").mock(return_value=httpx.Response(
            200, json={"status": "ok"}))
        rule = RuleModel(
            active=True, name="drop-all", proto=FwProto.ANY, table=FwTable.FILTER,
            src="0.0.0.0/0", dst="0.0.0.0/0",
            port_src_from=1, port_src_to=65535,
            port_dst_from=1, port_dst_to=65535,
            action=FwAction.DROP, mode=FwMode.IN,
        )
        await fn(policy=FwAction.ACCEPT, rules=[rule])
        body = route.calls[0].request.read().decode()
        assert '"policy":"accept"' in body
        assert '"name":"drop-all"' in body


@pytest.mark.asyncio
async def test_set_firewall_settings_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.firewall import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_firewall_settings")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.put("/api/firewall/settings").mock(return_value=httpx.Response(
            200, json={"status": "ok"}))
        await fn(
            keep_rules=True, allow_loopback=True, allow_established=True,
            allow_icmp=True, multicast_dns=False, allow_upnp=False,
            drop_invalid=True, allow_dhcp=False,
        )
        body = route.calls[0].request.read().decode()
        assert '"keep_rules":true' in body
        assert '"allow_dhcp":false' in body
```

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_tools.py -v
```

- [ ] **Step 3: Implement `src/firegex_mcp/tools/firewall.py`**

```python
"""MCP tools for Firegex firewall (nftables ruleset)."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.models import FirewallSettings, FwAction, RuleInfo, RuleModel


def register(mcp: FastMCP, client: FiregexClient) -> None:
    @mcp.tool()
    async def get_firewall_settings() -> FirewallSettings:
        """Read the firewall meta-settings (loopback, established, ICMP, mDNS, ...)."""
        return await client.get_firewall_settings()

    @mcp.tool()
    async def set_firewall_settings(
        keep_rules: bool,
        allow_loopback: bool,
        allow_established: bool,
        allow_icmp: bool,
        multicast_dns: bool,
        allow_upnp: bool,
        drop_invalid: bool,
        allow_dhcp: bool,
    ) -> dict[str, Any]:
        """Replace the firewall settings. All fields are required (no partial update)."""
        s = FirewallSettings(
            keep_rules=keep_rules,
            allow_loopback=allow_loopback,
            allow_established=allow_established,
            allow_icmp=allow_icmp,
            multicast_dns=multicast_dns,
            allow_upnp=allow_upnp,
            drop_invalid=drop_invalid,
            allow_dhcp=allow_dhcp,
        )
        return await client.set_firewall_settings(s)

    @mcp.tool()
    async def enable_firewall() -> dict[str, Any]:
        """Activate the nftables firewall ruleset."""
        return await client.enable_firewall()

    @mcp.tool()
    async def disable_firewall() -> dict[str, Any]:
        """Deactivate the nftables firewall ruleset (all rules unloaded)."""
        return await client.disable_firewall()

    @mcp.tool()
    async def list_firewall_rules() -> RuleInfo:
        """Return current rules, policy ('accept'/'drop'/'reject'), and enabled state."""
        return await client.list_firewall_rules()

    @mcp.tool()
    async def replace_firewall_rules(
        policy: FwAction,
        rules: list[RuleModel],
    ) -> dict[str, Any]:
        """Atomically replace the entire rule list.

        Firegex performs a `DELETE FROM rules; INSERT ...` transaction — there is
        no per-rule CRUD. Read with `list_firewall_rules`, mutate, then write back.
        """
        return await client.replace_firewall_rules(policy=policy, rules=rules)
```

- [ ] **Step 4: Wire into `tools/__init__.py`**

```python
"""Tool registration for MCP server."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.tools import firewall, nfproxy, nfregex, system


def register_all(mcp: FastMCP, client: FiregexClient) -> None:
    system.register(mcp, client)
    nfregex.register(mcp, client)
    nfproxy.register(mcp, client)
    firewall.register(mcp, client)
```

- [ ] **Step 5: Run — should pass**

```bash
uv run pytest tests/test_tools.py -v
```
Expected: 19 passed.

- [ ] **Step 6: Commit**

```bash
git add src/firegex_mcp/tools/firewall.py src/firegex_mcp/tools/__init__.py tests/test_tools.py
git commit -m "feat(tools): firewall settings, enable/disable, atomic rule replace"
```

---

## Task 17: Tools — porthijack

**Files:**
- Create: `src/firegex_mcp/tools/porthijack.py`
- Modify: `src/firegex_mcp/tools/__init__.py`
- Modify: `tests/test_tools.py`

- [ ] **Step 1: Append failing tests**

```python
# ---------- porthijack ----------


@pytest.mark.asyncio
async def test_phj_services_listed(client: FiregexClient) -> None:
    from firegex_mcp.tools.porthijack import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_phj_services")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        mock.get("/api/porthijack/services").mock(return_value=httpx.Response(
            200, json=[{
                "service_id": "abc", "active": True, "public_port": 22,
                "proxy_port": 2222, "name": "ssh", "proto": "tcp",
                "ip_src": "0.0.0.0", "ip_dst": "127.0.0.1",
            }]))
        svcs = await fn()
        assert svcs[0].public_port == 22


@pytest.mark.asyncio
async def test_add_phj_service_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.porthijack import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "add_phj_service")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.post("/api/porthijack/services").mock(return_value=httpx.Response(
            200, json={"status": "ok", "service_id": "abc"}))
        await fn(
            name="ssh", public_port=22, proxy_port=2222, proto="tcp",
            ip_src="0.0.0.0", ip_dst="127.0.0.1",
        )
        body = route.calls[0].request.read().decode()
        assert '"public_port":22' in body
        assert '"ip_dst":"127.0.0.1"' in body


@pytest.mark.asyncio
async def test_change_phj_destination_tool(client: FiregexClient) -> None:
    from firegex_mcp.tools.porthijack import register
    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "change_phj_destination")
    with respx.mock(base_url="http://localhost:4444") as mock:
        await _logged_in(mock)
        route = mock.put("/api/porthijack/services/abc/change-destination").mock(
            return_value=httpx.Response(200, json={"status": "ok"}))
        await fn(service_id="abc", ip_dst="10.0.0.5", proxy_port=4444)
        body = route.calls[0].request.read().decode()
        assert '"ip_dst":"10.0.0.5"' in body
        assert '"proxy_port":4444' in body
```

- [ ] **Step 2: Run — should fail**

```bash
uv run pytest tests/test_tools.py -v
```

- [ ] **Step 3: Implement `src/firegex_mcp/tools/porthijack.py`**

```python
"""MCP tools for Firegex porthijack (port redirection)."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.models import PortHijackService, Protocol


def register(mcp: FastMCP, client: FiregexClient) -> None:
    @mcp.tool()
    async def list_phj_services() -> list[PortHijackService]:
        """List port-hijack rules (each redirects public_port → proxy_port on ip_dst)."""
        return await client.list_phj_services()

    @mcp.tool()
    async def get_phj_service(service_id: str) -> PortHijackService:
        """Get a single porthijack rule."""
        return await client.get_phj_service(service_id)

    @mcp.tool()
    async def add_phj_service(
        name: str,
        public_port: int,
        proxy_port: int,
        proto: Protocol,
        ip_src: str,
        ip_dst: str,
    ) -> dict[str, Any]:
        """Add a porthijack rule.

        `ip_src` is the inbound bind interface; `ip_dst` is the new destination.
        `public_port` is what clients connect to; traffic is rewritten to
        `ip_dst:proxy_port`. Use this to plug your own proxy in front of a service.
        """
        return await client.add_phj_service(
            name=name, public_port=public_port, proxy_port=proxy_port,
            proto=proto.value if isinstance(proto, Protocol) else proto,
            ip_src=ip_src, ip_dst=ip_dst,
        )

    @mcp.tool()
    async def start_phj_service(service_id: str) -> dict[str, Any]:
        """Activate a porthijack rule."""
        return await client.start_phj_service(service_id)

    @mcp.tool()
    async def stop_phj_service(service_id: str) -> dict[str, Any]:
        """Deactivate a porthijack rule (traffic is no longer redirected)."""
        return await client.stop_phj_service(service_id)

    @mcp.tool()
    async def delete_phj_service(service_id: str) -> dict[str, Any]:
        """Remove a porthijack rule permanently."""
        return await client.delete_phj_service(service_id)

    @mcp.tool()
    async def rename_phj_service(service_id: str, name: str) -> dict[str, Any]:
        """Rename a porthijack rule."""
        return await client.rename_phj_service(service_id, name)

    @mcp.tool()
    async def change_phj_destination(
        service_id: str,
        ip_dst: str,
        proxy_port: int,
    ) -> dict[str, Any]:
        """Repoint an existing porthijack rule to a new ip_dst:proxy_port."""
        return await client.change_phj_destination(
            service_id, ip_dst=ip_dst, proxy_port=proxy_port,
        )
```

- [ ] **Step 4: Wire into `tools/__init__.py`**

```python
"""Tool registration for MCP server."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.tools import firewall, nfproxy, nfregex, porthijack, system


def register_all(mcp: FastMCP, client: FiregexClient) -> None:
    system.register(mcp, client)
    nfregex.register(mcp, client)
    nfproxy.register(mcp, client)
    firewall.register(mcp, client)
    porthijack.register(mcp, client)
```

- [ ] **Step 5: Verify the full test/lint/type matrix**

```bash
uv run pytest --cov=src/firegex_mcp --cov-report=term-missing
uv run ruff check src tests
uv run mypy src
```
Expected: tests all pass; coverage ≥ 90 % for `src/firegex_mcp/`; ruff clean; mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/firegex_mcp/tools/porthijack.py src/firegex_mcp/tools/__init__.py tests/test_tools.py
git commit -m "feat(tools): porthijack services + change_destination"
```

---

## Task 18: README + CHANGELOG

**Files:**
- Create: `README.md` (overwrites the empty existing file)
- Create: `CHANGELOG.md`

- [ ] **Step 1: Write `README.md`**

```markdown
# firegex-mcp

MCP server that exposes [Firegex](https://github.com/Pwnzer0tt1/firegex) — a CTF regex/proxy firewall — to LLM tooling like Claude Desktop or Claude Code.

## Features

- 49 tools across system, nfregex (kernel-side PCRE2 filter), nfproxy (Python inline proxy), firewall (nftables rules), and porthijack (port redirection).
- Auto-managed JWT lifecycle: log in on first use, transparently re-login on 401 / secret rotation, single `asyncio.Lock` to avoid login storms.
- Plain-text regex on the tool boundary; base64 is handled inside the client.
- Two ways to push nfproxy Python filters: inline `code: str` or local `path: str` (≤ 1 MiB).
- Pure async `httpx` client + pydantic v2 DTOs.
- stdio transport — drop into Claude Desktop or Claude Code as a subprocess.

## Install

```bash
uvx firegex-mcp        # ephemeral, recommended
# or
pip install firegex-mcp
```

## Configure

All settings are env vars with the `FIREGEX_MCP_` prefix:

| Env var | Default | Description |
|---|---|---|
| `FIREGEX_MCP_BASE_URL` | `http://localhost:4444` | Firegex base URL |
| `FIREGEX_MCP_PASSWORD` | (required) | Used at `/api/login` |
| `FIREGEX_MCP_TIMEOUT_SECONDS` | `30` | HTTP request timeout |
| `FIREGEX_MCP_VERIFY_SSL` | `true` | Disable for self-signed HTTPS |
| `FIREGEX_MCP_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |

See [`.env.example`](.env.example) for a starter template.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%AppData%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "firegex": {
      "command": "uvx",
      "args": ["firegex-mcp"],
      "env": {
        "FIREGEX_MCP_BASE_URL": "http://localhost:4444",
        "FIREGEX_MCP_PASSWORD": "..."
      }
    }
  }
}
```

Restart Claude Desktop fully (`Cmd+Q` / tray → Quit), then look for the connector under the `+` menu.

### Claude Code

```bash
claude mcp add firegex uvx firegex-mcp --env FIREGEX_MCP_PASSWORD=...
```

## Tools

Grouped by Firegex module. See the [design spec](docs/superpowers/specs/2026-05-13-firegex-mcp-design.md) for the full catalogue.

- **system** (6): `get_firegex_status`, `set_password`, `change_password`, `list_interfaces`, `reset_firegex`, `login_probe`.
- **nfregex** (15): services CRUD + regex CRUD/toggle + Prometheus metrics.
- **nfproxy** (14): services CRUD + pyfilter toggle + `get_pyfilter_code`, `set_pyfilter_code`, `set_pyfilter_code_from_file`.
- **firewall** (6): `get_firewall_settings`, `set_firewall_settings`, `enable_firewall`, `disable_firewall`, `list_firewall_rules`, `replace_firewall_rules`.
- **porthijack** (8): services CRUD + `rename_phj_service` + `change_phj_destination`.

## Development

```bash
git clone https://github.com/umbra2728/firegex-mcp
cd firegex-mcp
uv sync --dev
uv run pytest
uv run ruff check src tests
uv run mypy src
```

Manual smoke test against a real Firegex instance:

```bash
# in the firegex repo
python3 run.py start --prebuilt
# back here
FIREGEX_MCP_PASSWORD=test uv run mcp dev src/firegex_mcp/server.py
```

This opens the MCP Inspector in your browser; you can call every tool by hand.

## Releasing

This package ships to PyPI via Trusted Publishing. The workflow runs on any `v*.*.*` tag.

1. Bump `version` in `pyproject.toml`.
2. Add a `## [X.Y.Z] - YYYY-MM-DD` section to `CHANGELOG.md`.
3. Commit, tag, push:

```bash
git commit -am "Release vX.Y.Z"
git tag vX.Y.Z
git push --tags
```

One-time setup (not in repo state):

- PyPI → Account settings → Add a pending publisher with repo `umbra2728/firegex-mcp`, workflow `release.yml`, environment `pypi`.
- GitHub → repo → Settings → Environments → create `pypi`.

## License

MIT.
```

- [ ] **Step 2: Write `CHANGELOG.md`**

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release: 49 MCP tools wrapping Firegex's REST API (system + four modules).
- Auto-managed JWT lifecycle (login, retry on 401, asyncio.Lock).
- Plain-text regex on the tool boundary with base64 handled inside the client.
- Dual upload tools for nfproxy Python filters: inline `code: str` and file `path: str`.
- PyPI Trusted Publishing release workflow.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: README and CHANGELOG"
```

---

## Task 19: CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3
        with:
          enable-cache: true

      - name: Set up Python
        run: uv python install ${{ matrix.python-version }}

      - name: Install deps
        run: uv sync --dev

      - name: Lint
        run: uv run ruff check src tests

      - name: Type-check
        run: uv run mypy src

      - name: Test
        run: uv run pytest --cov=src/firegex_mcp --cov-report=term-missing
```

- [ ] **Step 2: Verify all checks pass locally one more time**

```bash
uv run ruff check src tests
uv run mypy src
uv run pytest --cov=src/firegex_mcp --cov-report=term-missing
```
Expected: green across the board.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: GitHub Actions matrix (3.10–3.13) for lint/type/test"
```

---

## Task 20: Release workflow

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Write `.github/workflows/release.yml`**

```yaml
name: Release

on:
  push:
    tags: ["v*.*.*"]

jobs:
  release:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
      contents: write
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3
        with:
          enable-cache: true

      - name: Set up Python
        run: uv python install 3.12

      - name: Install deps
        run: uv sync --dev

      - name: Test
        run: uv run pytest

      - name: Build
        run: uv build

      - name: Publish to PyPI (Trusted Publishing)
        uses: pypa/gh-action-pypi-publish@release/v1

      - name: GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: dist/*
```

- [ ] **Step 2: Verify the package builds cleanly**

```bash
uv build
ls dist/
```
Expected: `firegex_mcp-0.1.0-py3-none-any.whl` and `firegex_mcp-0.1.0.tar.gz` exist. Delete `dist/` afterwards (it's gitignored).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: PyPI trusted-publishing release workflow on v*.*.* tags"
```

---

## Self-review

Run through the spec one more time and confirm every section maps to a task:

- **§3 Architecture / layout** → Tasks 1, 12, 13–17.
- **§4.1 FiregexSettings** → Task 2.
- **§4.2 Client (exceptions + lifecycle + 48 methods)** → Tasks 5, 6 (auth), 7 (system), 8 (nfregex), 9 (nfproxy), 10 (firewall), 11 (porthijack).
- **§4.3 Models + enums** → Tasks 3, 4.
- **§4.4 Tools per module** → Tasks 13–17.
- **§4.5 server.py + lifespan** → Task 12.
- **§4.6 `__main__.py`** → Task 12.
- **§5.1 Normal tool-call flow** → exercised by Task 13–17 integration tests.
- **§5.2 JWT state machine + Lock** → Task 6.
- **§5.3 Regex base64 + pyfilter code (both paths) + reset(delete) + replace_rules** → Tasks 4 (base64), 8 (add_regex), 15 (set_pyfilter_code_from_file), 13 (reset_firegex), 16 (replace_firewall_rules).
- **§6 Error handling table** → Task 5 covers all rows.
- **§7 Testing stack + coverage target ≥ 90 %** → asserted in Task 17 Step 5.
- **§8 Release + CI** → Tasks 19, 20.
- **§9 Tool catalogue (49 tools)** → wired by Tasks 13–17.

No gaps. No placeholders. All file paths absolute.
