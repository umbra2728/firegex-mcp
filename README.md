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
