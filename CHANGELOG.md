# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-05-13

### Removed
- `FIREGEX_MCP_VERIFY_SSL` env var. The flag is gone; httpx uses the system trust store. If a use case for custom CA appears, a follow-up can add `ca_bundle: Path`.

### Added
- `LICENSE` file (MIT).
- README "Related" section linking to [`packmate-mcp`](https://github.com/umbra2728/packmate-mcp) and [`ad-ctf-toolkit`](https://github.com/umbra2728/ad-ctf-toolkit).

## [0.1.0] - 2026-05-13

### Added
- Initial release: 49 MCP tools wrapping Firegex's REST API (system + four modules).
- Auto-managed JWT lifecycle (login, retry on 401, asyncio.Lock).
- Plain-text regex on the tool boundary with base64 handled inside the client.
- Dual upload tools for nfproxy Python filters: inline `code: str` and file `path: str`.
- PyPI Trusted Publishing release workflow.
