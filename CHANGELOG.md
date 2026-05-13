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
