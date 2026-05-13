"""MCP tools for Firegex nfproxy (Python-pluggable inline proxy)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient
from firegex_mcp.models import NfproxyProtocol, NfproxyService, PyFilterModel

_PYFILTER_MAX_BYTES = 1024 * 1024  # 1 MiB


def _read_local_pyfilter(path: str) -> str:
    """Synchronously read a local pyfilter source. Called via asyncio.to_thread."""
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(f"No such file: {p}")
    size = p.stat().st_size
    if size > _PYFILTER_MAX_BYTES:
        raise ValueError(f"File {p} is too large ({size} bytes; limit {_PYFILTER_MAX_BYTES}).")
    return p.read_text(encoding="utf-8")


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
            name=name,
            port=port,
            proto=proto.value if isinstance(proto, NfproxyProtocol) else proto,
            ip_int=ip_int,
            fail_open=fail_open,
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
            service_id, port=port, ip_int=ip_int, fail_open=fail_open
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
        or more handlers. Firegex compiles the code server-side and returns 400
        on syntax/import errors.
        """
        return await client.set_pyfilter_code(service_id, code)

    @mcp.tool()
    async def set_pyfilter_code_from_file(service_id: str, path: str) -> dict[str, Any]:
        """Load Python filter code from a local file and push it to Firegex.

        The path is read on the machine running the MCP server. UTF-8 only.
        Files larger than 1 MiB are rejected.
        """
        code = await asyncio.to_thread(_read_local_pyfilter, path)
        return await client.set_pyfilter_code(service_id, code)
