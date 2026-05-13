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
            name=name,
            port=port,
            proto=proto.value if isinstance(proto, Protocol) else proto,
            ip_int=ip_int,
            fail_open=fail_open,
        )

    @mcp.tool()
    async def start_nfregex_service(service_id: str) -> dict[str, Any]:
        """Start the nfregex engine for this service."""
        return await client.start_nfregex_service(service_id)

    @mcp.tool()
    async def stop_nfregex_service(service_id: str) -> dict[str, Any]:
        """Stop the nfregex engine (traffic flows through unfiltered)."""
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
        """Change service settings (causes restart). Only provided fields are updated."""
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
            service_id=service_id,
            regex=regex,
            mode=mode.value if isinstance(mode, RegexMode) else mode,
            is_case_sensitive=is_case_sensitive,
            active=active,
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
