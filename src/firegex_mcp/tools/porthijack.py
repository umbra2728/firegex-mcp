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
            name=name,
            public_port=public_port,
            proxy_port=proxy_port,
            proto=proto.value if isinstance(proto, Protocol) else proto,
            ip_src=ip_src,
            ip_dst=ip_dst,
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
            service_id, ip_dst=ip_dst, proxy_port=proxy_port
        )
