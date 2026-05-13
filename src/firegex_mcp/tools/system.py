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
