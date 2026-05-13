"""Tool registration for MCP server.

Each submodule exposes a `register(mcp, client)` function that attaches its tools
to the FastMCP instance using the shared FiregexClient.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from firegex_mcp.client import FiregexClient


def register_all(mcp: FastMCP, client: FiregexClient) -> None:
    # Submodules are wired in subsequent tasks.
    pass
