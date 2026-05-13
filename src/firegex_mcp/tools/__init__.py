"""Tool registration for MCP server.

Each submodule exposes a `register(mcp, client)` function that attaches its tools
to the FastMCP instance using the shared FiregexClient.
"""

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
