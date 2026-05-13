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
