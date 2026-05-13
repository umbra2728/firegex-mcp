"""CLI entrypoint: `firegex-mcp` and `python -m firegex_mcp`."""

from __future__ import annotations

import sys

from firegex_mcp.server import run


def main() -> None:
    try:
        run()
    except Exception as e:  # noqa: BLE001 — top-level fence
        print(f"firegex-mcp failed to start: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
