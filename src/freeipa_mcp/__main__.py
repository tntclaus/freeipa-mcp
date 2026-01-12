#!/usr/bin/env python3
"""Entry point for the FreeIPA MCP Server.

Run with:
    python -m freeipa_mcp

Or after installation:
    freeipa-mcp
"""

from .server import run_server


def main():
    """Main entry point."""
    run_server()


if __name__ == "__main__":
    main()
