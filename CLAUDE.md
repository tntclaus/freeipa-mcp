# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FreeIPA MCP Server - A Model Context Protocol (MCP) server that exposes FreeIPA identity management operations as MCP tools. This enables AI assistants to manage users, groups, hosts, DNS, HBAC rules, sudo rules, and certificates through the FreeIPA API.

## Development Commands

```bash
# Install in development mode
pip install -e ".[dev]"

# Run linting
ruff check src/

# Run type checking
mypy src/

# Run all tests
pytest

# Run tests with coverage
pytest --cov=src/freeipa_mcp --cov-report=html

# Run a single test file
pytest tests/test_users.py

# Run a single test
pytest tests/test_users.py::test_user_find_success -v

# Test with MCP Inspector
pip install -e .
npx @modelcontextprotocol/inspector
# In inspector, connect via stdio to: freeipa-mcp
```

## Architecture

### Core Components

- **`src/freeipa_mcp/server.py`**: FastMCP server entry point. Defines all MCP tools as decorated functions that delegate to tool modules. The `mcp` instance is the FastMCP server object.

- **`src/freeipa_mcp/client.py`**: FreeIPA client wrapper with connection management. Key classes:
  - `FreeIPAClient`: Main client class wrapping `python-freeipa`'s `ClientMeta`
  - `get_client()`: Returns singleton client instance
  - Custom exceptions: `FreeIPAClientError`, `AuthenticationError`, `ObjectNotFoundError`, `ObjectExistsError`

- **`src/freeipa_mcp/config.py`**: Pydantic Settings-based configuration. `FreeIPASettings` loads from environment variables with `FREEIPA_` prefix.

### Tool Modules (`src/freeipa_mcp/tools/`)

Each module implements operations for a FreeIPA domain:
- `users.py` - User CRUD, enable/disable/unlock
- `groups.py` - Group CRUD, membership management
- `hosts.py` - Host registration and management
- `dns.py` - DNS zones and records
- `hbac.py` - Host-Based Access Control rules
- `sudo.py` - Sudo rules
- `certs.py` - Certificate operations

**Pattern**: Each tool function calls `get_client()` to get the singleton FreeIPA client, builds kwargs from parameters, executes via `client.execute()` or convenience methods, and returns a standardized response dict with `success`, `count`/`user`/etc., and `error` on failure.

### Testing

Tests use mocked FreeIPA client (`mock_get_client` fixture). No real FreeIPA connection required. Test fixtures in `tests/conftest.py` provide sample API response data structures matching FreeIPA's format (lists for single values, etc.).

## Configuration

Required environment variables (or `.env` file):
```bash
FREEIPA_SERVER=ipa.example.com    # hostname only, no https://
FREEIPA_USERNAME=admin
FREEIPA_PASSWORD=secret
```

Optional:
```bash
FREEIPA_VERIFY_SSL=true           # default: true
FREEIPA_API_VERSION=2.230         # minimum for FreeIPA 4.6.5+
FREEIPA_DEFAULT_LIMIT=100         # list operation limit
FREEIPA_REQUEST_TIMEOUT=30        # seconds
```
