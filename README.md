# FreeIPA MCP Server

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server for FreeIPA identity management. Enables AI assistants like Claude to manage users, groups, hosts, DNS, HBAC rules, sudo rules, and certificates through natural language.

## Requirements

- Python 3.10+
- FreeIPA 4.6.5+ (API version 2.230+)
- Network access to your FreeIPA server

For more information about FreeIPA concepts (HBAC, sudo rules, etc.), see the [FreeIPA Documentation](https://freeipa.readthedocs.io/).

## Installation

```bash
# From source
cd freeipa-mcp
pip install -e .

# Or with uv
uv pip install -e .
```

## Configuration

Set environment variables for your FreeIPA server:

```bash
export FREEIPA_SERVER=ipa.example.com
export FREEIPA_USERNAME=admin
export FREEIPA_PASSWORD=your-password

# Optional settings
export FREEIPA_VERIFY_SSL=true        # default: true
export FREEIPA_CA_CERT_PATH=/etc/ipa/ca.crt  # for custom CA certificates
export FREEIPA_API_VERSION=2.230      # default: 2.230
export FREEIPA_DEFAULT_LIMIT=100      # max results for list operations
export FREEIPA_REQUEST_TIMEOUT=30     # request timeout in seconds
```

Or create a `.env` file:

```bash
cp .env.example .env
# Edit .env with your settings
```

## Usage with Claude Code

Add to your `~/.claude.json`:

```json
{
  "mcpServers": {
    "freeipa": {
      "type": "stdio",
      "command": "freeipa-mcp",
      "env": {
        "FREEIPA_SERVER": "ipa.example.com",
        "FREEIPA_USERNAME": "admin",
        "FREEIPA_PASSWORD": "your-password"
      }
    }
  }
}
```

> **Security**: Avoid committing credentials to version control. Consider using environment variables from your shell profile or a secrets manager instead of hardcoding passwords in configuration files.

Once published to PyPI, you can also use uvx (no local installation needed):

```json
{
  "mcpServers": {
    "freeipa": {
      "type": "stdio",
      "command": "uvx",
      "args": ["freeipa-mcp"],
      "env": {
        "FREEIPA_SERVER": "ipa.example.com",
        "FREEIPA_USERNAME": "admin",
        "FREEIPA_PASSWORD": "your-password"
      }
    }
  }
}
```

## Available Tools

### User Management
| Tool | Description |
|------|-------------|
| `user_find` | Search users with filters |
| `user_show` | Get user details |
| `user_add` | Create a new user |
| `user_mod` | Modify user attributes |
| `user_del` | Delete a user |
| `user_enable` | Enable user account |
| `user_disable` | Disable user account |
| `user_unlock` | Unlock locked account |

### Group Management
| Tool | Description |
|------|-------------|
| `group_find` | Search groups |
| `group_show` | Get group details |
| `group_add` | Create a new group |
| `group_mod` | Modify group |
| `group_del` | Delete a group |
| `group_add_member` | Add members to group |
| `group_remove_member` | Remove members |

### Host Management
| Tool | Description |
|------|-------------|
| `host_find` | Search hosts |
| `host_show` | Get host details |
| `host_add` | Register a new host |
| `host_mod` | Modify host |
| `host_del` | Delete a host |
| `host_disable` | Disable host |

### DNS Management
| Tool | Description |
|------|-------------|
| `dnszone_find` | List DNS zones |
| `dnszone_show` | Get zone details |
| `dnszone_add` | Create DNS zone |
| `dnsrecord_find` | Search DNS records |
| `dnsrecord_add` | Add DNS record |
| `dnsrecord_del` | Delete DNS record |

### HBAC Rules
| Tool | Description |
|------|-------------|
| `hbacrule_find` | Search HBAC rules |
| `hbacrule_show` | Get rule details |
| `hbacrule_add` | Create HBAC rule |
| `hbacrule_enable` | Enable rule |
| `hbacrule_disable` | Disable rule |
| `hbacrule_add_user` | Add users to rule |
| `hbacrule_add_host` | Add hosts to rule |

### Sudo Rules
| Tool | Description |
|------|-------------|
| `sudorule_find` | Search sudo rules |
| `sudorule_show` | Get rule details |
| `sudorule_add` | Create sudo rule |
| `sudorule_enable` | Enable rule |
| `sudorule_disable` | Disable rule |
| `sudorule_add_user` | Add users to rule |
| `sudorule_add_host` | Add hosts to rule |
| `sudorule_add_allow_command` | Add allowed commands |
| `sudorule_add_option` | Add sudo options |

### Certificates
| Tool | Description |
|------|-------------|
| `cert_find` | Search certificates |
| `user_add_cert` | Add cert to user |
| `host_add_cert` | Add cert to host |

## Example Conversations

**Create a user:**
> "Create a new user 'jsmith' with name John Smith and email jsmith@example.com"

**Add user to group:**
> "Add user jsmith to the developers group"

**Create an HBAC rule:**
> "Create an HBAC rule that allows the developers group to access all hosts via SSH"

**Search for expiring certificates:**
> "Find all certificates expiring before 2026-12-31"

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run linting
ruff check src/

# Run type checking
mypy src/

# Run tests
pytest
```

## Testing with MCP Inspector

```bash
# Build and test
pip install -e .
npx @modelcontextprotocol/inspector

# In inspector, connect via stdio to: freeipa-mcp
```

## Troubleshooting

**SSL Certificate Errors**
If your FreeIPA server uses a self-signed certificate:
```bash
# Option 1: Provide the CA certificate path
export FREEIPA_CA_CERT_PATH=/etc/ipa/ca.crt

# Option 2: Disable SSL verification (not recommended for production)
export FREEIPA_VERIFY_SSL=false
```

**Authentication Failures**
- Verify your username and password are correct
- Ensure the user has sufficient privileges in FreeIPA
- Check that the account is not locked or expired

**Connection Issues**
- Verify network connectivity to the FreeIPA server: `ping ipa.example.com`
- Ensure the FreeIPA API is accessible: `curl -k https://ipa.example.com/ipa/json`
- Check firewall rules allow HTTPS (port 443) traffic

**Timeout Errors**
For slow networks or large queries, increase the timeout:
```bash
export FREEIPA_REQUEST_TIMEOUT=60
```

## License

MIT
