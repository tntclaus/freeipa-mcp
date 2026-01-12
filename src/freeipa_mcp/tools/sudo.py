"""Sudo rule management tools for FreeIPA MCP Server."""

import logging
from typing import Any, Optional

from ..client import (
    FreeIPAClientError,
    ObjectExistsError,
    ObjectNotFoundError,
    get_client,
)
from ..config import get_settings

logger = logging.getLogger(__name__)


def _format_sudorule(rule: dict[str, Any]) -> dict[str, Any]:
    """Format a FreeIPA sudo rule record for clean output."""
    def extract(val: Any) -> Any:
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val

    return {
        "cn": extract(rule.get("cn")),
        "description": extract(rule.get("description")),
        "ipaenabledflag": extract(rule.get("ipaenabledflag", True)),
        "usercategory": extract(rule.get("usercategory")),
        "hostcategory": extract(rule.get("hostcategory")),
        "cmdcategory": extract(rule.get("cmdcategory")),
        "ipasudorunasusercategory": extract(rule.get("ipasudorunasusercategory")),
        "ipasudorunasgroupcategory": extract(rule.get("ipasudorunasgroupcategory")),
        "memberuser_user": rule.get("memberuser_user", []),
        "memberuser_group": rule.get("memberuser_group", []),
        "memberhost_host": rule.get("memberhost_host", []),
        "memberhost_hostgroup": rule.get("memberhost_hostgroup", []),
        "memberallowcmd_sudocmd": rule.get("memberallowcmd_sudocmd", []),
        "memberallowcmd_sudocmdgroup": rule.get("memberallowcmd_sudocmdgroup", []),
        "memberdenycmd_sudocmd": rule.get("memberdenycmd_sudocmd", []),
        "memberdenycmd_sudocmdgroup": rule.get("memberdenycmd_sudocmdgroup", []),
        "ipasudoopt": rule.get("ipasudoopt", []),
        "ipasudorunasuser_user": rule.get("ipasudorunasuser_user", []),
        "ipasudorunasgroup_group": rule.get("ipasudorunasgroup_group", []),
        "sudoorder": extract(rule.get("sudoorder", 0)),
    }


def sudorule_find(
    cn: Optional[str] = None,
    description: Optional[str] = None,
    enabled: Optional[bool] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for sudo rules in FreeIPA.

    Args:
        cn: Rule name pattern (supports wildcards *)
        description: Description pattern to search
        enabled: Filter by enabled/disabled status
        limit: Maximum number of results to return

    Returns:
        Dictionary containing:
        - count: Number of rules found
        - rules: List of sudo rule records
    """
    client = get_client()
    settings = get_settings()

    kwargs: dict[str, Any] = {
        "sizelimit": limit or settings.default_limit,
        "all": True,
    }

    if cn:
        kwargs["cn"] = cn
    if description:
        kwargs["description"] = description
    if enabled is not None:
        kwargs["ipaenabledflag"] = enabled

    try:
        result = client.execute("sudorule_find", **kwargs)
        rules = [_format_sudorule(r) for r in result.get("result", [])]

        return {
            "success": True,
            "count": result.get("count", len(rules)),
            "rules": rules,
        }
    except FreeIPAClientError as e:
        logger.error(f"sudorule_find failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def sudorule_show(cn: str) -> dict[str, Any]:
    """Get detailed information about a specific sudo rule.

    Args:
        cn: Rule name

    Returns:
        Dictionary containing rule details or error information
    """
    client = get_client()

    try:
        result = client.execute("sudorule_show", cn, all=True)
        rule = result.get("result", {})

        return {
            "success": True,
            "rule": _format_sudorule(rule),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Sudo rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"sudorule_show failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def sudorule_add(
    cn: str,
    description: Optional[str] = None,
    usercategory: Optional[str] = None,
    hostcategory: Optional[str] = None,
    cmdcategory: Optional[str] = None,
    runasusercategory: Optional[str] = None,
    runasgroupcategory: Optional[str] = None,
    sudoorder: Optional[int] = None,
) -> dict[str, Any]:
    """Create a new sudo rule in FreeIPA.

    Args:
        cn: Rule name
        description: Rule description
        usercategory: User category ('all' to apply to all users)
        hostcategory: Host category ('all' to apply to all hosts)
        cmdcategory: Command category ('all' to allow all commands)
        runasusercategory: Run-as user category ('all' for any user)
        runasgroupcategory: Run-as group category ('all' for any group)
        sudoorder: Sudo order (priority, lower numbers run first)

    Returns:
        Dictionary containing created rule details or error information

    Note:
        New rules are enabled by default.
        If you set a category to 'all', you cannot add specific members of that type.
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if description:
        kwargs["description"] = description
    if usercategory:
        kwargs["usercategory"] = usercategory
    if hostcategory:
        kwargs["hostcategory"] = hostcategory
    if cmdcategory:
        kwargs["cmdcategory"] = cmdcategory
    if runasusercategory:
        kwargs["ipasudorunasusercategory"] = runasusercategory
    if runasgroupcategory:
        kwargs["ipasudorunasgroupcategory"] = runasgroupcategory
    if sudoorder is not None:
        kwargs["sudoorder"] = sudoorder

    try:
        result = client.execute("sudorule_add", cn, **kwargs)
        rule = result.get("result", {})

        return {
            "success": True,
            "message": f"Sudo rule '{cn}' created successfully",
            "rule": _format_sudorule(rule),
        }
    except ObjectExistsError:
        return {"success": False, "error": f"Sudo rule '{cn}' already exists", "code": "DUPLICATE_ENTRY"}
    except FreeIPAClientError as e:
        logger.error(f"sudorule_add failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def sudorule_mod(
    cn: str,
    description: Optional[str] = None,
    usercategory: Optional[str] = None,
    hostcategory: Optional[str] = None,
    cmdcategory: Optional[str] = None,
    sudoorder: Optional[int] = None,
) -> dict[str, Any]:
    """Modify an existing sudo rule.

    Args:
        cn: Rule name to modify
        description: New description
        usercategory: New user category
        hostcategory: New host category
        cmdcategory: New command category
        sudoorder: New sudo order (priority)

    Returns:
        Dictionary containing updated rule details or error information
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if description is not None:
        kwargs["description"] = description
    if usercategory is not None:
        kwargs["usercategory"] = usercategory
    if hostcategory is not None:
        kwargs["hostcategory"] = hostcategory
    if cmdcategory is not None:
        kwargs["cmdcategory"] = cmdcategory
    if sudoorder is not None:
        kwargs["sudoorder"] = sudoorder

    if not kwargs:
        return {"success": False, "error": "No modifications specified", "code": "NO_CHANGES"}

    try:
        result = client.execute("sudorule_mod", cn, **kwargs)
        rule = result.get("result", {})

        return {
            "success": True,
            "message": f"Sudo rule '{cn}' modified successfully",
            "rule": _format_sudorule(rule),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Sudo rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"sudorule_mod failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def sudorule_del(cn: str) -> dict[str, Any]:
    """Delete a sudo rule from FreeIPA.

    Args:
        cn: Rule name to delete

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("sudorule_del", cn)
        return {
            "success": True,
            "message": f"Sudo rule '{cn}' deleted successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Sudo rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"sudorule_del failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def sudorule_enable(cn: str) -> dict[str, Any]:
    """Enable a sudo rule.

    Args:
        cn: Rule name to enable

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("sudorule_enable", cn)
        return {
            "success": True,
            "message": f"Sudo rule '{cn}' enabled successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Sudo rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"sudorule_enable failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def sudorule_disable(cn: str) -> dict[str, Any]:
    """Disable a sudo rule.

    Args:
        cn: Rule name to disable

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("sudorule_disable", cn)
        return {
            "success": True,
            "message": f"Sudo rule '{cn}' disabled successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Sudo rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"sudorule_disable failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def sudorule_add_user(
    cn: str,
    users: Optional[list[str]] = None,
    groups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add users or groups to a sudo rule.

    Args:
        cn: Rule name
        users: List of usernames to add
        groups: List of group names to add

    Returns:
        Dictionary indicating success and any failures
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if users:
        kwargs["user"] = users
    if groups:
        kwargs["group"] = groups

    if not kwargs:
        return {"success": False, "error": "No users or groups specified", "code": "NO_MEMBERS"}

    try:
        result = client.execute("sudorule_add_user", cn, **kwargs)

        response: dict[str, Any] = {
            "success": True,
            "message": f"Users/groups added to sudo rule '{cn}'",
        }

        failed = result.get("failed", {})
        if failed.get("memberuser", {}):
            response["warnings"] = [f"Some members failed: {failed['memberuser']}"]

        return response

    except ObjectNotFoundError:
        return {"success": False, "error": f"Sudo rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        if "category" in str(e).lower():
            return {
                "success": False,
                "error": "Cannot add users when usercategory is 'all'",
                "code": "CATEGORY_CONFLICT"
            }
        logger.error(f"sudorule_add_user failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def sudorule_add_host(
    cn: str,
    hosts: Optional[list[str]] = None,
    hostgroups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add hosts or hostgroups to a sudo rule.

    Args:
        cn: Rule name
        hosts: List of host FQDNs to add
        hostgroups: List of hostgroup names to add

    Returns:
        Dictionary indicating success and any failures
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if hosts:
        kwargs["host"] = hosts
    if hostgroups:
        kwargs["hostgroup"] = hostgroups

    if not kwargs:
        return {"success": False, "error": "No hosts or hostgroups specified", "code": "NO_MEMBERS"}

    try:
        result = client.execute("sudorule_add_host", cn, **kwargs)

        response: dict[str, Any] = {
            "success": True,
            "message": f"Hosts/hostgroups added to sudo rule '{cn}'",
        }

        failed = result.get("failed", {})
        if failed.get("memberhost", {}):
            response["warnings"] = [f"Some members failed: {failed['memberhost']}"]

        return response

    except ObjectNotFoundError:
        return {"success": False, "error": f"Sudo rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        if "category" in str(e).lower():
            return {
                "success": False,
                "error": "Cannot add hosts when hostcategory is 'all'",
                "code": "CATEGORY_CONFLICT"
            }
        logger.error(f"sudorule_add_host failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def sudorule_add_allow_command(
    cn: str,
    sudocmds: Optional[list[str]] = None,
    sudocmdgroups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add allowed commands to a sudo rule.

    Args:
        cn: Rule name
        sudocmds: List of sudo command paths (e.g., '/usr/bin/systemctl')
        sudocmdgroups: List of sudo command group names

    Returns:
        Dictionary indicating success and any failures
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if sudocmds:
        kwargs["sudocmd"] = sudocmds
    if sudocmdgroups:
        kwargs["sudocmdgroup"] = sudocmdgroups

    if not kwargs:
        return {"success": False, "error": "No commands specified", "code": "NO_COMMANDS"}

    try:
        result = client.execute("sudorule_add_allow_command", cn, **kwargs)

        response: dict[str, Any] = {
            "success": True,
            "message": f"Allowed commands added to sudo rule '{cn}'",
        }

        failed = result.get("failed", {})
        if failed.get("memberallowcmd", {}):
            response["warnings"] = [f"Some commands failed: {failed['memberallowcmd']}"]

        return response

    except ObjectNotFoundError:
        return {"success": False, "error": f"Sudo rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        if "category" in str(e).lower():
            return {
                "success": False,
                "error": "Cannot add commands when cmdcategory is 'all'",
                "code": "CATEGORY_CONFLICT"
            }
        logger.error(f"sudorule_add_allow_command failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def sudorule_add_option(cn: str, ipasudoopt: str) -> dict[str, Any]:
    """Add a sudo option to a rule.

    Args:
        cn: Rule name
        ipasudoopt: Sudo option string (e.g., '!authenticate', 'env_keep+=SSH_AUTH_SOCK')

    Returns:
        Dictionary indicating success or error

    Common options:
        - '!authenticate' - Don't require password
        - '!requiretty' - Don't require a TTY
        - 'env_keep+=VAR' - Preserve environment variable
        - 'env_reset' - Reset environment
    """
    client = get_client()

    try:
        client.execute("sudorule_add_option", cn, ipasudoopt=ipasudoopt)
        return {
            "success": True,
            "message": f"Sudo option '{ipasudoopt}' added to rule '{cn}'",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Sudo rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"sudorule_add_option failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def sudorule_add_runasuser(
    cn: str,
    users: Optional[list[str]] = None,
    groups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add run-as users to a sudo rule.

    Specifies which users commands can be run as (sudo -u).

    Args:
        cn: Rule name
        users: List of usernames that commands can be run as
        groups: List of groups that commands can be run as

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if users:
        kwargs["user"] = users
    if groups:
        kwargs["group"] = groups

    if not kwargs:
        return {"success": False, "error": "No run-as users specified", "code": "NO_MEMBERS"}

    try:
        result = client.execute("sudorule_add_runasuser", cn, **kwargs)

        response: dict[str, Any] = {
            "success": True,
            "message": f"Run-as users added to sudo rule '{cn}'",
        }

        return response

    except ObjectNotFoundError:
        return {"success": False, "error": f"Sudo rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"sudorule_add_runasuser failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}
