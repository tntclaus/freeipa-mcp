"""Group management tools for FreeIPA MCP Server."""

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


def _format_group(group: dict[str, Any]) -> dict[str, Any]:
    """Format a FreeIPA group record for clean output."""
    def extract(val: Any) -> Any:
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val

    return {
        "cn": extract(group.get("cn")),
        "description": extract(group.get("description")),
        "gidnumber": extract(group.get("gidnumber")),
        "member_user": group.get("member_user", []),
        "member_group": group.get("member_group", []),
        "memberof_group": group.get("memberof_group", []),
        "memberindirect_user": group.get("memberindirect_user", []),
        "memberindirect_group": group.get("memberindirect_group", []),
        "posix": not group.get("nonposix", False),
        "external": group.get("external", False),
    }


def group_find(
    cn: Optional[str] = None,
    description: Optional[str] = None,
    posix: Optional[bool] = None,
    nonposix: Optional[bool] = None,
    external: Optional[bool] = None,
    user: Optional[str] = None,
    no_user: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for groups in FreeIPA.

    Args:
        cn: Group name pattern to search (supports wildcards *)
        description: Description pattern to search
        posix: If True, only POSIX groups
        nonposix: If True, only non-POSIX groups
        external: If True, only external groups
        user: Filter groups that contain this user as a member
        no_user: Filter groups that do NOT contain this user
        limit: Maximum number of results to return

    Returns:
        Dictionary containing:
        - count: Number of groups found
        - truncated: Whether results were truncated
        - groups: List of group records
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
    if posix is not None:
        kwargs["posix"] = posix
    if nonposix is not None:
        kwargs["nonposix"] = nonposix
    if external is not None:
        kwargs["external"] = external
    if user:
        kwargs["user"] = user
    if no_user:
        kwargs["no_user"] = no_user

    try:
        result = client.group_find(**kwargs)
        groups = [_format_group(g) for g in result.get("result", [])]

        return {
            "success": True,
            "count": result.get("count", len(groups)),
            "truncated": result.get("truncated", False),
            "groups": groups,
        }
    except FreeIPAClientError as e:
        logger.error(f"group_find failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def group_show(cn: str) -> dict[str, Any]:
    """Get detailed information about a specific group.

    Args:
        cn: Group name to look up

    Returns:
        Dictionary containing group details or error information
    """
    client = get_client()

    try:
        result = client.group_show(cn, all=True)
        group = result.get("result", {})

        return {
            "success": True,
            "group": _format_group(group),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Group '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"group_show failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def group_add(
    cn: str,
    description: Optional[str] = None,
    gidnumber: Optional[int] = None,
    nonposix: bool = False,
    external: bool = False,
) -> dict[str, Any]:
    """Create a new group in FreeIPA.

    Args:
        cn: Group name
        description: Group description
        gidnumber: GID number (auto-assigned if not specified)
        nonposix: Create as non-POSIX group (no GID)
        external: Create as external group (for AD trust mapping)

    Returns:
        Dictionary containing created group details or error information
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if description:
        kwargs["description"] = description
    if gidnumber:
        kwargs["gidnumber"] = gidnumber
    if nonposix:
        kwargs["nonposix"] = True
    if external:
        kwargs["external"] = True

    try:
        result = client.group_add(cn, **kwargs)
        group = result.get("result", {})

        return {
            "success": True,
            "message": f"Group '{cn}' created successfully",
            "group": _format_group(group),
        }
    except ObjectExistsError:
        return {"success": False, "error": f"Group '{cn}' already exists", "code": "DUPLICATE_ENTRY"}
    except FreeIPAClientError as e:
        logger.error(f"group_add failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def group_mod(
    cn: str,
    description: Optional[str] = None,
    gidnumber: Optional[int] = None,
    posix: Optional[bool] = None,
) -> dict[str, Any]:
    """Modify an existing group in FreeIPA.

    Args:
        cn: Group name to modify
        description: New description
        gidnumber: New GID number
        posix: Convert to/from POSIX group

    Returns:
        Dictionary containing updated group details or error information
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if description:
        kwargs["description"] = description
    if gidnumber:
        kwargs["gidnumber"] = gidnumber
    if posix is not None:
        kwargs["posix"] = posix

    if not kwargs:
        return {"success": False, "error": "No modifications specified", "code": "NO_CHANGES"}

    try:
        result = client.group_mod(cn, **kwargs)
        group = result.get("result", {})

        return {
            "success": True,
            "message": f"Group '{cn}' modified successfully",
            "group": _format_group(group),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Group '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"group_mod failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def group_del(cn: str) -> dict[str, Any]:
    """Delete a group from FreeIPA.

    Note: Protected system groups (admins, trust admins, etc.) cannot be deleted.

    Args:
        cn: Group name to delete

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    # Check for protected groups
    protected_groups = ["admins", "trust admins", "default smb group", "editors"]
    if cn.lower() in [g.lower() for g in protected_groups]:
        return {
            "success": False,
            "error": f"Group '{cn}' is a protected system group and cannot be deleted",
            "code": "PROTECTED_GROUP",
        }

    try:
        client.group_del(cn)
        return {
            "success": True,
            "message": f"Group '{cn}' deleted successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Group '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"group_del failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def group_add_member(
    cn: str,
    users: Optional[list[str]] = None,
    groups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add members to a group.

    Args:
        cn: Group name to add members to
        users: List of usernames to add
        groups: List of group names to add (nested groups)

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
        return {"success": False, "error": "No members specified to add", "code": "NO_MEMBERS"}

    try:
        result = client.group_add_member(cn, **kwargs)

        # Check for partial failures
        failed = result.get("failed", {})
        failed_users = failed.get("member", {}).get("user", [])
        failed_groups = failed.get("member", {}).get("group", [])

        response: dict[str, Any] = {
            "success": True,
            "message": f"Members added to group '{cn}'",
        }

        if failed_users or failed_groups:
            response["warnings"] = []
            if failed_users:
                response["warnings"].append(f"Failed to add users: {failed_users}")
            if failed_groups:
                response["warnings"].append(f"Failed to add groups: {failed_groups}")

        return response

    except ObjectNotFoundError:
        return {"success": False, "error": f"Group '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"group_add_member failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def group_remove_member(
    cn: str,
    users: Optional[list[str]] = None,
    groups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Remove members from a group.

    Args:
        cn: Group name to remove members from
        users: List of usernames to remove
        groups: List of group names to remove

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
        return {"success": False, "error": "No members specified to remove", "code": "NO_MEMBERS"}

    try:
        result = client.group_remove_member(cn, **kwargs)

        # Check for partial failures
        failed = result.get("failed", {})
        failed_users = failed.get("member", {}).get("user", [])
        failed_groups = failed.get("member", {}).get("group", [])

        response: dict[str, Any] = {
            "success": True,
            "message": f"Members removed from group '{cn}'",
        }

        if failed_users or failed_groups:
            response["warnings"] = []
            if failed_users:
                response["warnings"].append(f"Failed to remove users: {failed_users}")
            if failed_groups:
                response["warnings"].append(f"Failed to remove groups: {failed_groups}")

        return response

    except ObjectNotFoundError:
        return {"success": False, "error": f"Group '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"group_remove_member failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}
