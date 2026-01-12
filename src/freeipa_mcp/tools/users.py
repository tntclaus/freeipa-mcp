"""User management tools for FreeIPA MCP Server."""

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


def _format_user(user: dict[str, Any]) -> dict[str, Any]:
    """Format a FreeIPA user record for clean output.

    Extracts commonly used fields and flattens single-value lists.
    """
    def extract(val: Any) -> Any:
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val

    return {
        "uid": extract(user.get("uid")),
        "givenname": extract(user.get("givenname")),
        "sn": extract(user.get("sn")),
        "cn": extract(user.get("cn")),
        "displayname": extract(user.get("displayname")),
        "mail": extract(user.get("mail")),
        "uidnumber": extract(user.get("uidnumber")),
        "gidnumber": extract(user.get("gidnumber")),
        "homedirectory": extract(user.get("homedirectory")),
        "loginshell": extract(user.get("loginshell")),
        "nsaccountlock": extract(user.get("nsaccountlock", False)),
        "memberof_group": user.get("memberof_group", []),
        "krbprincipalname": extract(user.get("krbprincipalname")),
    }


def user_find(
    uid: Optional[str] = None,
    mail: Optional[str] = None,
    givenname: Optional[str] = None,
    sn: Optional[str] = None,
    in_group: Optional[str] = None,
    not_in_group: Optional[str] = None,
    disabled: Optional[bool] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for users in FreeIPA.

    Args:
        uid: Username pattern to search (supports wildcards *)
        mail: Email pattern to search
        givenname: First name pattern to search
        sn: Last name (surname) pattern to search
        in_group: Filter users who are members of this group
        not_in_group: Filter users who are NOT members of this group
        disabled: If True, only disabled users; if False, only enabled users
        limit: Maximum number of results to return

    Returns:
        Dictionary containing:
        - count: Number of users found
        - truncated: Whether results were truncated
        - users: List of user records
    """
    client = get_client()
    settings = get_settings()

    kwargs: dict[str, Any] = {
        "sizelimit": limit or settings.default_limit,
        "all": True,  # Get all attributes
    }

    if uid:
        kwargs["uid"] = uid
    if mail:
        kwargs["mail"] = mail
    if givenname:
        kwargs["givenname"] = givenname
    if sn:
        kwargs["sn"] = sn
    if in_group:
        kwargs["in_group"] = in_group
    if not_in_group:
        kwargs["not_in_group"] = not_in_group
    if disabled is not None:
        kwargs["nsaccountlock"] = disabled

    try:
        result = client.user_find(**kwargs)
        users = [_format_user(u) for u in result.get("result", [])]

        return {
            "success": True,
            "count": result.get("count", len(users)),
            "truncated": result.get("truncated", False),
            "users": users,
        }
    except FreeIPAClientError as e:
        logger.error(f"user_find failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def user_show(uid: str) -> dict[str, Any]:
    """Get detailed information about a specific user.

    Args:
        uid: Username to look up

    Returns:
        Dictionary containing user details or error information
    """
    client = get_client()

    try:
        result = client.user_show(uid, all=True)
        user = result.get("result", {})

        return {
            "success": True,
            "user": _format_user(user),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"User '{uid}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"user_show failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def user_add(
    uid: str,
    givenname: str,
    sn: str,
    mail: Optional[str] = None,
    password: Optional[str] = None,
    loginshell: Optional[str] = None,
    homedirectory: Optional[str] = None,
    gidnumber: Optional[int] = None,
    noprivate: bool = False,
) -> dict[str, Any]:
    """Create a new user in FreeIPA.

    Args:
        uid: Username (login name)
        givenname: First name
        sn: Last name (surname)
        mail: Email address
        password: Initial password (user will be prompted to change on first login)
        loginshell: Login shell (e.g., /bin/bash)
        homedirectory: Home directory path
        gidnumber: Primary group ID number
        noprivate: If True, don't create a private group for the user

    Returns:
        Dictionary containing created user details or error information
    """
    client = get_client()

    kwargs: dict[str, Any] = {
        "givenname": givenname,
        "sn": sn,
    }

    if mail:
        kwargs["mail"] = mail
    if password:
        kwargs["userpassword"] = password
    if loginshell:
        kwargs["loginshell"] = loginshell
    if homedirectory:
        kwargs["homedirectory"] = homedirectory
    if gidnumber:
        kwargs["gidnumber"] = gidnumber
    if noprivate:
        kwargs["noprivate"] = True

    try:
        result = client.user_add(uid, **kwargs)
        user = result.get("result", {})

        return {
            "success": True,
            "message": f"User '{uid}' created successfully",
            "user": _format_user(user),
        }
    except ObjectExistsError:
        return {"success": False, "error": f"User '{uid}' already exists", "code": "DUPLICATE_ENTRY"}
    except FreeIPAClientError as e:
        logger.error(f"user_add failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def user_mod(
    uid: str,
    givenname: Optional[str] = None,
    sn: Optional[str] = None,
    mail: Optional[str] = None,
    loginshell: Optional[str] = None,
    homedirectory: Optional[str] = None,
    displayname: Optional[str] = None,
) -> dict[str, Any]:
    """Modify an existing user in FreeIPA.

    Args:
        uid: Username to modify
        givenname: New first name
        sn: New last name
        mail: New email address
        loginshell: New login shell
        homedirectory: New home directory
        displayname: New display name

    Returns:
        Dictionary containing updated user details or error information
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if givenname:
        kwargs["givenname"] = givenname
    if sn:
        kwargs["sn"] = sn
    if mail:
        kwargs["mail"] = mail
    if loginshell:
        kwargs["loginshell"] = loginshell
    if homedirectory:
        kwargs["homedirectory"] = homedirectory
    if displayname:
        kwargs["displayname"] = displayname

    if not kwargs:
        return {"success": False, "error": "No modifications specified", "code": "NO_CHANGES"}

    try:
        result = client.user_mod(uid, **kwargs)
        user = result.get("result", {})

        return {
            "success": True,
            "message": f"User '{uid}' modified successfully",
            "user": _format_user(user),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"User '{uid}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"user_mod failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def user_del(uid: str, preserve: bool = False) -> dict[str, Any]:
    """Delete a user from FreeIPA.

    Args:
        uid: Username to delete
        preserve: If True, preserve the user (can be undeleted later)
                 If False, permanently delete the user

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    kwargs: dict[str, Any] = {}
    if preserve:
        kwargs["preserve"] = True

    try:
        client.user_del(uid, **kwargs)

        action = "preserved" if preserve else "deleted"
        return {
            "success": True,
            "message": f"User '{uid}' {action} successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"User '{uid}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"user_del failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def user_enable(uid: str) -> dict[str, Any]:
    """Enable a disabled user account.

    Args:
        uid: Username to enable

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("user_enable", uid)
        return {
            "success": True,
            "message": f"User '{uid}' enabled successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"User '{uid}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"user_enable failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def user_disable(uid: str) -> dict[str, Any]:
    """Disable a user account.

    Args:
        uid: Username to disable

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("user_disable", uid)
        return {
            "success": True,
            "message": f"User '{uid}' disabled successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"User '{uid}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"user_disable failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def user_unlock(uid: str) -> dict[str, Any]:
    """Unlock a locked user account.

    This resets the account lockout counter, allowing the user to log in again
    after being locked out due to failed login attempts.

    Args:
        uid: Username to unlock

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("user_unlock", uid)
        return {
            "success": True,
            "message": f"User '{uid}' unlocked successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"User '{uid}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"user_unlock failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def user_status(uid: str) -> dict[str, Any]:
    """Get the status of a user account across all IPA servers.

    Shows whether the user is locked, disabled, or has password issues.

    Args:
        uid: Username to check status

    Returns:
        Dictionary containing user status information
    """
    client = get_client()

    try:
        result = client.execute("user_status", uid)
        status_list = result.get("result", [])

        # Aggregate status from potentially multiple IPA servers
        status = {
            "uid": uid,
            "servers": [],
        }

        for server_status in status_list:
            status["servers"].append({
                "server": server_status.get("server"),
                "krbloginfailedcount": server_status.get("krbloginfailedcount", [0])[0],
                "krblastfailedauth": server_status.get("krblastfailedauth"),
                "krblastsuccessfulauth": server_status.get("krblastsuccessfulauth"),
                "now": server_status.get("now"),
            })

        return {
            "success": True,
            "status": status,
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"User '{uid}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"user_status failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}
