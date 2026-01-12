"""HBAC (Host-Based Access Control) rule tools for FreeIPA MCP Server."""

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


def _format_hbacrule(rule: dict[str, Any]) -> dict[str, Any]:
    """Format a FreeIPA HBAC rule record for clean output."""
    def extract(val: Any) -> Any:
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val

    return {
        "cn": extract(rule.get("cn")),
        "description": extract(rule.get("description")),
        "ipaenabledflag": extract(rule.get("ipaenabledflag", True)),
        "accessruletype": extract(rule.get("accessruletype", "allow")),
        "usercategory": extract(rule.get("usercategory")),
        "hostcategory": extract(rule.get("hostcategory")),
        "servicecategory": extract(rule.get("servicecategory")),
        "memberuser_user": rule.get("memberuser_user", []),
        "memberuser_group": rule.get("memberuser_group", []),
        "memberhost_host": rule.get("memberhost_host", []),
        "memberhost_hostgroup": rule.get("memberhost_hostgroup", []),
        "memberservice_hbacsvc": rule.get("memberservice_hbacsvc", []),
        "memberservice_hbacsvcgroup": rule.get("memberservice_hbacsvcgroup", []),
    }


def hbacrule_find(
    cn: Optional[str] = None,
    description: Optional[str] = None,
    enabled: Optional[bool] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for HBAC rules in FreeIPA.

    Args:
        cn: Rule name pattern (supports wildcards *)
        description: Description pattern to search
        enabled: Filter by enabled/disabled status
        limit: Maximum number of results to return

    Returns:
        Dictionary containing:
        - count: Number of rules found
        - rules: List of HBAC rule records
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
        result = client.execute("hbacrule_find", **kwargs)
        rules = [_format_hbacrule(r) for r in result.get("result", [])]

        return {
            "success": True,
            "count": result.get("count", len(rules)),
            "rules": rules,
        }
    except FreeIPAClientError as e:
        logger.error(f"hbacrule_find failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def hbacrule_show(cn: str) -> dict[str, Any]:
    """Get detailed information about a specific HBAC rule.

    Args:
        cn: Rule name

    Returns:
        Dictionary containing rule details or error information
    """
    client = get_client()

    try:
        result = client.execute("hbacrule_show", cn, all=True)
        rule = result.get("result", {})

        return {
            "success": True,
            "rule": _format_hbacrule(rule),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"HBAC rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"hbacrule_show failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def hbacrule_add(
    cn: str,
    description: Optional[str] = None,
    usercategory: Optional[str] = None,
    hostcategory: Optional[str] = None,
    servicecategory: Optional[str] = None,
) -> dict[str, Any]:
    """Create a new HBAC rule in FreeIPA.

    Args:
        cn: Rule name
        description: Rule description
        usercategory: User category ('all' to apply to all users)
        hostcategory: Host category ('all' to apply to all hosts)
        servicecategory: Service category ('all' to apply to all services)

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
    if servicecategory:
        kwargs["servicecategory"] = servicecategory

    try:
        result = client.execute("hbacrule_add", cn, **kwargs)
        rule = result.get("result", {})

        return {
            "success": True,
            "message": f"HBAC rule '{cn}' created successfully",
            "rule": _format_hbacrule(rule),
        }
    except ObjectExistsError:
        return {"success": False, "error": f"HBAC rule '{cn}' already exists", "code": "DUPLICATE_ENTRY"}
    except FreeIPAClientError as e:
        logger.error(f"hbacrule_add failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def hbacrule_mod(
    cn: str,
    description: Optional[str] = None,
    usercategory: Optional[str] = None,
    hostcategory: Optional[str] = None,
    servicecategory: Optional[str] = None,
) -> dict[str, Any]:
    """Modify an existing HBAC rule.

    Args:
        cn: Rule name to modify
        description: New description
        usercategory: New user category ('all' or None to clear)
        hostcategory: New host category
        servicecategory: New service category

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
    if servicecategory is not None:
        kwargs["servicecategory"] = servicecategory

    if not kwargs:
        return {"success": False, "error": "No modifications specified", "code": "NO_CHANGES"}

    try:
        result = client.execute("hbacrule_mod", cn, **kwargs)
        rule = result.get("result", {})

        return {
            "success": True,
            "message": f"HBAC rule '{cn}' modified successfully",
            "rule": _format_hbacrule(rule),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"HBAC rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"hbacrule_mod failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def hbacrule_del(cn: str) -> dict[str, Any]:
    """Delete an HBAC rule from FreeIPA.

    Args:
        cn: Rule name to delete

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("hbacrule_del", cn)
        return {
            "success": True,
            "message": f"HBAC rule '{cn}' deleted successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"HBAC rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"hbacrule_del failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def hbacrule_enable(cn: str) -> dict[str, Any]:
    """Enable an HBAC rule.

    Args:
        cn: Rule name to enable

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("hbacrule_enable", cn)
        return {
            "success": True,
            "message": f"HBAC rule '{cn}' enabled successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"HBAC rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"hbacrule_enable failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def hbacrule_disable(cn: str) -> dict[str, Any]:
    """Disable an HBAC rule.

    Args:
        cn: Rule name to disable

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("hbacrule_disable", cn)
        return {
            "success": True,
            "message": f"HBAC rule '{cn}' disabled successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"HBAC rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"hbacrule_disable failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def hbacrule_add_user(
    cn: str,
    users: Optional[list[str]] = None,
    groups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add users or groups to an HBAC rule.

    Args:
        cn: Rule name
        users: List of usernames to add
        groups: List of group names to add

    Returns:
        Dictionary indicating success and any failures

    Note:
        Cannot add users if rule has usercategory='all'
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
        result = client.execute("hbacrule_add_user", cn, **kwargs)

        failed = result.get("failed", {})
        response: dict[str, Any] = {
            "success": True,
            "message": f"Users/groups added to HBAC rule '{cn}'",
        }

        if failed.get("memberuser", {}):
            response["warnings"] = [f"Some members failed: {failed['memberuser']}"]

        return response

    except ObjectNotFoundError:
        return {"success": False, "error": f"HBAC rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        # Check for category conflict
        if "category" in str(e).lower():
            return {
                "success": False,
                "error": "Cannot add users when usercategory is 'all'",
                "code": "CATEGORY_CONFLICT"
            }
        logger.error(f"hbacrule_add_user failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def hbacrule_add_host(
    cn: str,
    hosts: Optional[list[str]] = None,
    hostgroups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add hosts or hostgroups to an HBAC rule.

    Args:
        cn: Rule name
        hosts: List of host FQDNs to add
        hostgroups: List of hostgroup names to add

    Returns:
        Dictionary indicating success and any failures

    Note:
        Cannot add hosts if rule has hostcategory='all'
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
        result = client.execute("hbacrule_add_host", cn, **kwargs)

        failed = result.get("failed", {})
        response: dict[str, Any] = {
            "success": True,
            "message": f"Hosts/hostgroups added to HBAC rule '{cn}'",
        }

        if failed.get("memberhost", {}):
            response["warnings"] = [f"Some members failed: {failed['memberhost']}"]

        return response

    except ObjectNotFoundError:
        return {"success": False, "error": f"HBAC rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        if "category" in str(e).lower():
            return {
                "success": False,
                "error": "Cannot add hosts when hostcategory is 'all'",
                "code": "CATEGORY_CONFLICT"
            }
        logger.error(f"hbacrule_add_host failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def hbacrule_add_service(
    cn: str,
    hbacsvcs: Optional[list[str]] = None,
    hbacsvcgroups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add services or service groups to an HBAC rule.

    Args:
        cn: Rule name
        hbacsvcs: List of HBAC service names (e.g., 'sshd', 'login')
        hbacsvcgroups: List of HBAC service group names

    Returns:
        Dictionary indicating success and any failures

    Note:
        Cannot add services if rule has servicecategory='all'
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if hbacsvcs:
        kwargs["hbacsvc"] = hbacsvcs
    if hbacsvcgroups:
        kwargs["hbacsvcgroup"] = hbacsvcgroups

    if not kwargs:
        return {"success": False, "error": "No services specified", "code": "NO_MEMBERS"}

    try:
        result = client.execute("hbacrule_add_service", cn, **kwargs)

        failed = result.get("failed", {})
        response: dict[str, Any] = {
            "success": True,
            "message": f"Services added to HBAC rule '{cn}'",
        }

        if failed.get("memberservice", {}):
            response["warnings"] = [f"Some services failed: {failed['memberservice']}"]

        return response

    except ObjectNotFoundError:
        return {"success": False, "error": f"HBAC rule '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        if "category" in str(e).lower():
            return {
                "success": False,
                "error": "Cannot add services when servicecategory is 'all'",
                "code": "CATEGORY_CONFLICT"
            }
        logger.error(f"hbacrule_add_service failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}
