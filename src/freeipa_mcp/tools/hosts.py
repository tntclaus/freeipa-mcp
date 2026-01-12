"""Host management tools for FreeIPA MCP Server."""

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


def _format_host(host: dict[str, Any]) -> dict[str, Any]:
    """Format a FreeIPA host record for clean output."""
    def extract(val: Any) -> Any:
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val

    return {
        "fqdn": extract(host.get("fqdn")),
        "description": extract(host.get("description")),
        "locality": extract(host.get("l")),  # locality is stored as 'l'
        "location": extract(host.get("nshostlocation")),
        "platform": extract(host.get("nshardwareplatform")),
        "os": extract(host.get("nsosversion")),
        "krbprincipalname": extract(host.get("krbprincipalname")),
        "managedby_host": host.get("managedby_host", []),
        "memberof_hostgroup": host.get("memberof_hostgroup", []),
        "memberofindirect_hostgroup": host.get("memberofindirect_hostgroup", []),
        "sshpubkeyfp": host.get("sshpubkeyfp", []),
        "has_keytab": host.get("has_keytab", False),
        "has_password": host.get("has_password", False),
    }


def host_find(
    fqdn: Optional[str] = None,
    description: Optional[str] = None,
    locality: Optional[str] = None,
    location: Optional[str] = None,
    platform: Optional[str] = None,
    os: Optional[str] = None,
    in_hostgroup: Optional[str] = None,
    not_in_hostgroup: Optional[str] = None,
    enroll_by_user: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for hosts in FreeIPA.

    Args:
        fqdn: Fully qualified domain name pattern (supports wildcards *)
        description: Description pattern to search
        locality: Locality pattern to search
        location: Location pattern to search
        platform: Hardware platform pattern to search
        os: Operating system version pattern to search
        in_hostgroup: Filter hosts in this hostgroup
        not_in_hostgroup: Filter hosts NOT in this hostgroup
        enroll_by_user: Filter hosts enrolled by this user
        limit: Maximum number of results to return

    Returns:
        Dictionary containing:
        - count: Number of hosts found
        - truncated: Whether results were truncated
        - hosts: List of host records
    """
    client = get_client()
    settings = get_settings()

    kwargs: dict[str, Any] = {
        "sizelimit": limit or settings.default_limit,
        "all": True,
    }

    if fqdn:
        kwargs["fqdn"] = fqdn
    if description:
        kwargs["description"] = description
    if locality:
        kwargs["l"] = locality
    if location:
        kwargs["nshostlocation"] = location
    if platform:
        kwargs["nshardwareplatform"] = platform
    if os:
        kwargs["nsosversion"] = os
    if in_hostgroup:
        kwargs["in_hostgroup"] = in_hostgroup
    if not_in_hostgroup:
        kwargs["not_in_hostgroup"] = not_in_hostgroup
    if enroll_by_user:
        kwargs["enroll_by_user"] = enroll_by_user

    try:
        result = client.host_find(**kwargs)
        hosts = [_format_host(h) for h in result.get("result", [])]

        return {
            "success": True,
            "count": result.get("count", len(hosts)),
            "truncated": result.get("truncated", False),
            "hosts": hosts,
        }
    except FreeIPAClientError as e:
        logger.error(f"host_find failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def host_show(fqdn: str) -> dict[str, Any]:
    """Get detailed information about a specific host.

    Args:
        fqdn: Fully qualified domain name of the host

    Returns:
        Dictionary containing host details or error information
    """
    client = get_client()

    try:
        result = client.host_show(fqdn, all=True)
        host = result.get("result", {})

        return {
            "success": True,
            "host": _format_host(host),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Host '{fqdn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"host_show failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def host_add(
    fqdn: str,
    description: Optional[str] = None,
    locality: Optional[str] = None,
    location: Optional[str] = None,
    platform: Optional[str] = None,
    os: Optional[str] = None,
    ip_address: Optional[str] = None,
    random_password: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Register a new host in FreeIPA.

    Args:
        fqdn: Fully qualified domain name for the host
        description: Host description
        locality: Locality (city, region)
        location: Physical location (e.g., rack, room)
        platform: Hardware platform (e.g., x86_64, aarch64)
        os: Operating system version
        ip_address: IP address (creates DNS A record if DNS is enabled)
        random_password: Generate a random OTP for host enrollment
        force: Force creation even if host not resolvable

    Returns:
        Dictionary containing created host details or error information
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if description:
        kwargs["description"] = description
    if locality:
        kwargs["l"] = locality
    if location:
        kwargs["nshostlocation"] = location
    if platform:
        kwargs["nshardwareplatform"] = platform
    if os:
        kwargs["nsosversion"] = os
    if ip_address:
        kwargs["ip_address"] = ip_address
    if random_password:
        kwargs["random"] = True
    if force:
        kwargs["force"] = True

    try:
        result = client.host_add(fqdn, **kwargs)
        host = result.get("result", {})

        response: dict[str, Any] = {
            "success": True,
            "message": f"Host '{fqdn}' created successfully",
            "host": _format_host(host),
        }

        # Include random password if generated
        if random_password and "randompassword" in host:
            response["otp"] = host["randompassword"]

        return response

    except ObjectExistsError:
        return {"success": False, "error": f"Host '{fqdn}' already exists", "code": "DUPLICATE_ENTRY"}
    except FreeIPAClientError as e:
        logger.error(f"host_add failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def host_mod(
    fqdn: str,
    description: Optional[str] = None,
    locality: Optional[str] = None,
    location: Optional[str] = None,
    platform: Optional[str] = None,
    os: Optional[str] = None,
) -> dict[str, Any]:
    """Modify an existing host in FreeIPA.

    Args:
        fqdn: Fully qualified domain name of the host
        description: New description
        locality: New locality
        location: New physical location
        platform: New hardware platform
        os: New operating system version

    Returns:
        Dictionary containing updated host details or error information
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if description:
        kwargs["description"] = description
    if locality:
        kwargs["l"] = locality
    if location:
        kwargs["nshostlocation"] = location
    if platform:
        kwargs["nshardwareplatform"] = platform
    if os:
        kwargs["nsosversion"] = os

    if not kwargs:
        return {"success": False, "error": "No modifications specified", "code": "NO_CHANGES"}

    try:
        result = client.host_mod(fqdn, **kwargs)
        host = result.get("result", {})

        return {
            "success": True,
            "message": f"Host '{fqdn}' modified successfully",
            "host": _format_host(host),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Host '{fqdn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"host_mod failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def host_del(fqdn: str, updatedns: bool = False) -> dict[str, Any]:
    """Delete a host from FreeIPA.

    Args:
        fqdn: Fully qualified domain name of the host to delete
        updatedns: Also remove DNS records associated with the host

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    kwargs: dict[str, Any] = {}
    if updatedns:
        kwargs["updatedns"] = True

    try:
        client.host_del(fqdn, **kwargs)
        return {
            "success": True,
            "message": f"Host '{fqdn}' deleted successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Host '{fqdn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"host_del failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def host_disable(fqdn: str) -> dict[str, Any]:
    """Disable a host's Kerberos key.

    This prevents the host from authenticating but keeps the entry.

    Args:
        fqdn: Fully qualified domain name of the host to disable

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("host_disable", fqdn)
        return {
            "success": True,
            "message": f"Host '{fqdn}' disabled successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Host '{fqdn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"host_disable failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def hostgroup_find(
    cn: Optional[str] = None,
    description: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for hostgroups in FreeIPA.

    Args:
        cn: Hostgroup name pattern (supports wildcards *)
        description: Description pattern to search
        limit: Maximum number of results to return

    Returns:
        Dictionary containing list of hostgroups
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

    try:
        result = client.execute("hostgroup_find", **kwargs)
        hostgroups = result.get("result", [])

        formatted = []
        for hg in hostgroups:
            formatted.append({
                "cn": hg.get("cn", [None])[0] if isinstance(hg.get("cn"), list) else hg.get("cn"),
                "description": hg.get("description", [None])[0] if isinstance(hg.get("description"), list) else hg.get("description"),
                "member_host": hg.get("member_host", []),
                "member_hostgroup": hg.get("member_hostgroup", []),
            })

        return {
            "success": True,
            "count": result.get("count", len(formatted)),
            "hostgroups": formatted,
        }
    except FreeIPAClientError as e:
        logger.error(f"hostgroup_find failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def hostgroup_add_member(
    cn: str,
    hosts: Optional[list[str]] = None,
    hostgroups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add hosts or hostgroups to a hostgroup.

    Args:
        cn: Hostgroup name
        hosts: List of host FQDNs to add
        hostgroups: List of hostgroup names to add (nested hostgroups)

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
        return {"success": False, "error": "No members specified to add", "code": "NO_MEMBERS"}

    try:
        result = client.execute("hostgroup_add_member", cn, **kwargs)

        failed = result.get("failed", {})
        failed_hosts = failed.get("member", {}).get("host", [])
        failed_hostgroups = failed.get("member", {}).get("hostgroup", [])

        response: dict[str, Any] = {
            "success": True,
            "message": f"Members added to hostgroup '{cn}'",
        }

        if failed_hosts or failed_hostgroups:
            response["warnings"] = []
            if failed_hosts:
                response["warnings"].append(f"Failed to add hosts: {failed_hosts}")
            if failed_hostgroups:
                response["warnings"].append(f"Failed to add hostgroups: {failed_hostgroups}")

        return response

    except ObjectNotFoundError:
        return {"success": False, "error": f"Hostgroup '{cn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"hostgroup_add_member failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}
