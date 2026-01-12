"""DNS management tools for FreeIPA MCP Server."""

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


def _format_zone(zone: dict[str, Any]) -> dict[str, Any]:
    """Format a FreeIPA DNS zone record for clean output."""
    def extract(val: Any) -> Any:
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val

    return {
        "idnsname": extract(zone.get("idnsname")),
        "idnszoneactive": extract(zone.get("idnszoneactive")),
        "idnssoamname": extract(zone.get("idnssoamname")),
        "idnssoarname": extract(zone.get("idnssoarname")),
        "idnssoaserial": extract(zone.get("idnssoaserial")),
        "idnssoarefresh": extract(zone.get("idnssoarefresh")),
        "idnssoaretry": extract(zone.get("idnssoaretry")),
        "idnssoaexpire": extract(zone.get("idnssoaexpire")),
        "idnssoaminimum": extract(zone.get("idnssoaminimum")),
        "idnsallowdynupdate": extract(zone.get("idnsallowdynupdate")),
    }


def _format_record(record: dict[str, Any]) -> dict[str, Any]:
    """Format a FreeIPA DNS record for clean output."""
    def extract(val: Any) -> Any:
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val

    formatted = {
        "idnsname": extract(record.get("idnsname")),
    }

    # Include all record types found
    record_types = [
        "arecord", "aaaarecord", "cnamerecord", "mxrecord",
        "txtrecord", "ptrrecord", "srvrecord", "nsrecord",
        "sshfprecord", "tlsarecord", "caarecord"
    ]

    for rt in record_types:
        if rt in record:
            formatted[rt] = record[rt]

    return formatted


def dnszone_find(
    idnsname: Optional[str] = None,
    forward_only: Optional[bool] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for DNS zones in FreeIPA.

    Args:
        idnsname: Zone name pattern (supports wildcards *)
        forward_only: If True, only return forward zones; if False, only reverse zones
        limit: Maximum number of results to return

    Returns:
        Dictionary containing:
        - count: Number of zones found
        - zones: List of zone records
    """
    client = get_client()
    settings = get_settings()

    kwargs: dict[str, Any] = {
        "sizelimit": limit or settings.default_limit,
        "all": True,
    }

    if idnsname:
        kwargs["idnsname"] = idnsname
    if forward_only is not None:
        kwargs["forward_only"] = forward_only

    try:
        result = client.execute("dnszone_find", **kwargs)
        zones = [_format_zone(z) for z in result.get("result", [])]

        return {
            "success": True,
            "count": result.get("count", len(zones)),
            "zones": zones,
        }
    except FreeIPAClientError as e:
        logger.error(f"dnszone_find failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def dnszone_show(idnsname: str) -> dict[str, Any]:
    """Get detailed information about a specific DNS zone.

    Args:
        idnsname: Zone name

    Returns:
        Dictionary containing zone details or error information
    """
    client = get_client()

    try:
        result = client.execute("dnszone_show", idnsname, all=True)
        zone = result.get("result", {})

        return {
            "success": True,
            "zone": _format_zone(zone),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"DNS zone '{idnsname}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"dnszone_show failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def dnszone_add(
    idnsname: str,
    idnssoamname: Optional[str] = None,
    idnssoarname: Optional[str] = None,
    force: bool = False,
) -> dict[str, Any]:
    """Create a new DNS zone in FreeIPA.

    Args:
        idnsname: Zone name (e.g., 'example.com' or '168.192.in-addr.arpa')
        idnssoamname: Primary nameserver FQDN
        idnssoarname: Administrator email (with @ replaced by .)
        force: Force creation even if nameserver is not resolvable

    Returns:
        Dictionary containing created zone details or error information
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if idnssoamname:
        kwargs["idnssoamname"] = idnssoamname
    if idnssoarname:
        kwargs["idnssoarname"] = idnssoarname
    if force:
        kwargs["force"] = True

    try:
        result = client.execute("dnszone_add", idnsname, **kwargs)
        zone = result.get("result", {})

        return {
            "success": True,
            "message": f"DNS zone '{idnsname}' created successfully",
            "zone": _format_zone(zone),
        }
    except ObjectExistsError:
        return {"success": False, "error": f"DNS zone '{idnsname}' already exists", "code": "DUPLICATE_ENTRY"}
    except FreeIPAClientError as e:
        logger.error(f"dnszone_add failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def dnszone_del(idnsname: str) -> dict[str, Any]:
    """Delete a DNS zone from FreeIPA.

    Args:
        idnsname: Zone name to delete

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("dnszone_del", idnsname)
        return {
            "success": True,
            "message": f"DNS zone '{idnsname}' deleted successfully",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"DNS zone '{idnsname}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"dnszone_del failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def dnsrecord_find(
    dnszoneidnsname: str,
    idnsname: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for DNS records in a zone.

    Args:
        dnszoneidnsname: Zone name to search in
        idnsname: Record name pattern (supports wildcards *)
        limit: Maximum number of results to return

    Returns:
        Dictionary containing:
        - count: Number of records found
        - records: List of DNS records
    """
    client = get_client()
    settings = get_settings()

    kwargs: dict[str, Any] = {
        "sizelimit": limit or settings.default_limit,
        "all": True,
    }

    if idnsname:
        kwargs["idnsname"] = idnsname

    try:
        result = client.execute("dnsrecord_find", dnszoneidnsname, **kwargs)
        records = [_format_record(r) for r in result.get("result", [])]

        return {
            "success": True,
            "count": result.get("count", len(records)),
            "zone": dnszoneidnsname,
            "records": records,
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"DNS zone '{dnszoneidnsname}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"dnsrecord_find failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def dnsrecord_add(
    dnszoneidnsname: str,
    idnsname: str,
    a_ip_address: Optional[str] = None,
    aaaa_ip_address: Optional[str] = None,
    cname_hostname: Optional[str] = None,
    mx_preference: Optional[int] = None,
    mx_exchanger: Optional[str] = None,
    txt_data: Optional[str] = None,
    ptr_hostname: Optional[str] = None,
) -> dict[str, Any]:
    """Add a DNS record to a zone.

    Args:
        dnszoneidnsname: Zone name to add record to
        idnsname: Record name (hostname part, not FQDN)
        a_ip_address: IPv4 address for A record
        aaaa_ip_address: IPv6 address for AAAA record
        cname_hostname: Target hostname for CNAME record
        mx_preference: MX preference value
        mx_exchanger: MX mail exchanger hostname
        txt_data: TXT record data
        ptr_hostname: PTR target hostname (for reverse DNS)

    Returns:
        Dictionary containing created record details or error information
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if a_ip_address:
        kwargs["arecord"] = a_ip_address
    if aaaa_ip_address:
        kwargs["aaaarecord"] = aaaa_ip_address
    if cname_hostname:
        kwargs["cnamerecord"] = cname_hostname
    if mx_preference is not None and mx_exchanger:
        kwargs["mxrecord"] = f"{mx_preference} {mx_exchanger}"
    if txt_data:
        kwargs["txtrecord"] = txt_data
    if ptr_hostname:
        kwargs["ptrrecord"] = ptr_hostname

    if not kwargs:
        return {"success": False, "error": "No record data specified", "code": "NO_DATA"}

    try:
        result = client.execute("dnsrecord_add", dnszoneidnsname, idnsname, **kwargs)
        record = result.get("result", {})

        return {
            "success": True,
            "message": f"DNS record '{idnsname}' added to zone '{dnszoneidnsname}'",
            "record": _format_record(record),
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"DNS zone '{dnszoneidnsname}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"dnsrecord_add failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def dnsrecord_del(
    dnszoneidnsname: str,
    idnsname: str,
    a_ip_address: Optional[str] = None,
    aaaa_ip_address: Optional[str] = None,
    cname_hostname: Optional[str] = None,
    del_all: bool = False,
) -> dict[str, Any]:
    """Delete a DNS record from a zone.

    Args:
        dnszoneidnsname: Zone name
        idnsname: Record name to delete
        a_ip_address: Specific A record to delete
        aaaa_ip_address: Specific AAAA record to delete
        cname_hostname: Specific CNAME record to delete
        del_all: Delete all records for this name

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    kwargs: dict[str, Any] = {}

    if del_all:
        kwargs["del_all"] = True
    else:
        if a_ip_address:
            kwargs["arecord"] = a_ip_address
        if aaaa_ip_address:
            kwargs["aaaarecord"] = aaaa_ip_address
        if cname_hostname:
            kwargs["cnamerecord"] = cname_hostname

    if not kwargs:
        return {
            "success": False,
            "error": "Specify records to delete or use del_all=True",
            "code": "NO_DATA"
        }

    try:
        client.execute("dnsrecord_del", dnszoneidnsname, idnsname, **kwargs)
        return {
            "success": True,
            "message": f"DNS record '{idnsname}' deleted from zone '{dnszoneidnsname}'",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"DNS record not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"dnsrecord_del failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}
