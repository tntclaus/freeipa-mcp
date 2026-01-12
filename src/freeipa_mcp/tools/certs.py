"""Certificate management tools for FreeIPA MCP Server."""

import logging
from typing import Any, Optional

from ..client import (
    FreeIPAClientError,
    ObjectNotFoundError,
    get_client,
)

logger = logging.getLogger(__name__)


def user_add_cert(uid: str, certificate: str) -> dict[str, Any]:
    """Add a certificate to a user.

    Args:
        uid: Username to add certificate to
        certificate: Base64-encoded certificate (PEM format without headers)

    Returns:
        Dictionary indicating success or error

    Note:
        The certificate should be the base64 content only,
        without the '-----BEGIN CERTIFICATE-----' and
        '-----END CERTIFICATE-----' headers.
    """
    client = get_client()

    # Clean up certificate if it has PEM headers
    cert_clean = certificate.strip()
    if cert_clean.startswith("-----BEGIN"):
        lines = cert_clean.split("\n")
        cert_clean = "".join(
            line for line in lines
            if not line.startswith("-----")
        )

    try:
        client.execute("user_add_cert", uid, usercertificate=cert_clean)
        return {
            "success": True,
            "message": f"Certificate added to user '{uid}'",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"User '{uid}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"user_add_cert failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def user_remove_cert(uid: str, certificate: str) -> dict[str, Any]:
    """Remove a certificate from a user.

    Args:
        uid: Username to remove certificate from
        certificate: Base64-encoded certificate to remove

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    # Clean up certificate if it has PEM headers
    cert_clean = certificate.strip()
    if cert_clean.startswith("-----BEGIN"):
        lines = cert_clean.split("\n")
        cert_clean = "".join(
            line for line in lines
            if not line.startswith("-----")
        )

    try:
        client.execute("user_remove_cert", uid, usercertificate=cert_clean)
        return {
            "success": True,
            "message": f"Certificate removed from user '{uid}'",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"User '{uid}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"user_remove_cert failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def host_add_cert(fqdn: str, certificate: str) -> dict[str, Any]:
    """Add a certificate to a host.

    Args:
        fqdn: Host FQDN to add certificate to
        certificate: Base64-encoded certificate (PEM format without headers)

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    # Clean up certificate if it has PEM headers
    cert_clean = certificate.strip()
    if cert_clean.startswith("-----BEGIN"):
        lines = cert_clean.split("\n")
        cert_clean = "".join(
            line for line in lines
            if not line.startswith("-----")
        )

    try:
        client.execute("host_add_cert", fqdn, usercertificate=cert_clean)
        return {
            "success": True,
            "message": f"Certificate added to host '{fqdn}'",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Host '{fqdn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"host_add_cert failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def host_remove_cert(fqdn: str, certificate: str) -> dict[str, Any]:
    """Remove a certificate from a host.

    Args:
        fqdn: Host FQDN to remove certificate from
        certificate: Base64-encoded certificate to remove

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    # Clean up certificate if it has PEM headers
    cert_clean = certificate.strip()
    if cert_clean.startswith("-----BEGIN"):
        lines = cert_clean.split("\n")
        cert_clean = "".join(
            line for line in lines
            if not line.startswith("-----")
        )

    try:
        client.execute("host_remove_cert", fqdn, usercertificate=cert_clean)
        return {
            "success": True,
            "message": f"Certificate removed from host '{fqdn}'",
        }
    except ObjectNotFoundError:
        return {"success": False, "error": f"Host '{fqdn}' not found", "code": "NOT_FOUND"}
    except FreeIPAClientError as e:
        logger.error(f"host_remove_cert failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def cert_find(
    subject: Optional[str] = None,
    issuer: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    service: Optional[str] = None,
    validnotafter_from: Optional[str] = None,
    validnotafter_to: Optional[str] = None,
    status: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for certificates in FreeIPA.

    Args:
        subject: Subject DN pattern to search
        issuer: Issuer DN pattern to search
        user: Find certificates for this user
        host: Find certificates for this host
        service: Find certificates for this service
        validnotafter_from: Certificates expiring after this date (YYYY-MM-DD)
        validnotafter_to: Certificates expiring before this date (YYYY-MM-DD)
        status: Certificate status (VALID, REVOKED, etc.)
        limit: Maximum number of results

    Returns:
        Dictionary containing certificate information
    """
    client = get_client()

    kwargs: dict[str, Any] = {
        "sizelimit": limit or 100,
    }

    if subject:
        kwargs["subject"] = subject
    if issuer:
        kwargs["issuer"] = issuer
    if user:
        kwargs["user"] = user
    if host:
        kwargs["host"] = host
    if service:
        kwargs["service"] = service
    if validnotafter_from:
        kwargs["validnotafter_from"] = validnotafter_from
    if validnotafter_to:
        kwargs["validnotafter_to"] = validnotafter_to
    if status:
        kwargs["status"] = status

    try:
        result = client.execute("cert_find", **kwargs)
        certs = result.get("result", [])

        formatted = []
        for cert in certs:
            formatted.append({
                "serial_number": cert.get("serial_number"),
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "valid_not_before": cert.get("valid_not_before"),
                "valid_not_after": cert.get("valid_not_after"),
                "status": cert.get("status"),
                "owner_user": cert.get("owner_user", []),
                "owner_host": cert.get("owner_host", []),
                "owner_service": cert.get("owner_service", []),
            })

        return {
            "success": True,
            "count": result.get("count", len(formatted)),
            "certificates": formatted,
        }
    except FreeIPAClientError as e:
        logger.error(f"cert_find failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def cert_show(serial_number: int) -> dict[str, Any]:
    """Get detailed information about a certificate.

    Args:
        serial_number: Certificate serial number

    Returns:
        Dictionary containing certificate details
    """
    client = get_client()

    try:
        result = client.execute("cert_show", serial_number)
        cert = result.get("result", {})

        return {
            "success": True,
            "certificate": {
                "serial_number": cert.get("serial_number"),
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "valid_not_before": cert.get("valid_not_before"),
                "valid_not_after": cert.get("valid_not_after"),
                "status": cert.get("status"),
                "revocation_reason": cert.get("revocation_reason"),
                "owner_user": cert.get("owner_user", []),
                "owner_host": cert.get("owner_host", []),
                "owner_service": cert.get("owner_service", []),
                "certificate": cert.get("certificate"),  # Base64 encoded
            }
        }
    except ObjectNotFoundError:
        return {
            "success": False,
            "error": f"Certificate with serial {serial_number} not found",
            "code": "NOT_FOUND"
        }
    except FreeIPAClientError as e:
        logger.error(f"cert_show failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}


def cert_revoke(serial_number: int, reason: int = 0) -> dict[str, Any]:
    """Revoke a certificate.

    Args:
        serial_number: Certificate serial number to revoke
        reason: Revocation reason code:
            0 - unspecified (default)
            1 - keyCompromise
            2 - cACompromise
            3 - affiliationChanged
            4 - superseded
            5 - cessationOfOperation
            6 - certificateHold
            9 - privilegeWithdrawn
            10 - aACompromise

    Returns:
        Dictionary indicating success or error
    """
    client = get_client()

    try:
        client.execute("cert_revoke", serial_number, revocation_reason=reason)

        reason_names = {
            0: "unspecified",
            1: "keyCompromise",
            2: "cACompromise",
            3: "affiliationChanged",
            4: "superseded",
            5: "cessationOfOperation",
            6: "certificateHold",
            9: "privilegeWithdrawn",
            10: "aACompromise",
        }

        return {
            "success": True,
            "message": f"Certificate {serial_number} revoked (reason: {reason_names.get(reason, reason)})",
        }
    except ObjectNotFoundError:
        return {
            "success": False,
            "error": f"Certificate with serial {serial_number} not found",
            "code": "NOT_FOUND"
        }
    except FreeIPAClientError as e:
        logger.error(f"cert_revoke failed: {e}")
        return {"success": False, "error": e.message, "code": e.code}
