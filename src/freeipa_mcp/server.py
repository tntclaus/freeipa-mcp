"""FastMCP server for FreeIPA identity management."""

import logging
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from .config import get_settings, validate_settings
from .tools import users, groups, hosts, dns, hbac, sudo, certs

# Configure logging to stderr (stdout is reserved for MCP protocol)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Create FastMCP server instance
mcp = FastMCP(
    "FreeIPA MCP Server",
    description="Identity management server for FreeIPA - manage users, groups, hosts, DNS, HBAC, and sudo rules",
)


# =============================================================================
# User Management Tools
# =============================================================================


@mcp.tool()
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
    """
    return users.user_find(
        uid=uid, mail=mail, givenname=givenname, sn=sn,
        in_group=in_group, not_in_group=not_in_group,
        disabled=disabled, limit=limit
    )


@mcp.tool()
def user_show(uid: str) -> dict[str, Any]:
    """Get detailed information about a specific user.

    Args:
        uid: Username to look up
    """
    return users.user_show(uid)


@mcp.tool()
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
    """
    return users.user_add(
        uid=uid, givenname=givenname, sn=sn, mail=mail,
        password=password, loginshell=loginshell,
        homedirectory=homedirectory, gidnumber=gidnumber, noprivate=noprivate
    )


@mcp.tool()
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
    """
    return users.user_mod(
        uid=uid, givenname=givenname, sn=sn, mail=mail,
        loginshell=loginshell, homedirectory=homedirectory, displayname=displayname
    )


@mcp.tool()
def user_del(uid: str, preserve: bool = False) -> dict[str, Any]:
    """Delete a user from FreeIPA.

    Args:
        uid: Username to delete
        preserve: If True, preserve the user (can be undeleted later)
    """
    return users.user_del(uid=uid, preserve=preserve)


@mcp.tool()
def user_enable(uid: str) -> dict[str, Any]:
    """Enable a disabled user account.

    Args:
        uid: Username to enable
    """
    return users.user_enable(uid)


@mcp.tool()
def user_disable(uid: str) -> dict[str, Any]:
    """Disable a user account.

    Args:
        uid: Username to disable
    """
    return users.user_disable(uid)


@mcp.tool()
def user_unlock(uid: str) -> dict[str, Any]:
    """Unlock a locked user account (reset failed login counter).

    Args:
        uid: Username to unlock
    """
    return users.user_unlock(uid)


# =============================================================================
# Group Management Tools
# =============================================================================


@mcp.tool()
def group_find(
    cn: Optional[str] = None,
    description: Optional[str] = None,
    posix: Optional[bool] = None,
    user: Optional[str] = None,
    no_user: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for groups in FreeIPA.

    Args:
        cn: Group name pattern (supports wildcards *)
        description: Description pattern to search
        posix: If True, only POSIX groups
        user: Filter groups containing this user
        no_user: Filter groups NOT containing this user
        limit: Maximum results to return
    """
    return groups.group_find(
        cn=cn, description=description, posix=posix,
        user=user, no_user=no_user, limit=limit
    )


@mcp.tool()
def group_show(cn: str) -> dict[str, Any]:
    """Get detailed information about a specific group.

    Args:
        cn: Group name
    """
    return groups.group_show(cn)


@mcp.tool()
def group_add(
    cn: str,
    description: Optional[str] = None,
    gidnumber: Optional[int] = None,
    nonposix: bool = False,
) -> dict[str, Any]:
    """Create a new group in FreeIPA.

    Args:
        cn: Group name
        description: Group description
        gidnumber: GID number (auto-assigned if not specified)
        nonposix: Create as non-POSIX group (no GID)
    """
    return groups.group_add(cn=cn, description=description, gidnumber=gidnumber, nonposix=nonposix)


@mcp.tool()
def group_mod(
    cn: str,
    description: Optional[str] = None,
    gidnumber: Optional[int] = None,
) -> dict[str, Any]:
    """Modify an existing group.

    Args:
        cn: Group name to modify
        description: New description
        gidnumber: New GID number
    """
    return groups.group_mod(cn=cn, description=description, gidnumber=gidnumber)


@mcp.tool()
def group_del(cn: str) -> dict[str, Any]:
    """Delete a group from FreeIPA.

    Args:
        cn: Group name to delete
    """
    return groups.group_del(cn)


@mcp.tool()
def group_add_member(
    cn: str,
    users: Optional[list[str]] = None,
    groups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add members to a group.

    Args:
        cn: Group name
        users: List of usernames to add
        groups: List of group names to add (nested groups)
    """
    return groups.group_add_member(cn=cn, users=users, groups=groups)


@mcp.tool()
def group_remove_member(
    cn: str,
    users: Optional[list[str]] = None,
    groups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Remove members from a group.

    Args:
        cn: Group name
        users: List of usernames to remove
        groups: List of group names to remove
    """
    return groups.group_remove_member(cn=cn, users=users, groups=groups)


# =============================================================================
# Host Management Tools
# =============================================================================


@mcp.tool()
def host_find(
    fqdn: Optional[str] = None,
    description: Optional[str] = None,
    in_hostgroup: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for hosts in FreeIPA.

    Args:
        fqdn: Hostname pattern (supports wildcards *)
        description: Description pattern
        in_hostgroup: Filter by hostgroup membership
        limit: Maximum results to return
    """
    return hosts.host_find(fqdn=fqdn, description=description, in_hostgroup=in_hostgroup, limit=limit)


@mcp.tool()
def host_show(fqdn: str) -> dict[str, Any]:
    """Get detailed information about a host.

    Args:
        fqdn: Fully qualified domain name
    """
    return hosts.host_show(fqdn)


@mcp.tool()
def host_add(
    fqdn: str,
    description: Optional[str] = None,
    ip_address: Optional[str] = None,
    random_password: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Register a new host in FreeIPA.

    Args:
        fqdn: Fully qualified domain name
        description: Host description
        ip_address: IP address (creates DNS A record if DNS enabled)
        random_password: Generate OTP for host enrollment
        force: Force creation even if not resolvable
    """
    return hosts.host_add(
        fqdn=fqdn, description=description, ip_address=ip_address,
        random_password=random_password, force=force
    )


@mcp.tool()
def host_mod(
    fqdn: str,
    description: Optional[str] = None,
    locality: Optional[str] = None,
    location: Optional[str] = None,
) -> dict[str, Any]:
    """Modify an existing host.

    Args:
        fqdn: Host FQDN to modify
        description: New description
        locality: New locality
        location: New physical location
    """
    return hosts.host_mod(fqdn=fqdn, description=description, locality=locality, location=location)


@mcp.tool()
def host_del(fqdn: str, updatedns: bool = False) -> dict[str, Any]:
    """Delete a host from FreeIPA.

    Args:
        fqdn: Host FQDN to delete
        updatedns: Also remove associated DNS records
    """
    return hosts.host_del(fqdn=fqdn, updatedns=updatedns)


@mcp.tool()
def host_disable(fqdn: str) -> dict[str, Any]:
    """Disable a host's Kerberos key.

    Args:
        fqdn: Host FQDN to disable
    """
    return hosts.host_disable(fqdn)


# =============================================================================
# DNS Management Tools
# =============================================================================


@mcp.tool()
def dnszone_find(
    idnsname: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for DNS zones.

    Args:
        idnsname: Zone name pattern (supports wildcards *)
        limit: Maximum results to return
    """
    return dns.dnszone_find(idnsname=idnsname, limit=limit)


@mcp.tool()
def dnszone_show(idnsname: str) -> dict[str, Any]:
    """Get DNS zone details.

    Args:
        idnsname: Zone name
    """
    return dns.dnszone_show(idnsname)


@mcp.tool()
def dnszone_add(idnsname: str, force: bool = False) -> dict[str, Any]:
    """Create a new DNS zone.

    Args:
        idnsname: Zone name (e.g., 'example.com')
        force: Force creation even if nameserver not resolvable
    """
    return dns.dnszone_add(idnsname=idnsname, force=force)


@mcp.tool()
def dnsrecord_find(
    dnszoneidnsname: str,
    idnsname: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for DNS records in a zone.

    Args:
        dnszoneidnsname: Zone name to search in
        idnsname: Record name pattern
        limit: Maximum results to return
    """
    return dns.dnsrecord_find(dnszoneidnsname=dnszoneidnsname, idnsname=idnsname, limit=limit)


@mcp.tool()
def dnsrecord_add(
    dnszoneidnsname: str,
    idnsname: str,
    a_ip_address: Optional[str] = None,
    aaaa_ip_address: Optional[str] = None,
    cname_hostname: Optional[str] = None,
    txt_data: Optional[str] = None,
) -> dict[str, Any]:
    """Add a DNS record to a zone.

    Args:
        dnszoneidnsname: Zone name
        idnsname: Record name (hostname part)
        a_ip_address: IPv4 address for A record
        aaaa_ip_address: IPv6 address for AAAA record
        cname_hostname: Target for CNAME record
        txt_data: TXT record data
    """
    return dns.dnsrecord_add(
        dnszoneidnsname=dnszoneidnsname, idnsname=idnsname,
        a_ip_address=a_ip_address, aaaa_ip_address=aaaa_ip_address,
        cname_hostname=cname_hostname, txt_data=txt_data
    )


@mcp.tool()
def dnsrecord_del(
    dnszoneidnsname: str,
    idnsname: str,
    del_all: bool = False,
) -> dict[str, Any]:
    """Delete DNS records.

    Args:
        dnszoneidnsname: Zone name
        idnsname: Record name to delete
        del_all: Delete all records for this name
    """
    return dns.dnsrecord_del(dnszoneidnsname=dnszoneidnsname, idnsname=idnsname, del_all=del_all)


# =============================================================================
# HBAC Rule Tools
# =============================================================================


@mcp.tool()
def hbacrule_find(
    cn: Optional[str] = None,
    enabled: Optional[bool] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for HBAC rules.

    Args:
        cn: Rule name pattern (supports wildcards *)
        enabled: Filter by enabled status
        limit: Maximum results to return
    """
    return hbac.hbacrule_find(cn=cn, enabled=enabled, limit=limit)


@mcp.tool()
def hbacrule_show(cn: str) -> dict[str, Any]:
    """Get HBAC rule details.

    Args:
        cn: Rule name
    """
    return hbac.hbacrule_show(cn)


@mcp.tool()
def hbacrule_add(
    cn: str,
    description: Optional[str] = None,
    usercategory: Optional[str] = None,
    hostcategory: Optional[str] = None,
    servicecategory: Optional[str] = None,
) -> dict[str, Any]:
    """Create a new HBAC rule.

    Args:
        cn: Rule name
        description: Rule description
        usercategory: 'all' to apply to all users
        hostcategory: 'all' to apply to all hosts
        servicecategory: 'all' to apply to all services
    """
    return hbac.hbacrule_add(
        cn=cn, description=description,
        usercategory=usercategory, hostcategory=hostcategory, servicecategory=servicecategory
    )


@mcp.tool()
def hbacrule_enable(cn: str) -> dict[str, Any]:
    """Enable an HBAC rule.

    Args:
        cn: Rule name to enable
    """
    return hbac.hbacrule_enable(cn)


@mcp.tool()
def hbacrule_disable(cn: str) -> dict[str, Any]:
    """Disable an HBAC rule.

    Args:
        cn: Rule name to disable
    """
    return hbac.hbacrule_disable(cn)


@mcp.tool()
def hbacrule_add_user(
    cn: str,
    users: Optional[list[str]] = None,
    groups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add users/groups to an HBAC rule.

    Args:
        cn: Rule name
        users: List of usernames
        groups: List of group names
    """
    return hbac.hbacrule_add_user(cn=cn, users=users, groups=groups)


@mcp.tool()
def hbacrule_add_host(
    cn: str,
    hosts: Optional[list[str]] = None,
    hostgroups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add hosts/hostgroups to an HBAC rule.

    Args:
        cn: Rule name
        hosts: List of host FQDNs
        hostgroups: List of hostgroup names
    """
    return hbac.hbacrule_add_host(cn=cn, hosts=hosts, hostgroups=hostgroups)


# =============================================================================
# Sudo Rule Tools
# =============================================================================


@mcp.tool()
def sudorule_find(
    cn: Optional[str] = None,
    enabled: Optional[bool] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for sudo rules.

    Args:
        cn: Rule name pattern (supports wildcards *)
        enabled: Filter by enabled status
        limit: Maximum results to return
    """
    return sudo.sudorule_find(cn=cn, enabled=enabled, limit=limit)


@mcp.tool()
def sudorule_show(cn: str) -> dict[str, Any]:
    """Get sudo rule details.

    Args:
        cn: Rule name
    """
    return sudo.sudorule_show(cn)


@mcp.tool()
def sudorule_add(
    cn: str,
    description: Optional[str] = None,
    usercategory: Optional[str] = None,
    hostcategory: Optional[str] = None,
    cmdcategory: Optional[str] = None,
) -> dict[str, Any]:
    """Create a new sudo rule.

    Args:
        cn: Rule name
        description: Rule description
        usercategory: 'all' to apply to all users
        hostcategory: 'all' to apply to all hosts
        cmdcategory: 'all' to allow all commands
    """
    return sudo.sudorule_add(
        cn=cn, description=description,
        usercategory=usercategory, hostcategory=hostcategory, cmdcategory=cmdcategory
    )


@mcp.tool()
def sudorule_enable(cn: str) -> dict[str, Any]:
    """Enable a sudo rule.

    Args:
        cn: Rule name to enable
    """
    return sudo.sudorule_enable(cn)


@mcp.tool()
def sudorule_disable(cn: str) -> dict[str, Any]:
    """Disable a sudo rule.

    Args:
        cn: Rule name to disable
    """
    return sudo.sudorule_disable(cn)


@mcp.tool()
def sudorule_add_user(
    cn: str,
    users: Optional[list[str]] = None,
    groups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add users/groups to a sudo rule.

    Args:
        cn: Rule name
        users: List of usernames
        groups: List of group names
    """
    return sudo.sudorule_add_user(cn=cn, users=users, groups=groups)


@mcp.tool()
def sudorule_add_host(
    cn: str,
    hosts: Optional[list[str]] = None,
    hostgroups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add hosts/hostgroups to a sudo rule.

    Args:
        cn: Rule name
        hosts: List of host FQDNs
        hostgroups: List of hostgroup names
    """
    return sudo.sudorule_add_host(cn=cn, hosts=hosts, hostgroups=hostgroups)


@mcp.tool()
def sudorule_add_allow_command(
    cn: str,
    sudocmds: Optional[list[str]] = None,
    sudocmdgroups: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Add allowed commands to a sudo rule.

    Args:
        cn: Rule name
        sudocmds: List of command paths (e.g., '/usr/bin/systemctl')
        sudocmdgroups: List of sudo command group names
    """
    return sudo.sudorule_add_allow_command(cn=cn, sudocmds=sudocmds, sudocmdgroups=sudocmdgroups)


@mcp.tool()
def sudorule_add_option(cn: str, ipasudoopt: str) -> dict[str, Any]:
    """Add a sudo option to a rule.

    Args:
        cn: Rule name
        ipasudoopt: Sudo option (e.g., '!authenticate', 'env_keep+=SSH_AUTH_SOCK')
    """
    return sudo.sudorule_add_option(cn=cn, ipasudoopt=ipasudoopt)


# =============================================================================
# Certificate Tools
# =============================================================================


@mcp.tool()
def cert_find(
    user: Optional[str] = None,
    host: Optional[str] = None,
    validnotafter_to: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict[str, Any]:
    """Search for certificates.

    Args:
        user: Find certificates for this user
        host: Find certificates for this host
        validnotafter_to: Find certs expiring before this date (YYYY-MM-DD)
        limit: Maximum results to return
    """
    return certs.cert_find(user=user, host=host, validnotafter_to=validnotafter_to, limit=limit)


@mcp.tool()
def user_add_cert(uid: str, certificate: str) -> dict[str, Any]:
    """Add a certificate to a user.

    Args:
        uid: Username
        certificate: Base64-encoded certificate (PEM without headers)
    """
    return certs.user_add_cert(uid=uid, certificate=certificate)


@mcp.tool()
def host_add_cert(fqdn: str, certificate: str) -> dict[str, Any]:
    """Add a certificate to a host.

    Args:
        fqdn: Host FQDN
        certificate: Base64-encoded certificate (PEM without headers)
    """
    return certs.host_add_cert(fqdn=fqdn, certificate=certificate)


def run_server():
    """Run the FreeIPA MCP server."""
    # Validate configuration on startup
    valid, message = validate_settings()
    if not valid:
        logger.error(f"Configuration error: {message}")
        logger.error("Please set FREEIPA_SERVER, FREEIPA_USERNAME, and FREEIPA_PASSWORD")
        raise SystemExit(1)

    logger.info(f"Starting FreeIPA MCP Server - {message}")
    mcp.run()
