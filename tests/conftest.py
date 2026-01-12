"""Pytest fixtures for FreeIPA MCP Server tests."""

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_settings():
    """Mock FreeIPA settings."""
    with patch("freeipa_mcp.config.FreeIPASettings") as mock:
        settings = MagicMock()
        settings.server = "ipa.test.local"
        settings.username = "admin"
        settings.password = "testpass"
        settings.verify_ssl = True
        settings.api_version = "2.230"
        settings.default_limit = 100
        settings.request_timeout = 30
        mock.return_value = settings
        yield settings


@pytest.fixture
def mock_client():
    """Mock FreeIPA client for testing tools without real API calls."""
    with patch("freeipa_mcp.client.FreeIPAClient") as mock_cls:
        client = MagicMock()
        client._authenticated = True
        mock_cls.return_value = client
        yield client


@pytest.fixture
def mock_get_settings():
    """Mock get_settings to return test settings."""
    settings = MagicMock()
    settings.server = "ipa.test.local"
    settings.username = "admin"
    settings.password = "testpass"
    settings.verify_ssl = True
    settings.api_version = "2.230"
    settings.default_limit = 100
    settings.request_timeout = 30

    with patch("freeipa_mcp.tools.users.get_settings", return_value=settings):
        with patch("freeipa_mcp.tools.groups.get_settings", return_value=settings):
            with patch("freeipa_mcp.tools.hosts.get_settings", return_value=settings):
                with patch("freeipa_mcp.tools.dns.get_settings", return_value=settings):
                    with patch("freeipa_mcp.tools.hbac.get_settings", return_value=settings):
                        with patch("freeipa_mcp.tools.sudo.get_settings", return_value=settings):
                            yield settings


@pytest.fixture
def mock_get_client(mock_client, mock_get_settings):
    """Patch get_client to return our mock."""
    with patch("freeipa_mcp.tools.users.get_client", return_value=mock_client):
        with patch("freeipa_mcp.tools.groups.get_client", return_value=mock_client):
            with patch("freeipa_mcp.tools.hosts.get_client", return_value=mock_client):
                with patch("freeipa_mcp.tools.dns.get_client", return_value=mock_client):
                    with patch("freeipa_mcp.tools.hbac.get_client", return_value=mock_client):
                        with patch("freeipa_mcp.tools.sudo.get_client", return_value=mock_client):
                            with patch("freeipa_mcp.tools.certs.get_client", return_value=mock_client):
                                yield mock_client


# Sample FreeIPA API response data

@pytest.fixture
def sample_user():
    """Sample user data as returned by FreeIPA API."""
    return {
        "uid": ["jsmith"],
        "givenname": ["John"],
        "sn": ["Smith"],
        "cn": ["John Smith"],
        "displayname": ["John Smith"],
        "mail": ["jsmith@example.com"],
        "uidnumber": [10001],
        "gidnumber": [10001],
        "homedirectory": ["/home/jsmith"],
        "loginshell": ["/bin/bash"],
        "nsaccountlock": [False],
        "memberof_group": ["developers", "users"],
        "krbprincipalname": ["jsmith@EXAMPLE.COM"],
    }


@pytest.fixture
def sample_user_list(sample_user):
    """Sample user list response."""
    return {
        "count": 1,
        "truncated": False,
        "result": [sample_user],
    }


@pytest.fixture
def sample_group():
    """Sample group data as returned by FreeIPA API."""
    return {
        "cn": ["developers"],
        "description": ["Development team"],
        "gidnumber": [20001],
        "member_user": ["jsmith", "jdoe"],
        "member_group": [],
        "memberof_group": [],
    }


@pytest.fixture
def sample_group_list(sample_group):
    """Sample group list response."""
    return {
        "count": 1,
        "truncated": False,
        "result": [sample_group],
    }


@pytest.fixture
def sample_host():
    """Sample host data as returned by FreeIPA API."""
    return {
        "fqdn": ["server01.example.com"],
        "description": ["Web server"],
        "l": ["New York"],
        "nshostlocation": ["Rack A1"],
        "nshardwareplatform": ["x86_64"],
        "nsosversion": ["RHEL 8.5"],
        "krbprincipalname": ["host/server01.example.com@EXAMPLE.COM"],
        "managedby_host": [],
        "memberof_hostgroup": ["webservers"],
        "has_keytab": True,
        "has_password": False,
    }


@pytest.fixture
def sample_host_list(sample_host):
    """Sample host list response."""
    return {
        "count": 1,
        "truncated": False,
        "result": [sample_host],
    }


@pytest.fixture
def sample_hbacrule():
    """Sample HBAC rule data."""
    return {
        "cn": ["allow_developers_ssh"],
        "description": ["Allow developers SSH access"],
        "ipaenabledflag": [True],
        "accessruletype": ["allow"],
        "usercategory": None,
        "hostcategory": None,
        "servicecategory": None,
        "memberuser_user": ["jsmith"],
        "memberuser_group": ["developers"],
        "memberhost_host": [],
        "memberhost_hostgroup": ["webservers"],
        "memberservice_hbacsvc": ["sshd"],
        "memberservice_hbacsvcgroup": [],
    }


@pytest.fixture
def sample_sudorule():
    """Sample sudo rule data."""
    return {
        "cn": ["developers_sudo"],
        "description": ["Sudo access for developers"],
        "ipaenabledflag": [True],
        "usercategory": None,
        "hostcategory": None,
        "cmdcategory": None,
        "memberuser_user": [],
        "memberuser_group": ["developers"],
        "memberhost_host": [],
        "memberhost_hostgroup": ["webservers"],
        "memberallowcmd_sudocmd": ["/usr/bin/systemctl"],
        "memberallowcmd_sudocmdgroup": [],
        "ipasudoopt": ["!authenticate"],
        "sudoorder": [10],
    }
