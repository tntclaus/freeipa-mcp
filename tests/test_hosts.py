"""Tests for host management tools."""

import pytest
from unittest.mock import MagicMock

from freeipa_mcp.tools import hosts
from freeipa_mcp.client import ObjectNotFoundError, ObjectExistsError, FreeIPAClientError


class TestHostFind:
    """Tests for host_find function."""

    def test_host_find_all(self, mock_get_client, sample_host_list):
        """Test finding all hosts."""
        mock_get_client.host_find.return_value = sample_host_list

        result = hosts.host_find()

        assert result["success"] is True
        assert result["count"] == 1
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["fqdn"] == "server01.example.com"

    def test_host_find_by_fqdn(self, mock_get_client, sample_host_list):
        """Test finding host by FQDN pattern."""
        mock_get_client.host_find.return_value = sample_host_list

        result = hosts.host_find(fqdn="server*.example.com")

        assert result["success"] is True
        call_kwargs = mock_get_client.host_find.call_args[1]
        assert call_kwargs["fqdn"] == "server*.example.com"

    def test_host_find_by_hostgroup(self, mock_get_client, sample_host_list):
        """Test finding hosts in a hostgroup."""
        mock_get_client.host_find.return_value = sample_host_list

        result = hosts.host_find(in_hostgroup="webservers")

        call_kwargs = mock_get_client.host_find.call_args[1]
        assert call_kwargs["in_hostgroup"] == "webservers"

    def test_host_find_with_limit(self, mock_get_client, sample_host_list):
        """Test finding hosts with limit."""
        mock_get_client.host_find.return_value = sample_host_list

        result = hosts.host_find(limit=25)

        call_kwargs = mock_get_client.host_find.call_args[1]
        assert call_kwargs["sizelimit"] == 25

    def test_host_find_error(self, mock_get_client):
        """Test host_find handles errors gracefully."""
        mock_get_client.host_find.side_effect = FreeIPAClientError("Connection failed", "CONN_ERROR")

        result = hosts.host_find()

        assert result["success"] is False
        assert result["code"] == "CONN_ERROR"


class TestHostShow:
    """Tests for host_show function."""

    def test_host_show_success(self, mock_get_client, sample_host):
        """Test showing host details."""
        mock_get_client.host_show.return_value = {"result": sample_host}

        result = hosts.host_show("server01.example.com")

        assert result["success"] is True
        assert result["host"]["fqdn"] == "server01.example.com"
        assert result["host"]["description"] == "Web server"
        assert result["host"]["os"] == "RHEL 8.5"

    def test_host_show_not_found(self, mock_get_client):
        """Test host_show when host doesn't exist."""
        mock_get_client.host_show.side_effect = ObjectNotFoundError("Host not found", "NOT_FOUND")

        result = hosts.host_show("nonexistent.example.com")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestHostAdd:
    """Tests for host_add function."""

    def test_host_add_minimal(self, mock_get_client, sample_host):
        """Test creating host with minimal fields."""
        mock_get_client.host_add.return_value = {"result": sample_host}

        result = hosts.host_add(fqdn="server01.example.com")

        assert result["success"] is True
        assert "created successfully" in result["message"]

    def test_host_add_with_ip(self, mock_get_client, sample_host):
        """Test creating host with IP address."""
        mock_get_client.host_add.return_value = {"result": sample_host}

        result = hosts.host_add(fqdn="server01.example.com", ip_address="192.168.1.100")

        call_kwargs = mock_get_client.host_add.call_args[1]
        assert call_kwargs["ip_address"] == "192.168.1.100"

    def test_host_add_with_otp(self, mock_get_client, sample_host):
        """Test creating host with random OTP."""
        host_with_otp = sample_host.copy()
        host_with_otp["randompassword"] = "abc123xyz"
        mock_get_client.host_add.return_value = {"result": host_with_otp}

        result = hosts.host_add(fqdn="server01.example.com", random_password=True)

        assert result["success"] is True
        assert result["otp"] == "abc123xyz"
        call_kwargs = mock_get_client.host_add.call_args[1]
        assert call_kwargs["random"] is True

    def test_host_add_force(self, mock_get_client, sample_host):
        """Test creating host with force flag."""
        mock_get_client.host_add.return_value = {"result": sample_host}

        result = hosts.host_add(fqdn="server01.example.com", force=True)

        call_kwargs = mock_get_client.host_add.call_args[1]
        assert call_kwargs["force"] is True

    def test_host_add_duplicate(self, mock_get_client):
        """Test creating host that already exists."""
        mock_get_client.host_add.side_effect = ObjectExistsError("Host exists", "DUPLICATE_ENTRY")

        result = hosts.host_add(fqdn="server01.example.com")

        assert result["success"] is False
        assert result["code"] == "DUPLICATE_ENTRY"


class TestHostMod:
    """Tests for host_mod function."""

    def test_host_mod_success(self, mock_get_client, sample_host):
        """Test modifying host."""
        mock_get_client.host_mod.return_value = {"result": sample_host}

        result = hosts.host_mod(fqdn="server01.example.com", description="Updated")

        assert result["success"] is True
        assert "modified successfully" in result["message"]

    def test_host_mod_no_changes(self, mock_get_client):
        """Test host_mod with no changes."""
        result = hosts.host_mod(fqdn="server01.example.com")

        assert result["success"] is False
        assert result["code"] == "NO_CHANGES"

    def test_host_mod_not_found(self, mock_get_client):
        """Test modifying non-existent host."""
        mock_get_client.host_mod.side_effect = ObjectNotFoundError("Host not found", "NOT_FOUND")

        result = hosts.host_mod(fqdn="nonexistent.example.com", description="test")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestHostDel:
    """Tests for host_del function."""

    def test_host_del_success(self, mock_get_client):
        """Test deleting host."""
        mock_get_client.host_del.return_value = {}

        result = hosts.host_del("server01.example.com")

        assert result["success"] is True
        assert "deleted successfully" in result["message"]

    def test_host_del_with_dns(self, mock_get_client):
        """Test deleting host with DNS cleanup."""
        mock_get_client.host_del.return_value = {}

        result = hosts.host_del("server01.example.com", updatedns=True)

        call_kwargs = mock_get_client.host_del.call_args[1]
        assert call_kwargs["updatedns"] is True

    def test_host_del_not_found(self, mock_get_client):
        """Test deleting non-existent host."""
        mock_get_client.host_del.side_effect = ObjectNotFoundError("Host not found", "NOT_FOUND")

        result = hosts.host_del("nonexistent.example.com")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestHostDisable:
    """Tests for host_disable function."""

    def test_host_disable_success(self, mock_get_client):
        """Test disabling host."""
        mock_get_client.execute.return_value = {}

        result = hosts.host_disable("server01.example.com")

        assert result["success"] is True
        assert "disabled successfully" in result["message"]

    def test_host_disable_not_found(self, mock_get_client):
        """Test disabling non-existent host."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Host not found", "NOT_FOUND")

        result = hosts.host_disable("nonexistent.example.com")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestHostgroupFind:
    """Tests for hostgroup_find function."""

    def test_hostgroup_find_success(self, mock_get_client):
        """Test finding hostgroups."""
        mock_get_client.execute.return_value = {
            "count": 1,
            "result": [{"cn": ["webservers"], "description": ["Web servers"], "member_host": ["server01.example.com"]}],
        }

        result = hosts.hostgroup_find()

        assert result["success"] is True
        assert result["count"] == 1
        assert result["hostgroups"][0]["cn"] == "webservers"


class TestFormatHost:
    """Tests for _format_host helper function."""

    def test_format_host_extracts_values(self, sample_host):
        """Test that host data is properly formatted."""
        formatted = hosts._format_host(sample_host)

        assert formatted["fqdn"] == "server01.example.com"
        assert formatted["description"] == "Web server"
        assert formatted["os"] == "RHEL 8.5"
        assert formatted["has_keytab"] is True
        assert isinstance(formatted["memberof_hostgroup"], list)
