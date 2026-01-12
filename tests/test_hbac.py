"""Tests for HBAC rule management tools."""

import pytest
from unittest.mock import MagicMock

from freeipa_mcp.tools import hbac
from freeipa_mcp.client import ObjectNotFoundError, ObjectExistsError, FreeIPAClientError


@pytest.fixture
def sample_hbacrule():
    """Sample HBAC rule data."""
    return {
        "cn": ["allow_ssh"],
        "description": ["Allow SSH access"],
        "ipaenabledflag": [True],
        "accessruletype": ["allow"],
        "usercategory": None,
        "hostcategory": None,
        "servicecategory": None,
        "memberuser_user": ["jsmith"],
        "memberuser_group": ["developers"],
        "memberhost_host": ["server01.example.com"],
        "memberhost_hostgroup": ["webservers"],
        "memberservice_hbacsvc": ["sshd"],
        "memberservice_hbacsvcgroup": [],
    }


@pytest.fixture
def sample_hbacrule_list(sample_hbacrule):
    """Sample HBAC rule list response."""
    return {
        "count": 1,
        "truncated": False,
        "result": [sample_hbacrule],
    }


class TestHbacruleFind:
    """Tests for hbacrule_find function."""

    def test_hbacrule_find_all(self, mock_get_client, sample_hbacrule_list):
        """Test finding all HBAC rules."""
        mock_get_client.execute.return_value = sample_hbacrule_list

        result = hbac.hbacrule_find()

        assert result["success"] is True
        assert result["count"] == 1
        assert result["rules"][0]["cn"] == "allow_ssh"

    def test_hbacrule_find_by_name(self, mock_get_client, sample_hbacrule_list):
        """Test finding rule by name."""
        mock_get_client.execute.return_value = sample_hbacrule_list

        result = hbac.hbacrule_find(cn="allow*")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["cn"] == "allow*"

    def test_hbacrule_find_enabled_only(self, mock_get_client, sample_hbacrule_list):
        """Test finding only enabled rules."""
        mock_get_client.execute.return_value = sample_hbacrule_list

        result = hbac.hbacrule_find(enabled=True)

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["ipaenabledflag"] is True

    def test_hbacrule_find_disabled_only(self, mock_get_client):
        """Test finding only disabled rules."""
        mock_get_client.execute.return_value = {"count": 0, "result": []}

        result = hbac.hbacrule_find(enabled=False)

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["ipaenabledflag"] is False

    def test_hbacrule_find_with_limit(self, mock_get_client, sample_hbacrule_list):
        """Test finding rules with limit."""
        mock_get_client.execute.return_value = sample_hbacrule_list

        result = hbac.hbacrule_find(limit=25)

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["sizelimit"] == 25

    def test_hbacrule_find_error(self, mock_get_client):
        """Test hbacrule_find handles errors."""
        mock_get_client.execute.side_effect = FreeIPAClientError("Error", "ERR")

        result = hbac.hbacrule_find()

        assert result["success"] is False
        assert result["code"] == "ERR"


class TestHbacruleShow:
    """Tests for hbacrule_show function."""

    def test_hbacrule_show_success(self, mock_get_client, sample_hbacrule):
        """Test showing rule details."""
        mock_get_client.execute.return_value = {"result": sample_hbacrule}

        result = hbac.hbacrule_show("allow_ssh")

        assert result["success"] is True
        assert result["rule"]["cn"] == "allow_ssh"
        assert result["rule"]["ipaenabledflag"] is True
        assert "jsmith" in result["rule"]["memberuser_user"]

    def test_hbacrule_show_not_found(self, mock_get_client):
        """Test showing non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = hbac.hbacrule_show("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestHbacruleAdd:
    """Tests for hbacrule_add function."""

    def test_hbacrule_add_minimal(self, mock_get_client, sample_hbacrule):
        """Test creating rule with minimal fields."""
        mock_get_client.execute.return_value = {"result": sample_hbacrule}

        result = hbac.hbacrule_add(cn="allow_ssh")

        assert result["success"] is True
        assert "created successfully" in result["message"]

    def test_hbacrule_add_with_description(self, mock_get_client, sample_hbacrule):
        """Test creating rule with description."""
        mock_get_client.execute.return_value = {"result": sample_hbacrule}

        result = hbac.hbacrule_add(cn="allow_ssh", description="Allow SSH access")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["description"] == "Allow SSH access"

    def test_hbacrule_add_all_users(self, mock_get_client, sample_hbacrule):
        """Test creating rule for all users."""
        mock_get_client.execute.return_value = {"result": sample_hbacrule}

        result = hbac.hbacrule_add(cn="allow_all", usercategory="all")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["usercategory"] == "all"

    def test_hbacrule_add_all_hosts(self, mock_get_client, sample_hbacrule):
        """Test creating rule for all hosts."""
        mock_get_client.execute.return_value = {"result": sample_hbacrule}

        result = hbac.hbacrule_add(cn="allow_all", hostcategory="all")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["hostcategory"] == "all"

    def test_hbacrule_add_all_services(self, mock_get_client, sample_hbacrule):
        """Test creating rule for all services."""
        mock_get_client.execute.return_value = {"result": sample_hbacrule}

        result = hbac.hbacrule_add(cn="allow_all", servicecategory="all")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["servicecategory"] == "all"

    def test_hbacrule_add_duplicate(self, mock_get_client):
        """Test creating duplicate rule."""
        mock_get_client.execute.side_effect = ObjectExistsError("Exists", "DUPLICATE_ENTRY")

        result = hbac.hbacrule_add(cn="allow_ssh")

        assert result["success"] is False
        assert result["code"] == "DUPLICATE_ENTRY"


class TestHbacruleMod:
    """Tests for hbacrule_mod function."""

    def test_hbacrule_mod_description(self, mock_get_client, sample_hbacrule):
        """Test modifying rule description."""
        mock_get_client.execute.return_value = {"result": sample_hbacrule}

        result = hbac.hbacrule_mod(cn="allow_ssh", description="New description")

        assert result["success"] is True
        assert "modified successfully" in result["message"]

    def test_hbacrule_mod_categories(self, mock_get_client, sample_hbacrule):
        """Test modifying rule categories."""
        mock_get_client.execute.return_value = {"result": sample_hbacrule}

        result = hbac.hbacrule_mod(cn="allow_ssh", usercategory="all", hostcategory="all")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["usercategory"] == "all"
        assert call_args[1]["hostcategory"] == "all"

    def test_hbacrule_mod_no_changes(self, mock_get_client):
        """Test modifying with no changes."""
        result = hbac.hbacrule_mod(cn="allow_ssh")

        assert result["success"] is False
        assert result["code"] == "NO_CHANGES"

    def test_hbacrule_mod_not_found(self, mock_get_client):
        """Test modifying non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = hbac.hbacrule_mod(cn="nonexistent", description="test")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestHbacruleDel:
    """Tests for hbacrule_del function."""

    def test_hbacrule_del_success(self, mock_get_client):
        """Test deleting rule."""
        mock_get_client.execute.return_value = {}

        result = hbac.hbacrule_del("allow_ssh")

        assert result["success"] is True
        assert "deleted successfully" in result["message"]

    def test_hbacrule_del_not_found(self, mock_get_client):
        """Test deleting non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = hbac.hbacrule_del("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestHbacruleEnable:
    """Tests for hbacrule_enable function."""

    def test_hbacrule_enable_success(self, mock_get_client):
        """Test enabling rule."""
        mock_get_client.execute.return_value = {}

        result = hbac.hbacrule_enable("allow_ssh")

        assert result["success"] is True
        assert "enabled successfully" in result["message"]

    def test_hbacrule_enable_not_found(self, mock_get_client):
        """Test enabling non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = hbac.hbacrule_enable("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestHbacruleDisable:
    """Tests for hbacrule_disable function."""

    def test_hbacrule_disable_success(self, mock_get_client):
        """Test disabling rule."""
        mock_get_client.execute.return_value = {}

        result = hbac.hbacrule_disable("allow_ssh")

        assert result["success"] is True
        assert "disabled successfully" in result["message"]

    def test_hbacrule_disable_not_found(self, mock_get_client):
        """Test disabling non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = hbac.hbacrule_disable("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestHbacruleAddUser:
    """Tests for hbacrule_add_user function."""

    def test_hbacrule_add_user_users(self, mock_get_client):
        """Test adding users to rule."""
        mock_get_client.execute.return_value = {"failed": {"memberuser": {}}}

        result = hbac.hbacrule_add_user(cn="allow_ssh", users=["jsmith", "jdoe"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["user"] == ["jsmith", "jdoe"]

    def test_hbacrule_add_user_groups(self, mock_get_client):
        """Test adding groups to rule."""
        mock_get_client.execute.return_value = {"failed": {"memberuser": {}}}

        result = hbac.hbacrule_add_user(cn="allow_ssh", groups=["developers"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["group"] == ["developers"]

    def test_hbacrule_add_user_no_members(self, mock_get_client):
        """Test adding no members."""
        result = hbac.hbacrule_add_user(cn="allow_ssh")

        assert result["success"] is False
        assert result["code"] == "NO_MEMBERS"

    def test_hbacrule_add_user_not_found(self, mock_get_client):
        """Test adding users to non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = hbac.hbacrule_add_user(cn="nonexistent", users=["jsmith"])

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"

    def test_hbacrule_add_user_category_conflict(self, mock_get_client):
        """Test category conflict when adding users."""
        mock_get_client.execute.side_effect = FreeIPAClientError(
            "category all", "CATEGORY_ERROR"
        )

        result = hbac.hbacrule_add_user(cn="allow_all", users=["jsmith"])

        assert result["success"] is False
        assert result["code"] == "CATEGORY_CONFLICT"

    def test_hbacrule_add_user_with_warnings(self, mock_get_client):
        """Test adding users with partial failures."""
        mock_get_client.execute.return_value = {
            "failed": {"memberuser": {"user": [["baduser", "not found"]]}}
        }

        result = hbac.hbacrule_add_user(cn="allow_ssh", users=["jsmith", "baduser"])

        assert result["success"] is True
        assert "warnings" in result


class TestHbacruleAddHost:
    """Tests for hbacrule_add_host function."""

    def test_hbacrule_add_host_hosts(self, mock_get_client):
        """Test adding hosts to rule."""
        mock_get_client.execute.return_value = {"failed": {"memberhost": {}}}

        result = hbac.hbacrule_add_host(cn="allow_ssh", hosts=["server01.example.com"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["host"] == ["server01.example.com"]

    def test_hbacrule_add_host_hostgroups(self, mock_get_client):
        """Test adding hostgroups to rule."""
        mock_get_client.execute.return_value = {"failed": {"memberhost": {}}}

        result = hbac.hbacrule_add_host(cn="allow_ssh", hostgroups=["webservers"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["hostgroup"] == ["webservers"]

    def test_hbacrule_add_host_no_members(self, mock_get_client):
        """Test adding no hosts."""
        result = hbac.hbacrule_add_host(cn="allow_ssh")

        assert result["success"] is False
        assert result["code"] == "NO_MEMBERS"

    def test_hbacrule_add_host_category_conflict(self, mock_get_client):
        """Test category conflict when adding hosts."""
        mock_get_client.execute.side_effect = FreeIPAClientError(
            "category all", "CATEGORY_ERROR"
        )

        result = hbac.hbacrule_add_host(cn="allow_all", hosts=["server01.example.com"])

        assert result["success"] is False
        assert result["code"] == "CATEGORY_CONFLICT"


class TestHbacruleAddService:
    """Tests for hbacrule_add_service function."""

    def test_hbacrule_add_service_services(self, mock_get_client):
        """Test adding services to rule."""
        mock_get_client.execute.return_value = {"failed": {"memberservice": {}}}

        result = hbac.hbacrule_add_service(cn="allow_ssh", hbacsvcs=["sshd", "login"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["hbacsvc"] == ["sshd", "login"]

    def test_hbacrule_add_service_groups(self, mock_get_client):
        """Test adding service groups to rule."""
        mock_get_client.execute.return_value = {"failed": {"memberservice": {}}}

        result = hbac.hbacrule_add_service(cn="allow_ssh", hbacsvcgroups=["Sudo"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["hbacsvcgroup"] == ["Sudo"]

    def test_hbacrule_add_service_no_services(self, mock_get_client):
        """Test adding no services."""
        result = hbac.hbacrule_add_service(cn="allow_ssh")

        assert result["success"] is False
        assert result["code"] == "NO_MEMBERS"

    def test_hbacrule_add_service_category_conflict(self, mock_get_client):
        """Test category conflict when adding services."""
        mock_get_client.execute.side_effect = FreeIPAClientError(
            "category all", "CATEGORY_ERROR"
        )

        result = hbac.hbacrule_add_service(cn="allow_all", hbacsvcs=["sshd"])

        assert result["success"] is False
        assert result["code"] == "CATEGORY_CONFLICT"


class TestFormatHbacrule:
    """Tests for _format_hbacrule helper."""

    def test_format_hbacrule_extracts_values(self, sample_hbacrule):
        """Test HBAC rule formatting."""
        formatted = hbac._format_hbacrule(sample_hbacrule)

        assert formatted["cn"] == "allow_ssh"
        assert formatted["ipaenabledflag"] is True
        assert "jsmith" in formatted["memberuser_user"]
        assert "developers" in formatted["memberuser_group"]
        assert "sshd" in formatted["memberservice_hbacsvc"]
