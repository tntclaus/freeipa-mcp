"""Tests for sudo rule management tools."""

import pytest
from unittest.mock import MagicMock

from freeipa_mcp.tools import sudo
from freeipa_mcp.client import ObjectNotFoundError, ObjectExistsError, FreeIPAClientError


@pytest.fixture
def sample_sudorule():
    """Sample sudo rule data."""
    return {
        "cn": ["developers_sudo"],
        "description": ["Sudo for developers"],
        "ipaenabledflag": [True],
        "usercategory": None,
        "hostcategory": None,
        "cmdcategory": None,
        "ipasudorunasusercategory": None,
        "ipasudorunasgroupcategory": None,
        "memberuser_user": ["jsmith"],
        "memberuser_group": ["developers"],
        "memberhost_host": ["server01.example.com"],
        "memberhost_hostgroup": ["webservers"],
        "memberallowcmd_sudocmd": ["/usr/bin/systemctl"],
        "memberallowcmd_sudocmdgroup": [],
        "memberdenycmd_sudocmd": [],
        "memberdenycmd_sudocmdgroup": [],
        "ipasudoopt": ["!authenticate"],
        "ipasudorunasuser_user": ["root"],
        "ipasudorunasgroup_group": [],
        "sudoorder": [10],
    }


@pytest.fixture
def sample_sudorule_list(sample_sudorule):
    """Sample sudo rule list response."""
    return {
        "count": 1,
        "truncated": False,
        "result": [sample_sudorule],
    }


class TestSudoruleFind:
    """Tests for sudorule_find function."""

    def test_sudorule_find_all(self, mock_get_client, sample_sudorule_list):
        """Test finding all sudo rules."""
        mock_get_client.execute.return_value = sample_sudorule_list

        result = sudo.sudorule_find()

        assert result["success"] is True
        assert result["count"] == 1
        assert result["rules"][0]["cn"] == "developers_sudo"

    def test_sudorule_find_by_name(self, mock_get_client, sample_sudorule_list):
        """Test finding rule by name."""
        mock_get_client.execute.return_value = sample_sudorule_list

        result = sudo.sudorule_find(cn="dev*")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["cn"] == "dev*"

    def test_sudorule_find_enabled_only(self, mock_get_client, sample_sudorule_list):
        """Test finding only enabled rules."""
        mock_get_client.execute.return_value = sample_sudorule_list

        result = sudo.sudorule_find(enabled=True)

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["ipaenabledflag"] is True

    def test_sudorule_find_with_limit(self, mock_get_client, sample_sudorule_list):
        """Test finding rules with limit."""
        mock_get_client.execute.return_value = sample_sudorule_list

        result = sudo.sudorule_find(limit=50)

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["sizelimit"] == 50

    def test_sudorule_find_error(self, mock_get_client):
        """Test sudorule_find handles errors."""
        mock_get_client.execute.side_effect = FreeIPAClientError("Error", "ERR")

        result = sudo.sudorule_find()

        assert result["success"] is False
        assert result["code"] == "ERR"


class TestSudoruleShow:
    """Tests for sudorule_show function."""

    def test_sudorule_show_success(self, mock_get_client, sample_sudorule):
        """Test showing rule details."""
        mock_get_client.execute.return_value = {"result": sample_sudorule}

        result = sudo.sudorule_show("developers_sudo")

        assert result["success"] is True
        assert result["rule"]["cn"] == "developers_sudo"
        assert result["rule"]["sudoorder"] == 10
        assert "!authenticate" in result["rule"]["ipasudoopt"]

    def test_sudorule_show_not_found(self, mock_get_client):
        """Test showing non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = sudo.sudorule_show("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestSudoruleAdd:
    """Tests for sudorule_add function."""

    def test_sudorule_add_minimal(self, mock_get_client, sample_sudorule):
        """Test creating rule with minimal fields."""
        mock_get_client.execute.return_value = {"result": sample_sudorule}

        result = sudo.sudorule_add(cn="developers_sudo")

        assert result["success"] is True
        assert "created successfully" in result["message"]

    def test_sudorule_add_with_description(self, mock_get_client, sample_sudorule):
        """Test creating rule with description."""
        mock_get_client.execute.return_value = {"result": sample_sudorule}

        result = sudo.sudorule_add(cn="developers_sudo", description="Sudo for devs")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["description"] == "Sudo for devs"

    def test_sudorule_add_all_users(self, mock_get_client, sample_sudorule):
        """Test creating rule for all users."""
        mock_get_client.execute.return_value = {"result": sample_sudorule}

        result = sudo.sudorule_add(cn="sudo_all", usercategory="all")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["usercategory"] == "all"

    def test_sudorule_add_all_hosts(self, mock_get_client, sample_sudorule):
        """Test creating rule for all hosts."""
        mock_get_client.execute.return_value = {"result": sample_sudorule}

        result = sudo.sudorule_add(cn="sudo_all", hostcategory="all")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["hostcategory"] == "all"

    def test_sudorule_add_all_commands(self, mock_get_client, sample_sudorule):
        """Test creating rule for all commands."""
        mock_get_client.execute.return_value = {"result": sample_sudorule}

        result = sudo.sudorule_add(cn="sudo_all", cmdcategory="all")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["cmdcategory"] == "all"

    def test_sudorule_add_with_order(self, mock_get_client, sample_sudorule):
        """Test creating rule with sudo order."""
        mock_get_client.execute.return_value = {"result": sample_sudorule}

        result = sudo.sudorule_add(cn="sudo_priority", sudoorder=5)

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["sudoorder"] == 5

    def test_sudorule_add_runas_categories(self, mock_get_client, sample_sudorule):
        """Test creating rule with run-as categories."""
        mock_get_client.execute.return_value = {"result": sample_sudorule}

        result = sudo.sudorule_add(
            cn="sudo_runas",
            runasusercategory="all",
            runasgroupcategory="all"
        )

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["ipasudorunasusercategory"] == "all"
        assert call_args[1]["ipasudorunasgroupcategory"] == "all"

    def test_sudorule_add_duplicate(self, mock_get_client):
        """Test creating duplicate rule."""
        mock_get_client.execute.side_effect = ObjectExistsError("Exists", "DUPLICATE_ENTRY")

        result = sudo.sudorule_add(cn="developers_sudo")

        assert result["success"] is False
        assert result["code"] == "DUPLICATE_ENTRY"


class TestSudoruleMod:
    """Tests for sudorule_mod function."""

    def test_sudorule_mod_description(self, mock_get_client, sample_sudorule):
        """Test modifying rule description."""
        mock_get_client.execute.return_value = {"result": sample_sudorule}

        result = sudo.sudorule_mod(cn="developers_sudo", description="New description")

        assert result["success"] is True
        assert "modified successfully" in result["message"]

    def test_sudorule_mod_categories(self, mock_get_client, sample_sudorule):
        """Test modifying rule categories."""
        mock_get_client.execute.return_value = {"result": sample_sudorule}

        result = sudo.sudorule_mod(cn="developers_sudo", usercategory="all")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["usercategory"] == "all"

    def test_sudorule_mod_order(self, mock_get_client, sample_sudorule):
        """Test modifying sudo order."""
        mock_get_client.execute.return_value = {"result": sample_sudorule}

        result = sudo.sudorule_mod(cn="developers_sudo", sudoorder=1)

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["sudoorder"] == 1

    def test_sudorule_mod_no_changes(self, mock_get_client):
        """Test modifying with no changes."""
        result = sudo.sudorule_mod(cn="developers_sudo")

        assert result["success"] is False
        assert result["code"] == "NO_CHANGES"

    def test_sudorule_mod_not_found(self, mock_get_client):
        """Test modifying non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = sudo.sudorule_mod(cn="nonexistent", description="test")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestSudoruleDel:
    """Tests for sudorule_del function."""

    def test_sudorule_del_success(self, mock_get_client):
        """Test deleting rule."""
        mock_get_client.execute.return_value = {}

        result = sudo.sudorule_del("developers_sudo")

        assert result["success"] is True
        assert "deleted successfully" in result["message"]

    def test_sudorule_del_not_found(self, mock_get_client):
        """Test deleting non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = sudo.sudorule_del("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestSudoruleEnable:
    """Tests for sudorule_enable function."""

    def test_sudorule_enable_success(self, mock_get_client):
        """Test enabling rule."""
        mock_get_client.execute.return_value = {}

        result = sudo.sudorule_enable("developers_sudo")

        assert result["success"] is True
        assert "enabled successfully" in result["message"]

    def test_sudorule_enable_not_found(self, mock_get_client):
        """Test enabling non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = sudo.sudorule_enable("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestSudoruleDisable:
    """Tests for sudorule_disable function."""

    def test_sudorule_disable_success(self, mock_get_client):
        """Test disabling rule."""
        mock_get_client.execute.return_value = {}

        result = sudo.sudorule_disable("developers_sudo")

        assert result["success"] is True
        assert "disabled successfully" in result["message"]

    def test_sudorule_disable_not_found(self, mock_get_client):
        """Test disabling non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = sudo.sudorule_disable("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestSudoruleAddUser:
    """Tests for sudorule_add_user function."""

    def test_sudorule_add_user_users(self, mock_get_client):
        """Test adding users to rule."""
        mock_get_client.execute.return_value = {"failed": {"memberuser": {}}}

        result = sudo.sudorule_add_user(cn="developers_sudo", users=["jsmith"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["user"] == ["jsmith"]

    def test_sudorule_add_user_groups(self, mock_get_client):
        """Test adding groups to rule."""
        mock_get_client.execute.return_value = {"failed": {"memberuser": {}}}

        result = sudo.sudorule_add_user(cn="developers_sudo", groups=["developers"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["group"] == ["developers"]

    def test_sudorule_add_user_no_members(self, mock_get_client):
        """Test adding no members."""
        result = sudo.sudorule_add_user(cn="developers_sudo")

        assert result["success"] is False
        assert result["code"] == "NO_MEMBERS"

    def test_sudorule_add_user_category_conflict(self, mock_get_client):
        """Test category conflict when adding users."""
        mock_get_client.execute.side_effect = FreeIPAClientError("category all", "ERR")

        result = sudo.sudorule_add_user(cn="sudo_all", users=["jsmith"])

        assert result["success"] is False
        assert result["code"] == "CATEGORY_CONFLICT"


class TestSudoruleAddHost:
    """Tests for sudorule_add_host function."""

    def test_sudorule_add_host_hosts(self, mock_get_client):
        """Test adding hosts to rule."""
        mock_get_client.execute.return_value = {"failed": {"memberhost": {}}}

        result = sudo.sudorule_add_host(cn="developers_sudo", hosts=["server01.example.com"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["host"] == ["server01.example.com"]

    def test_sudorule_add_host_hostgroups(self, mock_get_client):
        """Test adding hostgroups to rule."""
        mock_get_client.execute.return_value = {"failed": {"memberhost": {}}}

        result = sudo.sudorule_add_host(cn="developers_sudo", hostgroups=["webservers"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["hostgroup"] == ["webservers"]

    def test_sudorule_add_host_no_members(self, mock_get_client):
        """Test adding no hosts."""
        result = sudo.sudorule_add_host(cn="developers_sudo")

        assert result["success"] is False
        assert result["code"] == "NO_MEMBERS"

    def test_sudorule_add_host_category_conflict(self, mock_get_client):
        """Test category conflict when adding hosts."""
        mock_get_client.execute.side_effect = FreeIPAClientError("category all", "ERR")

        result = sudo.sudorule_add_host(cn="sudo_all", hosts=["server01.example.com"])

        assert result["success"] is False
        assert result["code"] == "CATEGORY_CONFLICT"


class TestSudoruleAddAllowCommand:
    """Tests for sudorule_add_allow_command function."""

    def test_sudorule_add_allow_command_cmds(self, mock_get_client):
        """Test adding allowed commands."""
        mock_get_client.execute.return_value = {"failed": {"memberallowcmd": {}}}

        result = sudo.sudorule_add_allow_command(
            cn="developers_sudo",
            sudocmds=["/usr/bin/systemctl", "/usr/bin/journalctl"]
        )

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["sudocmd"] == ["/usr/bin/systemctl", "/usr/bin/journalctl"]

    def test_sudorule_add_allow_command_groups(self, mock_get_client):
        """Test adding command groups."""
        mock_get_client.execute.return_value = {"failed": {"memberallowcmd": {}}}

        result = sudo.sudorule_add_allow_command(cn="developers_sudo", sudocmdgroups=["networking"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["sudocmdgroup"] == ["networking"]

    def test_sudorule_add_allow_command_no_commands(self, mock_get_client):
        """Test adding no commands."""
        result = sudo.sudorule_add_allow_command(cn="developers_sudo")

        assert result["success"] is False
        assert result["code"] == "NO_COMMANDS"

    def test_sudorule_add_allow_command_category_conflict(self, mock_get_client):
        """Test category conflict when adding commands."""
        mock_get_client.execute.side_effect = FreeIPAClientError("category all", "ERR")

        result = sudo.sudorule_add_allow_command(cn="sudo_all", sudocmds=["/bin/ls"])

        assert result["success"] is False
        assert result["code"] == "CATEGORY_CONFLICT"


class TestSudoruleAddOption:
    """Tests for sudorule_add_option function."""

    def test_sudorule_add_option_nopasswd(self, mock_get_client):
        """Test adding !authenticate option."""
        mock_get_client.execute.return_value = {}

        result = sudo.sudorule_add_option(cn="developers_sudo", ipasudoopt="!authenticate")

        assert result["success"] is True
        assert "!authenticate" in result["message"]

    def test_sudorule_add_option_env_keep(self, mock_get_client):
        """Test adding env_keep option."""
        mock_get_client.execute.return_value = {}

        result = sudo.sudorule_add_option(cn="developers_sudo", ipasudoopt="env_keep+=SSH_AUTH_SOCK")

        assert result["success"] is True

    def test_sudorule_add_option_not_found(self, mock_get_client):
        """Test adding option to non-existent rule."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = sudo.sudorule_add_option(cn="nonexistent", ipasudoopt="!authenticate")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestSudoruleAddRunasuser:
    """Tests for sudorule_add_runasuser function."""

    def test_sudorule_add_runasuser_users(self, mock_get_client):
        """Test adding run-as users."""
        mock_get_client.execute.return_value = {}

        result = sudo.sudorule_add_runasuser(cn="developers_sudo", users=["root"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["user"] == ["root"]

    def test_sudorule_add_runasuser_groups(self, mock_get_client):
        """Test adding run-as groups."""
        mock_get_client.execute.return_value = {}

        result = sudo.sudorule_add_runasuser(cn="developers_sudo", groups=["wheel"])

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["group"] == ["wheel"]

    def test_sudorule_add_runasuser_no_users(self, mock_get_client):
        """Test adding no run-as users."""
        result = sudo.sudorule_add_runasuser(cn="developers_sudo")

        assert result["success"] is False
        assert result["code"] == "NO_MEMBERS"


class TestFormatSudorule:
    """Tests for _format_sudorule helper."""

    def test_format_sudorule_extracts_values(self, sample_sudorule):
        """Test sudo rule formatting."""
        formatted = sudo._format_sudorule(sample_sudorule)

        assert formatted["cn"] == "developers_sudo"
        assert formatted["ipaenabledflag"] is True
        assert formatted["sudoorder"] == 10
        assert "/usr/bin/systemctl" in formatted["memberallowcmd_sudocmd"]
        assert "!authenticate" in formatted["ipasudoopt"]
