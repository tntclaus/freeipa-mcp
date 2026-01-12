"""Tests for group management tools."""

import pytest
from unittest.mock import MagicMock

from freeipa_mcp.tools import groups
from freeipa_mcp.client import ObjectNotFoundError, ObjectExistsError, FreeIPAClientError


class TestGroupFind:
    """Tests for group_find function."""

    def test_group_find_all(self, mock_get_client, sample_group_list):
        """Test finding all groups."""
        mock_get_client.group_find.return_value = sample_group_list

        result = groups.group_find()

        assert result["success"] is True
        assert result["count"] == 1
        assert len(result["groups"]) == 1
        assert result["groups"][0]["cn"] == "developers"

    def test_group_find_by_name(self, mock_get_client, sample_group_list):
        """Test finding group by name pattern."""
        mock_get_client.group_find.return_value = sample_group_list

        result = groups.group_find(cn="dev*")

        assert result["success"] is True
        call_kwargs = mock_get_client.group_find.call_args[1]
        assert call_kwargs["cn"] == "dev*"

    def test_group_find_by_user(self, mock_get_client, sample_group_list):
        """Test finding groups containing a specific user."""
        mock_get_client.group_find.return_value = sample_group_list

        result = groups.group_find(user="jsmith")

        assert result["success"] is True
        call_kwargs = mock_get_client.group_find.call_args[1]
        assert call_kwargs["user"] == "jsmith"

    def test_group_find_posix_only(self, mock_get_client, sample_group_list):
        """Test finding only POSIX groups."""
        mock_get_client.group_find.return_value = sample_group_list

        result = groups.group_find(posix=True)

        call_kwargs = mock_get_client.group_find.call_args[1]
        assert call_kwargs["posix"] is True

    def test_group_find_error(self, mock_get_client):
        """Test group_find handles errors gracefully."""
        mock_get_client.group_find.side_effect = FreeIPAClientError("Connection failed", "CONN_ERROR")

        result = groups.group_find()

        assert result["success"] is False
        assert result["code"] == "CONN_ERROR"


class TestGroupShow:
    """Tests for group_show function."""

    def test_group_show_success(self, mock_get_client, sample_group):
        """Test showing group details."""
        mock_get_client.group_show.return_value = {"result": sample_group}

        result = groups.group_show("developers")

        assert result["success"] is True
        assert result["group"]["cn"] == "developers"
        assert result["group"]["description"] == "Development team"
        assert "jsmith" in result["group"]["member_user"]

    def test_group_show_not_found(self, mock_get_client):
        """Test group_show when group doesn't exist."""
        mock_get_client.group_show.side_effect = ObjectNotFoundError("Group not found", "NOT_FOUND")

        result = groups.group_show("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestGroupAdd:
    """Tests for group_add function."""

    def test_group_add_minimal(self, mock_get_client, sample_group):
        """Test creating group with minimal fields."""
        mock_get_client.group_add.return_value = {"result": sample_group}

        result = groups.group_add(cn="developers")

        assert result["success"] is True
        assert "created successfully" in result["message"]

    def test_group_add_with_description(self, mock_get_client, sample_group):
        """Test creating group with description."""
        mock_get_client.group_add.return_value = {"result": sample_group}

        result = groups.group_add(cn="developers", description="Dev team")

        call_kwargs = mock_get_client.group_add.call_args[1]
        assert call_kwargs["description"] == "Dev team"

    def test_group_add_nonposix(self, mock_get_client, sample_group):
        """Test creating non-POSIX group."""
        mock_get_client.group_add.return_value = {"result": sample_group}

        result = groups.group_add(cn="adgroup", nonposix=True)

        call_kwargs = mock_get_client.group_add.call_args[1]
        assert call_kwargs["nonposix"] is True

    def test_group_add_duplicate(self, mock_get_client):
        """Test creating group that already exists."""
        mock_get_client.group_add.side_effect = ObjectExistsError("Group exists", "DUPLICATE_ENTRY")

        result = groups.group_add(cn="developers")

        assert result["success"] is False
        assert result["code"] == "DUPLICATE_ENTRY"


class TestGroupMod:
    """Tests for group_mod function."""

    def test_group_mod_success(self, mock_get_client, sample_group):
        """Test modifying group."""
        mock_get_client.group_mod.return_value = {"result": sample_group}

        result = groups.group_mod(cn="developers", description="New description")

        assert result["success"] is True
        assert "modified successfully" in result["message"]

    def test_group_mod_no_changes(self, mock_get_client):
        """Test group_mod with no changes."""
        result = groups.group_mod(cn="developers")

        assert result["success"] is False
        assert result["code"] == "NO_CHANGES"

    def test_group_mod_not_found(self, mock_get_client):
        """Test modifying non-existent group."""
        mock_get_client.group_mod.side_effect = ObjectNotFoundError("Group not found", "NOT_FOUND")

        result = groups.group_mod(cn="nonexistent", description="test")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestGroupDel:
    """Tests for group_del function."""

    def test_group_del_success(self, mock_get_client):
        """Test deleting group."""
        mock_get_client.group_del.return_value = {}

        result = groups.group_del("developers")

        assert result["success"] is True
        assert "deleted successfully" in result["message"]

    def test_group_del_protected(self, mock_get_client):
        """Test deleting protected group."""
        result = groups.group_del("admins")

        assert result["success"] is False
        assert result["code"] == "PROTECTED_GROUP"
        # Should not call API for protected groups
        mock_get_client.group_del.assert_not_called()

    def test_group_del_not_found(self, mock_get_client):
        """Test deleting non-existent group."""
        mock_get_client.group_del.side_effect = ObjectNotFoundError("Group not found", "NOT_FOUND")

        result = groups.group_del("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestGroupAddMember:
    """Tests for group_add_member function."""

    def test_group_add_member_users(self, mock_get_client):
        """Test adding users to group."""
        mock_get_client.group_add_member.return_value = {"failed": {"member": {"user": [], "group": []}}}

        result = groups.group_add_member(cn="developers", users=["jsmith", "jdoe"])

        assert result["success"] is True
        call_kwargs = mock_get_client.group_add_member.call_args[1]
        assert call_kwargs["user"] == ["jsmith", "jdoe"]

    def test_group_add_member_groups(self, mock_get_client):
        """Test adding nested groups."""
        mock_get_client.group_add_member.return_value = {"failed": {"member": {"user": [], "group": []}}}

        result = groups.group_add_member(cn="all-devs", groups=["frontend", "backend"])

        assert result["success"] is True
        call_kwargs = mock_get_client.group_add_member.call_args[1]
        assert call_kwargs["group"] == ["frontend", "backend"]

    def test_group_add_member_partial_failure(self, mock_get_client):
        """Test adding members with some failures."""
        mock_get_client.group_add_member.return_value = {
            "failed": {"member": {"user": [["baduser", "user not found"]], "group": []}}
        }

        result = groups.group_add_member(cn="developers", users=["jsmith", "baduser"])

        assert result["success"] is True
        assert "warnings" in result

    def test_group_add_member_no_members(self, mock_get_client):
        """Test adding no members."""
        result = groups.group_add_member(cn="developers")

        assert result["success"] is False
        assert result["code"] == "NO_MEMBERS"

    def test_group_add_member_not_found(self, mock_get_client):
        """Test adding members to non-existent group."""
        mock_get_client.group_add_member.side_effect = ObjectNotFoundError("Group not found", "NOT_FOUND")

        result = groups.group_add_member(cn="nonexistent", users=["jsmith"])

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestGroupRemoveMember:
    """Tests for group_remove_member function."""

    def test_group_remove_member_success(self, mock_get_client):
        """Test removing members from group."""
        mock_get_client.group_remove_member.return_value = {"failed": {"member": {"user": [], "group": []}}}

        result = groups.group_remove_member(cn="developers", users=["jsmith"])

        assert result["success"] is True
        assert "removed from group" in result["message"]

    def test_group_remove_member_no_members(self, mock_get_client):
        """Test removing no members."""
        result = groups.group_remove_member(cn="developers")

        assert result["success"] is False
        assert result["code"] == "NO_MEMBERS"


class TestFormatGroup:
    """Tests for _format_group helper function."""

    def test_format_group_extracts_values(self, sample_group):
        """Test that group data is properly formatted."""
        formatted = groups._format_group(sample_group)

        assert formatted["cn"] == "developers"
        assert formatted["description"] == "Development team"
        assert formatted["gidnumber"] == 20001
        assert isinstance(formatted["member_user"], list)
