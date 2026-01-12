"""Tests for user management tools."""

import pytest
from unittest.mock import MagicMock

from freeipa_mcp.tools import users
from freeipa_mcp.client import ObjectNotFoundError, ObjectExistsError, FreeIPAClientError


class TestUserFind:
    """Tests for user_find function."""

    def test_user_find_all(self, mock_get_client, sample_user_list):
        """Test finding all users."""
        mock_get_client.user_find.return_value = sample_user_list

        result = users.user_find()

        assert result["success"] is True
        assert result["count"] == 1
        assert len(result["users"]) == 1
        assert result["users"][0]["uid"] == "jsmith"

    def test_user_find_by_uid(self, mock_get_client, sample_user_list):
        """Test finding user by uid pattern."""
        mock_get_client.user_find.return_value = sample_user_list

        result = users.user_find(uid="jsmith")

        assert result["success"] is True
        mock_get_client.user_find.assert_called_once()
        call_kwargs = mock_get_client.user_find.call_args[1]
        assert call_kwargs["uid"] == "jsmith"

    def test_user_find_by_group(self, mock_get_client, sample_user_list):
        """Test finding users in a specific group."""
        mock_get_client.user_find.return_value = sample_user_list

        result = users.user_find(in_group="developers")

        assert result["success"] is True
        call_kwargs = mock_get_client.user_find.call_args[1]
        assert call_kwargs["in_group"] == "developers"

    def test_user_find_disabled(self, mock_get_client):
        """Test finding disabled users."""
        mock_get_client.user_find.return_value = {"count": 0, "result": []}

        result = users.user_find(disabled=True)

        assert result["success"] is True
        call_kwargs = mock_get_client.user_find.call_args[1]
        assert call_kwargs["nsaccountlock"] is True

    def test_user_find_with_limit(self, mock_get_client, sample_user_list):
        """Test finding users with limit."""
        mock_get_client.user_find.return_value = sample_user_list

        result = users.user_find(limit=50)

        call_kwargs = mock_get_client.user_find.call_args[1]
        assert call_kwargs["sizelimit"] == 50

    def test_user_find_error(self, mock_get_client):
        """Test user_find handles errors gracefully."""
        mock_get_client.user_find.side_effect = FreeIPAClientError("Connection failed", "CONN_ERROR")

        result = users.user_find()

        assert result["success"] is False
        assert "error" in result
        assert result["code"] == "CONN_ERROR"


class TestUserShow:
    """Tests for user_show function."""

    def test_user_show_success(self, mock_get_client, sample_user):
        """Test showing user details."""
        mock_get_client.user_show.return_value = {"result": sample_user}

        result = users.user_show("jsmith")

        assert result["success"] is True
        assert result["user"]["uid"] == "jsmith"
        assert result["user"]["givenname"] == "John"
        assert result["user"]["mail"] == "jsmith@example.com"

    def test_user_show_not_found(self, mock_get_client):
        """Test user_show when user doesn't exist."""
        mock_get_client.user_show.side_effect = ObjectNotFoundError("User not found", "NOT_FOUND")

        result = users.user_show("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"
        assert "nonexistent" in result["error"]


class TestUserAdd:
    """Tests for user_add function."""

    def test_user_add_minimal(self, mock_get_client, sample_user):
        """Test creating user with minimal required fields."""
        mock_get_client.user_add.return_value = {"result": sample_user}

        result = users.user_add(uid="jsmith", givenname="John", sn="Smith")

        assert result["success"] is True
        assert "created successfully" in result["message"]
        mock_get_client.user_add.assert_called_once()

    def test_user_add_full(self, mock_get_client, sample_user):
        """Test creating user with all fields."""
        mock_get_client.user_add.return_value = {"result": sample_user}

        result = users.user_add(
            uid="jsmith",
            givenname="John",
            sn="Smith",
            mail="jsmith@example.com",
            password="initial123",
            loginshell="/bin/zsh",
            homedirectory="/home/jsmith",
        )

        assert result["success"] is True
        call_kwargs = mock_get_client.user_add.call_args[1]
        assert call_kwargs["mail"] == "jsmith@example.com"
        assert call_kwargs["userpassword"] == "initial123"
        assert call_kwargs["loginshell"] == "/bin/zsh"

    def test_user_add_duplicate(self, mock_get_client):
        """Test creating user that already exists."""
        mock_get_client.user_add.side_effect = ObjectExistsError("User exists", "DUPLICATE_ENTRY")

        result = users.user_add(uid="jsmith", givenname="John", sn="Smith")

        assert result["success"] is False
        assert result["code"] == "DUPLICATE_ENTRY"
        assert "already exists" in result["error"]


class TestUserMod:
    """Tests for user_mod function."""

    def test_user_mod_success(self, mock_get_client, sample_user):
        """Test modifying user attributes."""
        modified_user = sample_user.copy()
        modified_user["mail"] = ["newemail@example.com"]
        mock_get_client.user_mod.return_value = {"result": modified_user}

        result = users.user_mod(uid="jsmith", mail="newemail@example.com")

        assert result["success"] is True
        assert "modified successfully" in result["message"]

    def test_user_mod_no_changes(self, mock_get_client):
        """Test user_mod with no changes specified."""
        result = users.user_mod(uid="jsmith")

        assert result["success"] is False
        assert result["code"] == "NO_CHANGES"

    def test_user_mod_not_found(self, mock_get_client):
        """Test modifying non-existent user."""
        mock_get_client.user_mod.side_effect = ObjectNotFoundError("User not found", "NOT_FOUND")

        result = users.user_mod(uid="nonexistent", mail="test@example.com")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestUserDel:
    """Tests for user_del function."""

    def test_user_del_success(self, mock_get_client):
        """Test deleting user."""
        mock_get_client.user_del.return_value = {}

        result = users.user_del("jsmith")

        assert result["success"] is True
        assert "deleted successfully" in result["message"]

    def test_user_del_preserve(self, mock_get_client):
        """Test preserving user instead of deleting."""
        mock_get_client.user_del.return_value = {}

        result = users.user_del("jsmith", preserve=True)

        assert result["success"] is True
        assert "preserved" in result["message"]
        call_kwargs = mock_get_client.user_del.call_args[1]
        assert call_kwargs["preserve"] is True

    def test_user_del_not_found(self, mock_get_client):
        """Test deleting non-existent user."""
        mock_get_client.user_del.side_effect = ObjectNotFoundError("User not found", "NOT_FOUND")

        result = users.user_del("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestUserEnable:
    """Tests for user_enable function."""

    def test_user_enable_success(self, mock_get_client):
        """Test enabling user."""
        mock_get_client.execute.return_value = {}

        result = users.user_enable("jsmith")

        assert result["success"] is True
        assert "enabled successfully" in result["message"]

    def test_user_enable_not_found(self, mock_get_client):
        """Test enabling non-existent user."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("User not found", "NOT_FOUND")

        result = users.user_enable("nonexistent")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestUserDisable:
    """Tests for user_disable function."""

    def test_user_disable_success(self, mock_get_client):
        """Test disabling user."""
        mock_get_client.execute.return_value = {}

        result = users.user_disable("jsmith")

        assert result["success"] is True
        assert "disabled successfully" in result["message"]


class TestUserUnlock:
    """Tests for user_unlock function."""

    def test_user_unlock_success(self, mock_get_client):
        """Test unlocking user."""
        mock_get_client.execute.return_value = {}

        result = users.user_unlock("jsmith")

        assert result["success"] is True
        assert "unlocked successfully" in result["message"]


class TestFormatUser:
    """Tests for _format_user helper function."""

    def test_format_user_extracts_single_values(self, sample_user):
        """Test that single-item lists are flattened."""
        formatted = users._format_user(sample_user)

        assert formatted["uid"] == "jsmith"
        assert formatted["givenname"] == "John"
        assert formatted["mail"] == "jsmith@example.com"
        assert formatted["uidnumber"] == 10001

    def test_format_user_preserves_lists(self, sample_user):
        """Test that multi-item lists are preserved."""
        formatted = users._format_user(sample_user)

        assert isinstance(formatted["memberof_group"], list)
        assert "developers" in formatted["memberof_group"]
