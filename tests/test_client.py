"""Tests for FreeIPA client wrapper."""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from freeipa_mcp.client import (
    FreeIPAClient,
    FreeIPAClientError,
    AuthenticationError,
    ObjectNotFoundError,
    ObjectExistsError,
    PermissionDeniedError,
    get_client,
    reset_client,
    freeipa_session,
)
from python_freeipa.exceptions import (
    BadRequest,
    FreeIPAError,
    NotFound,
    Unauthorized,
    ValidationError,
)


class TestFreeIPAClientInit:
    """Tests for FreeIPAClient initialization."""

    def test_client_init(self):
        """Test client initializes with no connection."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(
                server="ipa.example.com",
                username="admin",
                password="secret",
                verify_ssl=True,
                api_version="2.230",
            )

            client = FreeIPAClient()

            assert client._client is None
            assert client._authenticated is False


class TestFreeIPAClientConnect:
    """Tests for FreeIPAClient connection."""

    def test_connect_success(self):
        """Test successful connection."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()
                client._connect()

                assert client._authenticated is True
                mock_client.login.assert_called_once_with(
                    username="admin",
                    password="secret",
                )

    def test_connect_auth_failure(self):
        """Test authentication failure."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="wrong",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client.login.side_effect = Unauthorized("Invalid credentials")
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()

                with pytest.raises(AuthenticationError) as exc_info:
                    client._connect()

                assert "Authentication failed" in str(exc_info.value)
                assert client._authenticated is False

    def test_connect_network_failure(self):
        """Test network connection failure."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="unreachable.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client_cls.side_effect = Exception("Connection refused")

                client = FreeIPAClient()

                with pytest.raises(FreeIPAClientError) as exc_info:
                    client._connect()

                assert "Failed to connect" in str(exc_info.value)


class TestFreeIPAClientDisconnect:
    """Tests for FreeIPAClient disconnect."""

    def test_disconnect_success(self):
        """Test successful disconnect."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()
                client._connect()
                client.disconnect()

                mock_client.logout.assert_called_once()
                assert client._authenticated is False

    def test_disconnect_with_error(self):
        """Test disconnect handles logout errors gracefully."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client.logout.side_effect = Exception("Logout failed")
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()
                client._connect()
                client.disconnect()  # Should not raise

                assert client._authenticated is False


class TestFreeIPAClientExecute:
    """Tests for FreeIPAClient execute method."""

    def test_execute_success(self):
        """Test successful API call."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client.user_find.return_value = {"count": 1, "result": []}
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()
                result = client.execute("user_find", uid="jsmith")

                assert result["count"] == 1

    def test_execute_not_found(self):
        """Test execute handles NotFound."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client.user_show.side_effect = NotFound("User not found")
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()

                with pytest.raises(ObjectNotFoundError):
                    client.execute("user_show", "nonexistent")

    def test_execute_bad_request_duplicate(self):
        """Test execute handles duplicate entry error."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client.user_add.side_effect = BadRequest("user already exists")
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()

                with pytest.raises(ObjectExistsError):
                    client.execute("user_add", "jsmith", givenname="John", sn="Smith")

    def test_execute_bad_request_other(self):
        """Test execute handles other bad request errors."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client.user_add.side_effect = BadRequest("Invalid parameter")
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()

                with pytest.raises(FreeIPAClientError) as exc_info:
                    client.execute("user_add", "jsmith")

                assert exc_info.value.code == "BAD_REQUEST"

    def test_execute_validation_error(self):
        """Test execute handles ValidationError."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client.user_add.side_effect = ValidationError("Invalid email format")
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()

                with pytest.raises(FreeIPAClientError) as exc_info:
                    client.execute("user_add", "jsmith")

                assert exc_info.value.code == "VALIDATION_ERROR"

    def test_execute_unauthorized(self):
        """Test execute handles Unauthorized (session expired)."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client.user_find.side_effect = Unauthorized("Session expired")
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()

                with pytest.raises(AuthenticationError):
                    client.execute("user_find")

                assert client._authenticated is False

    def test_execute_freeipa_error(self):
        """Test execute handles generic FreeIPAError."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client.user_find.side_effect = FreeIPAError("Internal error")
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()

                with pytest.raises(FreeIPAClientError) as exc_info:
                    client.execute("user_find")

                assert exc_info.value.code == "IPA_ERROR"

    def test_execute_unknown_method(self):
        """Test execute handles unknown method."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                del mock_client.nonexistent_method  # Ensure it doesn't exist
                mock_client_cls.return_value = mock_client

                # Make getattr raise AttributeError
                type(mock_client).nonexistent_method = PropertyMock(
                    side_effect=AttributeError("No such method")
                )

                client = FreeIPAClient()

                with pytest.raises(FreeIPAClientError) as exc_info:
                    client.execute("nonexistent_method")

                assert exc_info.value.code == "UNKNOWN_METHOD"


class TestConvenienceMethods:
    """Tests for convenience methods."""

    def test_user_find(self):
        """Test user_find convenience method."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client.user_find.return_value = {"count": 0, "result": []}
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()
                result = client.user_find(uid="jsmith")

                mock_client.user_find.assert_called_with(uid="jsmith")

    def test_group_add_member(self):
        """Test group_add_member convenience method."""
        with patch("freeipa_mcp.client.get_settings") as mock_settings:
            with patch("freeipa_mcp.client.ClientMeta") as mock_client_cls:
                mock_settings.return_value = MagicMock(
                    server="ipa.example.com",
                    username="admin",
                    password="secret",
                    verify_ssl=True,
                    api_version="2.230",
                )
                mock_client = MagicMock()
                mock_client.group_add_member.return_value = {"failed": {}}
                mock_client_cls.return_value = mock_client

                client = FreeIPAClient()
                client.group_add_member("developers", user=["jsmith"])

                mock_client.group_add_member.assert_called_with("developers", user=["jsmith"])


class TestGlobalClient:
    """Tests for global client functions."""

    def test_get_client_singleton(self):
        """Test get_client returns singleton."""
        reset_client()  # Ensure clean state

        with patch("freeipa_mcp.client.FreeIPAClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client

            client1 = get_client()
            client2 = get_client()

            assert client1 is client2
            mock_cls.assert_called_once()

    def test_reset_client(self):
        """Test reset_client clears singleton."""
        reset_client()  # Clear any existing state first

        with patch("freeipa_mcp.client.FreeIPAClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client

            client = get_client()
            assert client is mock_client

            reset_client()

            mock_client.disconnect.assert_called_once()


class TestFreeIPASession:
    """Tests for freeipa_session context manager."""

    def test_session_yields_client(self):
        """Test session yields client."""
        reset_client()

        with patch("freeipa_mcp.client.FreeIPAClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client

            with freeipa_session() as client:
                assert client is mock_client

    def test_session_reuses_client(self):
        """Test session reuses existing client."""
        reset_client()

        with patch("freeipa_mcp.client.FreeIPAClient") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client

            with freeipa_session() as client1:
                pass
            with freeipa_session() as client2:
                assert client1 is client2
