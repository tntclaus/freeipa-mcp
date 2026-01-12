"""Tests for certificate management tools."""

import pytest
from unittest.mock import MagicMock

from freeipa_mcp.tools import certs
from freeipa_mcp.client import ObjectNotFoundError, FreeIPAClientError


@pytest.fixture
def sample_cert():
    """Sample certificate data."""
    return {
        "serial_number": 12345,
        "subject": "CN=jsmith,O=EXAMPLE.COM",
        "issuer": "CN=Certificate Authority,O=EXAMPLE.COM",
        "valid_not_before": "2024-01-01T00:00:00Z",
        "valid_not_after": "2025-01-01T00:00:00Z",
        "status": "VALID",
        "owner_user": ["jsmith"],
        "owner_host": [],
        "owner_service": [],
        "certificate": "MIICvjCCAaagAwIBAgIBAjANBgkqhkiG9w0BAQ...",
    }


@pytest.fixture
def sample_cert_list(sample_cert):
    """Sample certificate list response."""
    return {
        "count": 1,
        "result": [sample_cert],
    }


@pytest.fixture
def sample_pem_cert():
    """Sample PEM certificate with headers."""
    return """-----BEGIN CERTIFICATE-----
MIICvjCCAaagAwIBAgIBAjANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDDBtDZXJ0
aWZpY2F0ZSBBdXRob3JpdHksIEVYQU1QTEUuQ09NMB4XDTI0MDEwMTAwMDAwMFoX
DTI1MDEwMTAwMDAwMFowHzEdMBsGA1UEAwwUanNtaXRoLCBFWEFNUExFLkNPTTCC
-----END CERTIFICATE-----"""


@pytest.fixture
def sample_base64_cert():
    """Sample base64 certificate without headers."""
    return "MIICvjCCAaagAwIBAgIBAjANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDDBtDZXJ0aWZpY2F0ZSBBdXRob3JpdHksIEVYQU1QTEUuQ09NMB4XDTI0MDEwMTAwMDAwMFo="


class TestUserAddCert:
    """Tests for user_add_cert function."""

    def test_user_add_cert_base64(self, mock_get_client, sample_base64_cert):
        """Test adding base64 certificate to user."""
        mock_get_client.execute.return_value = {}

        result = certs.user_add_cert(uid="jsmith", certificate=sample_base64_cert)

        assert result["success"] is True
        assert "added to user" in result["message"]

    def test_user_add_cert_pem(self, mock_get_client, sample_pem_cert):
        """Test adding PEM certificate (strips headers)."""
        mock_get_client.execute.return_value = {}

        result = certs.user_add_cert(uid="jsmith", certificate=sample_pem_cert)

        assert result["success"] is True
        # Should strip PEM headers
        call_args = mock_get_client.execute.call_args
        cert_arg = call_args[1]["usercertificate"]
        assert "-----BEGIN" not in cert_arg
        assert "-----END" not in cert_arg

    def test_user_add_cert_not_found(self, mock_get_client, sample_base64_cert):
        """Test adding cert to non-existent user."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = certs.user_add_cert(uid="nonexistent", certificate=sample_base64_cert)

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"

    def test_user_add_cert_error(self, mock_get_client, sample_base64_cert):
        """Test user_add_cert handles errors."""
        mock_get_client.execute.side_effect = FreeIPAClientError("Error", "ERR")

        result = certs.user_add_cert(uid="jsmith", certificate=sample_base64_cert)

        assert result["success"] is False
        assert result["code"] == "ERR"


class TestUserRemoveCert:
    """Tests for user_remove_cert function."""

    def test_user_remove_cert_success(self, mock_get_client, sample_base64_cert):
        """Test removing certificate from user."""
        mock_get_client.execute.return_value = {}

        result = certs.user_remove_cert(uid="jsmith", certificate=sample_base64_cert)

        assert result["success"] is True
        assert "removed from user" in result["message"]

    def test_user_remove_cert_pem(self, mock_get_client, sample_pem_cert):
        """Test removing PEM certificate (strips headers)."""
        mock_get_client.execute.return_value = {}

        result = certs.user_remove_cert(uid="jsmith", certificate=sample_pem_cert)

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        cert_arg = call_args[1]["usercertificate"]
        assert "-----BEGIN" not in cert_arg

    def test_user_remove_cert_not_found(self, mock_get_client, sample_base64_cert):
        """Test removing cert from non-existent user."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = certs.user_remove_cert(uid="nonexistent", certificate=sample_base64_cert)

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestHostAddCert:
    """Tests for host_add_cert function."""

    def test_host_add_cert_success(self, mock_get_client, sample_base64_cert):
        """Test adding certificate to host."""
        mock_get_client.execute.return_value = {}

        result = certs.host_add_cert(fqdn="server01.example.com", certificate=sample_base64_cert)

        assert result["success"] is True
        assert "added to host" in result["message"]

    def test_host_add_cert_pem(self, mock_get_client, sample_pem_cert):
        """Test adding PEM certificate to host."""
        mock_get_client.execute.return_value = {}

        result = certs.host_add_cert(fqdn="server01.example.com", certificate=sample_pem_cert)

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        cert_arg = call_args[1]["usercertificate"]
        assert "-----BEGIN" not in cert_arg

    def test_host_add_cert_not_found(self, mock_get_client, sample_base64_cert):
        """Test adding cert to non-existent host."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = certs.host_add_cert(fqdn="nonexistent.example.com", certificate=sample_base64_cert)

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestHostRemoveCert:
    """Tests for host_remove_cert function."""

    def test_host_remove_cert_success(self, mock_get_client, sample_base64_cert):
        """Test removing certificate from host."""
        mock_get_client.execute.return_value = {}

        result = certs.host_remove_cert(fqdn="server01.example.com", certificate=sample_base64_cert)

        assert result["success"] is True
        assert "removed from host" in result["message"]

    def test_host_remove_cert_not_found(self, mock_get_client, sample_base64_cert):
        """Test removing cert from non-existent host."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = certs.host_remove_cert(fqdn="nonexistent.example.com", certificate=sample_base64_cert)

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestCertFind:
    """Tests for cert_find function."""

    def test_cert_find_all(self, mock_get_client, sample_cert_list):
        """Test finding all certificates."""
        mock_get_client.execute.return_value = sample_cert_list

        result = certs.cert_find()

        assert result["success"] is True
        assert result["count"] == 1
        assert result["certificates"][0]["serial_number"] == 12345

    def test_cert_find_by_user(self, mock_get_client, sample_cert_list):
        """Test finding certificates by user."""
        mock_get_client.execute.return_value = sample_cert_list

        result = certs.cert_find(user="jsmith")

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["user"] == "jsmith"

    def test_cert_find_by_host(self, mock_get_client, sample_cert_list):
        """Test finding certificates by host."""
        mock_get_client.execute.return_value = sample_cert_list

        result = certs.cert_find(host="server01.example.com")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["host"] == "server01.example.com"

    def test_cert_find_expiring(self, mock_get_client, sample_cert_list):
        """Test finding expiring certificates."""
        mock_get_client.execute.return_value = sample_cert_list

        result = certs.cert_find(validnotafter_to="2024-12-31")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["validnotafter_to"] == "2024-12-31"

    def test_cert_find_by_subject(self, mock_get_client, sample_cert_list):
        """Test finding certificates by subject."""
        mock_get_client.execute.return_value = sample_cert_list

        result = certs.cert_find(subject="CN=jsmith")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["subject"] == "CN=jsmith"

    def test_cert_find_by_issuer(self, mock_get_client, sample_cert_list):
        """Test finding certificates by issuer."""
        mock_get_client.execute.return_value = sample_cert_list

        result = certs.cert_find(issuer="CN=Certificate Authority")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["issuer"] == "CN=Certificate Authority"

    def test_cert_find_by_status(self, mock_get_client, sample_cert_list):
        """Test finding certificates by status."""
        mock_get_client.execute.return_value = sample_cert_list

        result = certs.cert_find(status="VALID")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["status"] == "VALID"

    def test_cert_find_with_limit(self, mock_get_client, sample_cert_list):
        """Test finding certificates with limit."""
        mock_get_client.execute.return_value = sample_cert_list

        result = certs.cert_find(limit=50)

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["sizelimit"] == 50

    def test_cert_find_error(self, mock_get_client):
        """Test cert_find handles errors."""
        mock_get_client.execute.side_effect = FreeIPAClientError("Error", "ERR")

        result = certs.cert_find()

        assert result["success"] is False
        assert result["code"] == "ERR"


class TestCertShow:
    """Tests for cert_show function."""

    def test_cert_show_success(self, mock_get_client, sample_cert):
        """Test showing certificate details."""
        mock_get_client.execute.return_value = {"result": sample_cert}

        result = certs.cert_show(serial_number=12345)

        assert result["success"] is True
        assert result["certificate"]["serial_number"] == 12345
        assert result["certificate"]["subject"] == "CN=jsmith,O=EXAMPLE.COM"
        assert result["certificate"]["status"] == "VALID"

    def test_cert_show_not_found(self, mock_get_client):
        """Test showing non-existent certificate."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = certs.cert_show(serial_number=99999)

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"

    def test_cert_show_error(self, mock_get_client):
        """Test cert_show handles errors."""
        mock_get_client.execute.side_effect = FreeIPAClientError("Error", "ERR")

        result = certs.cert_show(serial_number=12345)

        assert result["success"] is False
        assert result["code"] == "ERR"


class TestCertRevoke:
    """Tests for cert_revoke function."""

    def test_cert_revoke_default_reason(self, mock_get_client):
        """Test revoking certificate with default reason."""
        mock_get_client.execute.return_value = {}

        result = certs.cert_revoke(serial_number=12345)

        assert result["success"] is True
        assert "revoked" in result["message"]
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["revocation_reason"] == 0

    def test_cert_revoke_key_compromise(self, mock_get_client):
        """Test revoking certificate for key compromise."""
        mock_get_client.execute.return_value = {}

        result = certs.cert_revoke(serial_number=12345, reason=1)

        assert result["success"] is True
        assert "keyCompromise" in result["message"]
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["revocation_reason"] == 1

    def test_cert_revoke_ca_compromise(self, mock_get_client):
        """Test revoking certificate for CA compromise."""
        mock_get_client.execute.return_value = {}

        result = certs.cert_revoke(serial_number=12345, reason=2)

        assert result["success"] is True
        assert "cACompromise" in result["message"]

    def test_cert_revoke_affiliation_changed(self, mock_get_client):
        """Test revoking certificate for affiliation change."""
        mock_get_client.execute.return_value = {}

        result = certs.cert_revoke(serial_number=12345, reason=3)

        assert result["success"] is True
        assert "affiliationChanged" in result["message"]

    def test_cert_revoke_superseded(self, mock_get_client):
        """Test revoking certificate as superseded."""
        mock_get_client.execute.return_value = {}

        result = certs.cert_revoke(serial_number=12345, reason=4)

        assert result["success"] is True
        assert "superseded" in result["message"]

    def test_cert_revoke_cessation(self, mock_get_client):
        """Test revoking certificate for cessation of operation."""
        mock_get_client.execute.return_value = {}

        result = certs.cert_revoke(serial_number=12345, reason=5)

        assert result["success"] is True
        assert "cessationOfOperation" in result["message"]

    def test_cert_revoke_hold(self, mock_get_client):
        """Test revoking certificate on hold."""
        mock_get_client.execute.return_value = {}

        result = certs.cert_revoke(serial_number=12345, reason=6)

        assert result["success"] is True
        assert "certificateHold" in result["message"]

    def test_cert_revoke_not_found(self, mock_get_client):
        """Test revoking non-existent certificate."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = certs.cert_revoke(serial_number=99999)

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"

    def test_cert_revoke_error(self, mock_get_client):
        """Test cert_revoke handles errors."""
        mock_get_client.execute.side_effect = FreeIPAClientError("Error", "ERR")

        result = certs.cert_revoke(serial_number=12345)

        assert result["success"] is False
        assert result["code"] == "ERR"
