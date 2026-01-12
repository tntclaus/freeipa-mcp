"""Tests for DNS management tools."""

import pytest
from unittest.mock import MagicMock

from freeipa_mcp.tools import dns
from freeipa_mcp.client import ObjectNotFoundError, ObjectExistsError, FreeIPAClientError


@pytest.fixture
def sample_zone():
    """Sample DNS zone data."""
    return {
        "idnsname": ["example.com"],
        "idnszoneactive": [True],
        "idnssoamname": ["ns1.example.com."],
        "idnssoarname": ["admin.example.com."],
        "idnssoaserial": [2024011201],
        "idnssoarefresh": [3600],
        "idnssoaretry": [900],
        "idnssoaexpire": [1209600],
        "idnssoaminimum": [3600],
        "idnsallowdynupdate": [False],
    }


@pytest.fixture
def sample_zone_list(sample_zone):
    """Sample zone list response."""
    return {
        "count": 1,
        "truncated": False,
        "result": [sample_zone],
    }


@pytest.fixture
def sample_record():
    """Sample DNS record data."""
    return {
        "idnsname": ["www"],
        "arecord": ["192.168.1.100"],
    }


@pytest.fixture
def sample_record_list(sample_record):
    """Sample record list response."""
    return {
        "count": 1,
        "truncated": False,
        "result": [sample_record],
    }


class TestDnszoneFind:
    """Tests for dnszone_find function."""

    def test_dnszone_find_all(self, mock_get_client, sample_zone_list):
        """Test finding all DNS zones."""
        mock_get_client.execute.return_value = sample_zone_list

        result = dns.dnszone_find()

        assert result["success"] is True
        assert result["count"] == 1
        assert len(result["zones"]) == 1
        assert result["zones"][0]["idnsname"] == "example.com"

    def test_dnszone_find_by_name(self, mock_get_client, sample_zone_list):
        """Test finding zone by name pattern."""
        mock_get_client.execute.return_value = sample_zone_list

        result = dns.dnszone_find(idnsname="example*")

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["idnsname"] == "example*"

    def test_dnszone_find_forward_only(self, mock_get_client, sample_zone_list):
        """Test finding only forward zones."""
        mock_get_client.execute.return_value = sample_zone_list

        result = dns.dnszone_find(forward_only=True)

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["forward_only"] is True

    def test_dnszone_find_with_limit(self, mock_get_client, sample_zone_list):
        """Test finding zones with limit."""
        mock_get_client.execute.return_value = sample_zone_list

        result = dns.dnszone_find(limit=50)

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["sizelimit"] == 50

    def test_dnszone_find_error(self, mock_get_client):
        """Test dnszone_find handles errors."""
        mock_get_client.execute.side_effect = FreeIPAClientError("Error", "ERR")

        result = dns.dnszone_find()

        assert result["success"] is False
        assert result["code"] == "ERR"


class TestDnszoneShow:
    """Tests for dnszone_show function."""

    def test_dnszone_show_success(self, mock_get_client, sample_zone):
        """Test showing zone details."""
        mock_get_client.execute.return_value = {"result": sample_zone}

        result = dns.dnszone_show("example.com")

        assert result["success"] is True
        assert result["zone"]["idnsname"] == "example.com"
        assert result["zone"]["idnszoneactive"] is True

    def test_dnszone_show_not_found(self, mock_get_client):
        """Test showing non-existent zone."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = dns.dnszone_show("nonexistent.com")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestDnszoneAdd:
    """Tests for dnszone_add function."""

    def test_dnszone_add_minimal(self, mock_get_client, sample_zone):
        """Test creating zone with minimal fields."""
        mock_get_client.execute.return_value = {"result": sample_zone}

        result = dns.dnszone_add(idnsname="example.com")

        assert result["success"] is True
        assert "created successfully" in result["message"]

    def test_dnszone_add_with_soa(self, mock_get_client, sample_zone):
        """Test creating zone with SOA records."""
        mock_get_client.execute.return_value = {"result": sample_zone}

        result = dns.dnszone_add(
            idnsname="example.com",
            idnssoamname="ns1.example.com.",
            idnssoarname="admin.example.com."
        )

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["idnssoamname"] == "ns1.example.com."
        assert call_args[1]["idnssoarname"] == "admin.example.com."

    def test_dnszone_add_force(self, mock_get_client, sample_zone):
        """Test creating zone with force flag."""
        mock_get_client.execute.return_value = {"result": sample_zone}

        result = dns.dnszone_add(idnsname="example.com", force=True)

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["force"] is True

    def test_dnszone_add_duplicate(self, mock_get_client):
        """Test creating duplicate zone."""
        mock_get_client.execute.side_effect = ObjectExistsError("Exists", "DUPLICATE_ENTRY")

        result = dns.dnszone_add(idnsname="example.com")

        assert result["success"] is False
        assert result["code"] == "DUPLICATE_ENTRY"


class TestDnszoneDel:
    """Tests for dnszone_del function."""

    def test_dnszone_del_success(self, mock_get_client):
        """Test deleting zone."""
        mock_get_client.execute.return_value = {}

        result = dns.dnszone_del("example.com")

        assert result["success"] is True
        assert "deleted successfully" in result["message"]

    def test_dnszone_del_not_found(self, mock_get_client):
        """Test deleting non-existent zone."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = dns.dnszone_del("nonexistent.com")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestDnsrecordFind:
    """Tests for dnsrecord_find function."""

    def test_dnsrecord_find_all(self, mock_get_client, sample_record_list):
        """Test finding all records in zone."""
        mock_get_client.execute.return_value = sample_record_list

        result = dns.dnsrecord_find("example.com")

        assert result["success"] is True
        assert result["count"] == 1
        assert result["zone"] == "example.com"
        assert result["records"][0]["idnsname"] == "www"

    def test_dnsrecord_find_by_name(self, mock_get_client, sample_record_list):
        """Test finding record by name."""
        mock_get_client.execute.return_value = sample_record_list

        result = dns.dnsrecord_find("example.com", idnsname="www")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["idnsname"] == "www"

    def test_dnsrecord_find_zone_not_found(self, mock_get_client):
        """Test finding records in non-existent zone."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = dns.dnsrecord_find("nonexistent.com")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestDnsrecordAdd:
    """Tests for dnsrecord_add function."""

    def test_dnsrecord_add_a_record(self, mock_get_client, sample_record):
        """Test adding A record."""
        mock_get_client.execute.return_value = {"result": sample_record}

        result = dns.dnsrecord_add("example.com", "www", a_ip_address="192.168.1.100")

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["arecord"] == "192.168.1.100"

    def test_dnsrecord_add_aaaa_record(self, mock_get_client, sample_record):
        """Test adding AAAA record."""
        mock_get_client.execute.return_value = {"result": sample_record}

        result = dns.dnsrecord_add("example.com", "www", aaaa_ip_address="2001:db8::1")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["aaaarecord"] == "2001:db8::1"

    def test_dnsrecord_add_cname(self, mock_get_client, sample_record):
        """Test adding CNAME record."""
        mock_get_client.execute.return_value = {"result": sample_record}

        result = dns.dnsrecord_add("example.com", "alias", cname_hostname="www.example.com.")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["cnamerecord"] == "www.example.com."

    def test_dnsrecord_add_mx(self, mock_get_client, sample_record):
        """Test adding MX record."""
        mock_get_client.execute.return_value = {"result": sample_record}

        result = dns.dnsrecord_add("example.com", "@", mx_preference=10, mx_exchanger="mail.example.com.")

        call_args = mock_get_client.execute.call_args
        assert call_args[1]["mxrecord"] == "10 mail.example.com."

    def test_dnsrecord_add_txt(self, mock_get_client, sample_record):
        """Test adding TXT record."""
        mock_get_client.execute.return_value = {"result": sample_record}

        result = dns.dnsrecord_add("example.com", "@", txt_data="v=spf1 include:_spf.example.com ~all")

        call_args = mock_get_client.execute.call_args
        assert "txtrecord" in call_args[1]

    def test_dnsrecord_add_no_data(self, mock_get_client):
        """Test adding record with no data."""
        result = dns.dnsrecord_add("example.com", "www")

        assert result["success"] is False
        assert result["code"] == "NO_DATA"

    def test_dnsrecord_add_zone_not_found(self, mock_get_client):
        """Test adding record to non-existent zone."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = dns.dnsrecord_add("nonexistent.com", "www", a_ip_address="192.168.1.1")

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestDnsrecordDel:
    """Tests for dnsrecord_del function."""

    def test_dnsrecord_del_specific(self, mock_get_client):
        """Test deleting specific A record."""
        mock_get_client.execute.return_value = {}

        result = dns.dnsrecord_del("example.com", "www", a_ip_address="192.168.1.100")

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["arecord"] == "192.168.1.100"

    def test_dnsrecord_del_all(self, mock_get_client):
        """Test deleting all records for a name."""
        mock_get_client.execute.return_value = {}

        result = dns.dnsrecord_del("example.com", "www", del_all=True)

        assert result["success"] is True
        call_args = mock_get_client.execute.call_args
        assert call_args[1]["del_all"] is True

    def test_dnsrecord_del_no_data(self, mock_get_client):
        """Test deleting with no specification."""
        result = dns.dnsrecord_del("example.com", "www")

        assert result["success"] is False
        assert result["code"] == "NO_DATA"

    def test_dnsrecord_del_not_found(self, mock_get_client):
        """Test deleting non-existent record."""
        mock_get_client.execute.side_effect = ObjectNotFoundError("Not found", "NOT_FOUND")

        result = dns.dnsrecord_del("example.com", "www", del_all=True)

        assert result["success"] is False
        assert result["code"] == "NOT_FOUND"


class TestFormatZone:
    """Tests for _format_zone helper."""

    def test_format_zone_extracts_values(self, sample_zone):
        """Test zone formatting."""
        formatted = dns._format_zone(sample_zone)

        assert formatted["idnsname"] == "example.com"
        assert formatted["idnszoneactive"] is True
        assert formatted["idnssoamname"] == "ns1.example.com."


class TestFormatRecord:
    """Tests for _format_record helper."""

    def test_format_record_with_a_record(self, sample_record):
        """Test record formatting with A record."""
        formatted = dns._format_record(sample_record)

        assert formatted["idnsname"] == "www"
        assert formatted["arecord"] == ["192.168.1.100"]

    def test_format_record_multiple_types(self):
        """Test record with multiple record types."""
        record = {
            "idnsname": ["mail"],
            "arecord": ["192.168.1.10"],
            "mxrecord": ["10 mail.example.com."],
        }

        formatted = dns._format_record(record)

        assert "arecord" in formatted
        assert "mxrecord" in formatted
