"""Tests for configuration management."""

import os
import pytest
from unittest.mock import patch

from freeipa_mcp.config import FreeIPASettings, get_settings, validate_settings


class TestFreeIPASettings:
    """Tests for FreeIPASettings model."""

    def test_settings_from_env(self):
        """Test loading settings from environment variables."""
        env = {
            "FREEIPA_SERVER": "ipa.example.com",
            "FREEIPA_USERNAME": "admin",
            "FREEIPA_PASSWORD": "secret123",
        }

        with patch.dict(os.environ, env, clear=False):
            # Clear the cache to force reload
            get_settings.cache_clear()
            settings = FreeIPASettings()

            assert settings.server == "ipa.example.com"
            assert settings.username == "admin"
            assert settings.password == "secret123"

    def test_settings_defaults(self):
        """Test default values are applied."""
        env = {
            "FREEIPA_SERVER": "ipa.example.com",
            "FREEIPA_USERNAME": "admin",
            "FREEIPA_PASSWORD": "secret",
        }

        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            settings = FreeIPASettings()

            assert settings.verify_ssl is True
            assert settings.api_version == "2.230"
            assert settings.default_limit == 100
            assert settings.request_timeout == 30

    def test_settings_custom_values(self):
        """Test custom values override defaults."""
        env = {
            "FREEIPA_SERVER": "ipa.example.com",
            "FREEIPA_USERNAME": "admin",
            "FREEIPA_PASSWORD": "secret",
            "FREEIPA_VERIFY_SSL": "false",
            "FREEIPA_API_VERSION": "2.245",
            "FREEIPA_DEFAULT_LIMIT": "50",
        }

        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            settings = FreeIPASettings()

            assert settings.verify_ssl is False
            assert settings.api_version == "2.245"
            assert settings.default_limit == 50

    def test_server_validation_strips_protocol(self):
        """Test server validation removes protocol prefix."""
        env = {
            "FREEIPA_SERVER": "https://ipa.example.com",
            "FREEIPA_USERNAME": "admin",
            "FREEIPA_PASSWORD": "secret",
        }

        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            settings = FreeIPASettings()

            assert settings.server == "ipa.example.com"

    def test_server_validation_strips_path(self):
        """Test server validation removes path components."""
        env = {
            "FREEIPA_SERVER": "ipa.example.com/ipa/json",
            "FREEIPA_USERNAME": "admin",
            "FREEIPA_PASSWORD": "secret",
        }

        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            settings = FreeIPASettings()

            assert settings.server == "ipa.example.com"

    def test_api_version_validation_format(self):
        """Test API version format validation."""
        env = {
            "FREEIPA_SERVER": "ipa.example.com",
            "FREEIPA_USERNAME": "admin",
            "FREEIPA_PASSWORD": "secret",
            "FREEIPA_API_VERSION": "invalid",
        }

        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            with pytest.raises(ValueError, match="major.minor"):
                FreeIPASettings()

    def test_api_version_validation_numeric(self):
        """Test API version requires numeric values."""
        env = {
            "FREEIPA_SERVER": "ipa.example.com",
            "FREEIPA_USERNAME": "admin",
            "FREEIPA_PASSWORD": "secret",
            "FREEIPA_API_VERSION": "a.b",
        }

        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            with pytest.raises(ValueError, match="numeric"):
                FreeIPASettings()

    def test_default_limit_bounds(self):
        """Test default_limit is within bounds."""
        env = {
            "FREEIPA_SERVER": "ipa.example.com",
            "FREEIPA_USERNAME": "admin",
            "FREEIPA_PASSWORD": "secret",
            "FREEIPA_DEFAULT_LIMIT": "5000",  # Over max of 2000
        }

        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            with pytest.raises(ValueError):
                FreeIPASettings()


class TestGetSettings:
    """Tests for get_settings function."""

    def test_get_settings_cached(self):
        """Test that settings are cached."""
        env = {
            "FREEIPA_SERVER": "ipa.example.com",
            "FREEIPA_USERNAME": "admin",
            "FREEIPA_PASSWORD": "secret",
        }

        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            settings1 = get_settings()
            settings2 = get_settings()

            # Same object (cached)
            assert settings1 is settings2


class TestValidateSettings:
    """Tests for validate_settings function."""

    def test_validate_settings_success(self):
        """Test validation with valid settings."""
        env = {
            "FREEIPA_SERVER": "ipa.example.com",
            "FREEIPA_USERNAME": "admin",
            "FREEIPA_PASSWORD": "secret",
        }

        with patch.dict(os.environ, env, clear=False):
            get_settings.cache_clear()
            valid, message = validate_settings()

            assert valid is True
            assert "ipa.example.com" in message

    def test_validate_settings_missing_server(self):
        """Test validation with missing server."""
        env = {
            "FREEIPA_USERNAME": "admin",
            "FREEIPA_PASSWORD": "secret",
        }

        # Clear any existing FREEIPA_SERVER
        with patch.dict(os.environ, env, clear=True):
            get_settings.cache_clear()
            valid, message = validate_settings()

            assert valid is False
            assert "error" in message.lower()
