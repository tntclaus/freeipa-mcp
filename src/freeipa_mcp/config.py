"""Configuration management for FreeIPA MCP Server."""

import logging
from functools import lru_cache
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class FreeIPASettings(BaseSettings):
    """FreeIPA connection and authentication settings.

    All settings can be configured via environment variables prefixed with FREEIPA_.
    """

    model_config = SettingsConfigDict(
        env_prefix="FREEIPA_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Connection settings
    server: str = Field(
        description="FreeIPA server hostname (e.g., ipa.example.com)"
    )
    verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates when connecting to FreeIPA"
    )
    ca_cert_path: Optional[str] = Field(
        default=None,
        description="Path to CA certificate file for SSL verification"
    )

    # Authentication
    username: str = Field(
        description="FreeIPA admin username for authentication"
    )
    password: str = Field(
        description="FreeIPA admin password for authentication"
    )

    # API settings
    api_version: str = Field(
        default="2.230",
        description="FreeIPA API version (minimum 2.230 for FreeIPA 4.6.5+)"
    )

    # Operational settings
    default_limit: int = Field(
        default=100,
        ge=1,
        le=2000,
        description="Default limit for list/search operations"
    )
    request_timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Request timeout in seconds"
    )

    @field_validator("server")
    @classmethod
    def validate_server(cls, v: str) -> str:
        """Ensure server is a valid hostname without protocol prefix."""
        v = v.strip()
        if v.startswith("http://") or v.startswith("https://"):
            # Strip protocol prefix if provided
            v = v.split("://", 1)[1]
        if "/" in v:
            # Strip any path components
            v = v.split("/", 1)[0]
        return v

    @field_validator("api_version")
    @classmethod
    def validate_api_version(cls, v: str) -> str:
        """Validate API version format."""
        parts = v.split(".")
        if len(parts) != 2:
            raise ValueError("API version must be in format 'major.minor' (e.g., '2.230')")
        try:
            major, minor = int(parts[0]), int(parts[1])
            if major < 2 or (major == 2 and minor < 230):
                logger.warning(
                    f"API version {v} is below minimum supported version 2.230. "
                    "Some features may not work correctly."
                )
        except ValueError:
            raise ValueError("API version must contain numeric major.minor values")
        return v


@lru_cache
def get_settings() -> FreeIPASettings:
    """Get cached FreeIPA settings instance.

    Returns:
        FreeIPASettings: Validated settings from environment variables.

    Raises:
        ValidationError: If required settings are missing or invalid.
    """
    return FreeIPASettings()  # type: ignore[call-arg]


def validate_settings() -> tuple[bool, str]:
    """Validate that all required settings are configured.

    Returns:
        Tuple of (is_valid, message).
    """
    try:
        settings = get_settings()
        return True, f"Connected to FreeIPA server: {settings.server}"
    except Exception as e:
        return False, f"Configuration error: {e}"
