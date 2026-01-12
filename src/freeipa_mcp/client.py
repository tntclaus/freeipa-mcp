"""FreeIPA client wrapper with connection management and error handling."""

import logging
from contextlib import contextmanager
from functools import lru_cache
from typing import Any, Generator, Optional

from python_freeipa import ClientMeta
from python_freeipa.exceptions import (
    BadRequest,
    FreeIPAError,
    NotFound,
    Unauthorized,
    ValidationError,
)

from .config import get_settings

logger = logging.getLogger(__name__)


class FreeIPAClientError(Exception):
    """Base exception for FreeIPA client errors."""

    def __init__(self, message: str, code: Optional[str] = None, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class AuthenticationError(FreeIPAClientError):
    """Raised when authentication fails."""
    pass


class ObjectNotFoundError(FreeIPAClientError):
    """Raised when a requested object is not found."""
    pass


class ObjectExistsError(FreeIPAClientError):
    """Raised when trying to create an object that already exists."""
    pass


class PermissionDeniedError(FreeIPAClientError):
    """Raised when operation is not permitted."""
    pass


class FreeIPAClient:
    """Wrapper around python-freeipa ClientMeta with improved error handling.

    This client manages connection lifecycle, authentication, and provides
    consistent error handling for all FreeIPA operations.
    """

    def __init__(self):
        """Initialize the FreeIPA client."""
        self._settings = get_settings()
        self._client: Optional[ClientMeta] = None
        self._authenticated = False

    @property
    def client(self) -> ClientMeta:
        """Get authenticated FreeIPA client, connecting if necessary."""
        if self._client is None or not self._authenticated:
            self._connect()
        return self._client  # type: ignore[return-value]

    def _connect(self) -> None:
        """Establish connection and authenticate to FreeIPA."""
        settings = self._settings
        logger.info(f"Connecting to FreeIPA server: {settings.server}")

        try:
            self._client = ClientMeta(
                host=settings.server,
                verify_ssl=settings.verify_ssl,
            )

            self._client.login(
                username=settings.username,
                password=settings.password,
            )
            self._authenticated = True
            logger.info("Successfully authenticated to FreeIPA")

        except Unauthorized as e:
            self._authenticated = False
            raise AuthenticationError(
                f"Authentication failed for user '{settings.username}': {e}",
                code="AUTH_FAILED"
            )
        except Exception as e:
            self._authenticated = False
            raise FreeIPAClientError(
                f"Failed to connect to FreeIPA server '{settings.server}': {e}",
                code="CONNECTION_FAILED"
            )

    def disconnect(self) -> None:
        """Logout and close connection to FreeIPA."""
        if self._client and self._authenticated:
            try:
                self._client.logout()
                logger.info("Disconnected from FreeIPA")
            except Exception as e:
                logger.warning(f"Error during logout: {e}")
            finally:
                self._authenticated = False

    def _handle_error(self, operation: str, error: Exception) -> None:
        """Convert FreeIPA exceptions to our typed exceptions."""
        error_msg = str(error)

        if isinstance(error, NotFound):
            raise ObjectNotFoundError(
                f"{operation}: Object not found - {error_msg}",
                code="NOT_FOUND"
            )
        elif isinstance(error, Unauthorized):
            self._authenticated = False
            raise AuthenticationError(
                f"{operation}: Authentication required - {error_msg}",
                code="AUTH_REQUIRED"
            )
        elif isinstance(error, ValidationError):
            raise FreeIPAClientError(
                f"{operation}: Validation error - {error_msg}",
                code="VALIDATION_ERROR"
            )
        elif isinstance(error, BadRequest):
            # Check for duplicate entry
            if "already exists" in error_msg.lower() or "duplicate" in error_msg.lower():
                raise ObjectExistsError(
                    f"{operation}: Object already exists - {error_msg}",
                    code="DUPLICATE_ENTRY"
                )
            raise FreeIPAClientError(
                f"{operation}: Bad request - {error_msg}",
                code="BAD_REQUEST"
            )
        elif isinstance(error, FreeIPAError):
            raise FreeIPAClientError(
                f"{operation}: FreeIPA error - {error_msg}",
                code="IPA_ERROR"
            )
        else:
            raise FreeIPAClientError(
                f"{operation}: Unexpected error - {error_msg}",
                code="UNKNOWN_ERROR"
            )

    def execute(self, method: str, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Execute a FreeIPA API method with error handling.

        Args:
            method: The FreeIPA API method name (e.g., 'user_find', 'group_add')
            *args: Positional arguments for the method
            **kwargs: Keyword arguments for the method

        Returns:
            The result dictionary from FreeIPA

        Raises:
            FreeIPAClientError: On any FreeIPA error
        """
        try:
            api_method = getattr(self.client, method)
            result = api_method(*args, **kwargs)

            # python-freeipa returns different structures depending on method
            # Normalize to always return a dict
            if isinstance(result, dict):
                return result
            return {"result": result}

        except (NotFound, Unauthorized, ValidationError, BadRequest, FreeIPAError) as e:
            self._handle_error(method, e)
            raise  # unreachable but keeps type checker happy
        except AttributeError:
            raise FreeIPAClientError(
                f"Unknown FreeIPA method: {method}",
                code="UNKNOWN_METHOD"
            )
        except Exception as e:
            self._handle_error(method, e)
            raise  # unreachable but keeps type checker happy

    # Convenience methods for common operations

    def user_find(self, **criteria: Any) -> dict[str, Any]:
        """Search for users matching criteria."""
        return self.execute("user_find", **criteria)

    def user_show(self, uid: str, **kwargs: Any) -> dict[str, Any]:
        """Get detailed information about a user."""
        return self.execute("user_show", uid, **kwargs)

    def user_add(self, uid: str, **attrs: Any) -> dict[str, Any]:
        """Create a new user."""
        return self.execute("user_add", uid, **attrs)

    def user_mod(self, uid: str, **attrs: Any) -> dict[str, Any]:
        """Modify an existing user."""
        return self.execute("user_mod", uid, **attrs)

    def user_del(self, uid: str, **kwargs: Any) -> dict[str, Any]:
        """Delete a user."""
        return self.execute("user_del", uid, **kwargs)

    def group_find(self, **criteria: Any) -> dict[str, Any]:
        """Search for groups matching criteria."""
        return self.execute("group_find", **criteria)

    def group_show(self, cn: str, **kwargs: Any) -> dict[str, Any]:
        """Get detailed information about a group."""
        return self.execute("group_show", cn, **kwargs)

    def group_add(self, cn: str, **attrs: Any) -> dict[str, Any]:
        """Create a new group."""
        return self.execute("group_add", cn, **attrs)

    def group_mod(self, cn: str, **attrs: Any) -> dict[str, Any]:
        """Modify an existing group."""
        return self.execute("group_mod", cn, **attrs)

    def group_del(self, cn: str, **kwargs: Any) -> dict[str, Any]:
        """Delete a group."""
        return self.execute("group_del", cn, **kwargs)

    def group_add_member(self, cn: str, **members: Any) -> dict[str, Any]:
        """Add members to a group."""
        return self.execute("group_add_member", cn, **members)

    def group_remove_member(self, cn: str, **members: Any) -> dict[str, Any]:
        """Remove members from a group."""
        return self.execute("group_remove_member", cn, **members)

    def host_find(self, **criteria: Any) -> dict[str, Any]:
        """Search for hosts matching criteria."""
        return self.execute("host_find", **criteria)

    def host_show(self, fqdn: str, **kwargs: Any) -> dict[str, Any]:
        """Get detailed information about a host."""
        return self.execute("host_show", fqdn, **kwargs)

    def host_add(self, fqdn: str, **attrs: Any) -> dict[str, Any]:
        """Register a new host."""
        return self.execute("host_add", fqdn, **attrs)

    def host_mod(self, fqdn: str, **attrs: Any) -> dict[str, Any]:
        """Modify an existing host."""
        return self.execute("host_mod", fqdn, **attrs)

    def host_del(self, fqdn: str, **kwargs: Any) -> dict[str, Any]:
        """Delete a host."""
        return self.execute("host_del", fqdn, **kwargs)


# Global client instance (lazy initialization)
_client: Optional[FreeIPAClient] = None


def get_client() -> FreeIPAClient:
    """Get the global FreeIPA client instance.

    Returns:
        FreeIPAClient: The singleton client instance.
    """
    global _client
    if _client is None:
        _client = FreeIPAClient()
    return _client


def reset_client() -> None:
    """Reset the global client (useful for testing or reconnection)."""
    global _client
    if _client:
        _client.disconnect()
    _client = None


@contextmanager
def freeipa_session() -> Generator[FreeIPAClient, None, None]:
    """Context manager for FreeIPA operations.

    Ensures proper cleanup of the session after use.

    Yields:
        FreeIPAClient: Connected client instance.
    """
    client = get_client()
    try:
        yield client
    finally:
        # Don't disconnect - we want to reuse the session
        pass
