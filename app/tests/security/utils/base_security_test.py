"""
Base Security Test Case

This module provides a base test case for security-related tests with
proper authentication setup and user role management.
"""

import uuid
from typing import Any

# Remove unittest import
# from unittest import TestCase
import pytest

from app.core.domain.entities.user import User, UserRole

# Import mocks for testing
from app.tests.security.utils.test_mocks import (
    MockAsyncSession,
    MockEntityFactory,
    RoleBasedAccessControl,
)

# We're now using the MockEntityFactory from test_mocks.py


# Remove inheritance from TestCase
class BaseSecurityTest:
    """
    Base class structure for security and authentication tests (using pytest fixtures).

    Provides common attributes and fixtures for security tests including:
        - Test user ID and roles
        - Mock database session
        - Mock entity factory
        - Mock RBAC setup
    """

    @pytest.fixture(autouse=True)
    def setup_security_test(self, mock_db_session, mock_entity_factory, mock_rbac):
        """Auto-use fixture to set up common attributes for each test method."""
        # Initialize authentication attributes
        self.test_user_id = str(uuid.uuid4())
        self.test_roles = ["user", "clinician"]

        # Assign mocked fixtures to instance attributes
        self.db_session = mock_db_session
        self.entity_factory = mock_entity_factory
        self.rbac = mock_rbac

    # Convert setUp logic into fixtures
    @pytest.fixture(scope="function")  # Scope per test function
    def mock_db_session(self):
        """Provides a mock database session."""
        return MockAsyncSession()

    @pytest.fixture(scope="function")
    def mock_entity_factory(self):
        """Provides a mock entity factory."""
        return MockEntityFactory()

    @pytest.fixture(scope="function")
    def mock_rbac(self):
        """Provides a mock RBAC service configured with test permissions."""
        rbac = RoleBasedAccessControl()
        # Add roles first
        rbac.add_role("user")
        rbac.add_role("clinician")
        rbac.add_role("admin")

        # Default role configuration for tests
        rbac.add_role_permission("user", "read:own_data")
        rbac.add_role_permission("user", "update:own_data")

        rbac.add_role_permission("clinician", "read:patient_data")
        rbac.add_role_permission("clinician", "update:patient_data")
        rbac.add_role_permission("clinician", "read:clinical_notes")

        rbac.add_role_permission("admin", "read:all_data")
        rbac.add_role_permission("admin", "update:all_data")
        rbac.add_role_permission("admin", "delete:all_data")
        return rbac

    # Helper methods remain as regular methods
    def has_permission(self, permission: str, roles: list[str] | None = None) -> bool:
        """
        Check if the specified roles have the given permission using the instance's rbac.

        Args:
            permission: The permission to check
            roles: The roles to check. If None, uses the instance's test_roles

        Returns:
            bool: True if any of the roles have the permission, False otherwise
        """
        check_roles = roles if roles is not None else self.test_roles

        # Check if any role has the permission
        for role in check_roles:
            # Use self.rbac which is set up by the fixture
            if self.rbac.has_permission(role, permission):
                return True

        return False

    def get_auth_token(
        self,
        user_id: str | None = None,
        roles: list[str] | None = None,
        custom_claims: dict[str, Any] | None = None,
    ) -> str:
        """
        Generate a mock authentication token for testing.

        Args:
            user_id: The user ID to include in the token. Default uses instance's test_user_id.
            roles: The roles to include in the token. Default uses instance's test_roles.
            custom_claims: Additional claims to include in the token.

        Returns:
            str: A mock authentication token
        """
        claims = {
            "sub": user_id or self.test_user_id,  # Use instance attribute
            "roles": roles or self.test_roles,  # Use instance attribute
            **(custom_claims or {}),
        }
        # Mock token is just the string representation of the claims for
        # testing
        return f"mock_token.{claims!s}"

    def get_auth_headers(self, token: str | None = None) -> dict[str, str]:
        """
        Generate mock authentication headers for testing.

        Args:
            token: The token to include in the headers. Default is generated
                   with get_auth_token().

        Returns:
            Dict[str, str]: Mock authorization headers
        """
        auth_token = token or self.get_auth_token()
        return {"Authorization": f"Bearer {auth_token}"}

    # Remove tearDown method, pytest handles fixture cleanup automatically
    # Remove standalone pytest fixtures defined within the class if they are not needed or move them outside
    # Define a pytest fixture for easy reuse in pytest-based tests
    # @pytest.fixture
    # def security_test_base(self):
    #     """Pytest fixture that provides a configured security test base."""
    #     test_base = BaseSecurityTest()
    #     test_base.setUp() # This setUp is gone now
    #     yield test_base
    #     # tearDown is also gone

    # @pytest.fixture
    # def mock_auth_headers(self, security_test_base):
    #     """Pytest fixture that provides mock authentication headers."""
    #     return security_test_base.get_auth_headers()

    # Keep mock_db_session fixture defined above
    # @pytest.fixture
    # def mock_db_session(self):
    #     """Pytest fixture that provides a mock database session."""
    #     session = MockAsyncSession()
    #     yield session

    @pytest.fixture
    def mock_user(
        self,
        mock_db_session,
        user_id="test_user_id",
        email="test@example.com",
        roles: list[str] | None = None,
    ):
        """Helper to create a mock user with specific roles."""
        if roles is None:
            roles = self.test_roles
        # Implementation of creating a mock user with the specified roles
        # This is a placeholder and should be replaced with the actual implementation
        # based on the mock_db_session and the roles
        return User(id=user_id, email=email, roles=[UserRole(role) for role in roles])
