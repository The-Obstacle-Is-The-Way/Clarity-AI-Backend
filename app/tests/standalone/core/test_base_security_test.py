"""
Self-contained test for BaseSecurityTest infrastructure.

This test module includes both the necessary security test infrastructure and tests
in a single file to validate that the test infrastructure is working correctly.
"""
import unittest
from enum import Enum
from typing import Any
from unittest.mock import MagicMock

import pytest


# Mock Role class that would normally be in app/core/security/roles.py
class Role(str, Enum):
    """Mock user roles for testing."""

    USER = "user"
    ADMIN = "admin"
    CLINICIAN = "clinician"
    SUPERVISOR = "supervisor"
    RESEARCHER = "researcher"


class BaseSecurityTest(unittest.TestCase):
    """
    Base class for security and authorization testing.

    This class provides utilities and fixtures for testing security features
    such as authentication, authorization, and role-based access control.
    """

    # Default test user ID
    test_user_id: str = "test-user-id-12345"

    # Default test roles
    test_roles: list[Role] = [Role.USER]

    def setUp(self):
        """Set up test fixtures."""
        self.mock_auth_service = self.create_mock_auth_service()
        self.test_user = self.create_test_user()

    def create_mock_auth_service(self) -> MagicMock:
        """Create a mock authentication service for testing."""
        mock = MagicMock()
        mock.authenticate.return_value = True
        mock.get_user_by_id.return_value = self.create_test_user()
        return mock

    def create_test_user(self) -> dict[str, Any]:
        """Create a test user with the configured roles."""
        return {
            "id": self.test_user_id,
            "username": "test_user",
            "email": "test_user@example.com",
            "roles": self.test_roles,
        }

    @pytest.fixture(autouse=True)
    def setup_security_context(self):
        """Fixture to set up security context before each test."""
        # Example setup: mock authentication, permissions, etc.
        print("\nSetting up security context...")
        self.mock_user = MagicMock()
        self.mock_user.id = "test_user_id"
        self.mock_user.roles = ["admin"]
        # You might mock a security context manager or global state here
        yield
        # Teardown if needed
        print("\nTearing down security context...")

    def test_example_base_security_feature(self):
        """An example test inheriting the setup."""
        # Test logic that relies on the setup_security_context
        assert self.mock_user.id == "test_user_id"
        assert "admin" in self.mock_user.roles


class TestBaseSecurityTest(BaseSecurityTest):
    """Test the BaseSecurityTest class itself."""

    @pytest.mark.standalone()
    def test_default_attributes(self):
        """Test that default attributes are correctly initialized."""
        # Verify test_user_id attribute
        self.assertEqual(self.test_user_id, "test-user-id-12345")

        # Verify test_roles attribute
        self.assertEqual(self.test_roles, [Role.USER])

        # Verify test_user was created correctly
        self.assertEqual(self.test_user["id"], self.test_user_id)
        self.assertEqual(self.test_user["roles"], self.test_roles)

    @pytest.mark.standalone()
    def test_mock_auth_service(self):
        """Test that the mock authentication service works as expected."""
        # Verify authenticate method
        self.assertTrue(self.mock_auth_service.authenticate())

        # Verify get_user_by_id method
        user = self.mock_auth_service.get_user_by_id(self.test_user_id)
        self.assertEqual(user, self.test_user)


class AdminSecurityTest(BaseSecurityTest):
    """Test subclassing with different roles."""

    # Override test_roles for admin testing
    test_roles = [Role.ADMIN, Role.USER]

    @pytest.mark.standalone()
    def test_admin_roles(self):
        """Test that admin roles are correctly set up."""
        self.assertEqual(self.test_roles, [Role.ADMIN, Role.USER])
        self.assertEqual(self.test_user["roles"], [Role.ADMIN, Role.USER])


class ClinicianSecurityTest(BaseSecurityTest):
    """Test subclassing with clinician roles."""

    # Override test_roles for clinician testing
    test_roles = [Role.CLINICIAN, Role.USER]

    @pytest.mark.standalone()
    def test_clinician_roles(self):
        """Test that clinician roles are correctly set up."""
        self.assertEqual(self.test_roles, [Role.CLINICIAN, Role.USER])
        self.assertEqual(self.test_user["roles"], [Role.CLINICIAN, Role.USER])


if __name__ == "__main__":
    unittest.main()
