"""
Base test @pytest.mark.venv_only
class for all security and HIPAA compliance tests.

This module provides test infrastructure for security-related tests,
focusing on HIPAA compliance, PHI protection, authentication, authorization,
and other security concerns in the Novamind Digital Twin Platform.
"""
import os
from typing import Any
from unittest import TestCase
from unittest.mock import MagicMock, patch

import pytest

# Import the Role enum from the correct infrastructure location
from app.infrastructure.security.rbac.roles import Role


class BaseSecurityTest(TestCase):
    """Base class for all security-related tests.

    This class provides common setup, teardown, and utility methods
    for security testing, including mocking of authentication,
    authorization, and audit logging components.

    All security tests should inherit from this 
    class to ensure consistent
    test structure and behavior.
    """

    # Default user ID for testing:
    test_user_id: str = "test-user-id-12345"

    # Default roles for testing, to be overridden by subclasses as needed
    test_roles: list[Role] = [Role.USER]

    def setUp(self):
        """Set up security test fixtures.

        This method sets up the following:
        1. Mocked authentication context
        2. Mocked authorization service
        3. Mocked audit logger
        4. Test user with configured roles
        """
        # Create mocked components
        self.mock_auth_service = MagicMock()
        self.mock_audit_logger = MagicMock()

        # Create test user
        self.user = self._create_test_user()

        # Set up patches
        self._setup_auth_patches()
        self._setup_audit_patches()

        # Start all patches
        for patcher in self.patchers:
            patcher.start()

        # Set environment for testing
        os.environ["TESTING"] = "1"
        os.environ["ENVIRONMENT"] = "testing"

    def tearDown(self):
        """Tear down security test fixtures.

        This method cleans up all patches and mocks created during setup.
        """
        # Stop all patches
        for patcher in self.patchers:
            patcher.stop()

        # Clear environment variables
        os.environ.pop("TESTING", None)
        os.environ.pop("ENVIRONMENT", None)

    def _create_test_user(self) -> dict[str, Any]:
        """Create a test user with the configured roles.

        Returns:
            Dict[str, Any]: A dictionary representing the test user
        """
        return {
            "id": self.test_user_id,
            "username": "test_user",
            "email": "test_user@example.com",
            "roles": self.test_roles,
        }

    def _setup_auth_patches(self):
        """Set up authentication and authorization patches."""
        self.patchers = []

        # Patch get_current_user to return our test user
        current_user_patcher = patch(
            "app.core.security.auth.get_current_user", return_value=self.user
        )
        self.patchers.append(current_user_patcher)

        # Patch get_current_user_id to return our test user ID
        current_user_id_patcher = patch(
            "app.core.security.auth.get_current_user_id",
            return_value=self.test_user_id
        )
        self.patchers.append(current_user_id_patcher)

        # Patch has_role to check against our test roles
        def mock_has_role(role):
            return role in self.test_roles

        has_role_patcher = patch(
            "app.core.security.auth.has_role", side_effect=mock_has_role
        )
        self.patchers.append(has_role_patcher)

    def _setup_audit_patches(self):
        """Set up audit logging patches."""
        # Patch the audit logger to use our mock
        audit_logger_patcher = patch(
            "app.infrastructure.logging.audit_logger.AuditLogger",
            return_value=self.mock_audit_logger,
        )
        self.patchers.append(audit_logger_patcher)

    def assert_phi_access_logged(
        self, resource_type: str, resource_id: str, action: str
    ):
        """Assert that PHI access was properly logged.

        Args:
            resource_type (str): The type of resource accessed (e.g., 'patient')
            resource_id (str): The ID of the resource accessed
            action (str): The action performed (e.g., 'view', 'update')

        Raises:
            AssertionError: If PHI access was not properly logged
        """
        self.mock_audit_logger.log_phi_access.assert_called_with(
            user_id=self.test_user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=pytest.ANY,
        )

    def assert_has_required_role(self, required_role: Role):
        """Assert that the test user has the required role.

        Args:
            required_role (Role): The role that should be required

        Raises:
            AssertionError: If the test user doesn't have the required role
        """
        self.assertIn(
            required_role,
            self.test_roles,
            f"Test user doesn't have the required role: {required_role}",
        )
