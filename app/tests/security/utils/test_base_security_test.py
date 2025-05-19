"""
Base Security Test Class Tests

This module contains tests for the BaseSecurityTest class to ensure
proper functionality of the security test infrastructure.
"""


from app.tests.security.utils.base_security_test import BaseSecurityTest

# Mocks are likely not needed directly in this test file anymore
# from app.tests.security.utils.test_mocks import MockAuthService, MockRBACService, MockAuditLogger, MockEncryptionService, MockEntityFactory
# User and Role might not be needed if BaseSecurityTest handles setup
# from app.domain.entities.user import User
# from app.domain.enums.role import Role # Import Role enum


# Inherit directly from BaseSecurityTest if it provides the necessary fixtures via autouse
# If BaseSecurityTest is just a utility container, don't inherit.
# Assuming inheritance makes sense to get access to fixtures on self.
class TestBaseSecurityTest(BaseSecurityTest):
    """Test suite for BaseSecurityTest functionality (using pytest)."""

    # Remove setUp method, rely on autouse fixture from BaseSecurityTest

    def test_initialization(self):
        """Test that BaseSecurityTest initializes via its autouse fixture."""
        # Access attributes set by the autouse fixture in BaseSecurityTest
        assert self.test_user_id is not None
        assert isinstance(self.test_user_id, str)
        assert self.test_roles is not None
        assert "user" in self.test_roles
        assert "clinician" in self.test_roles
        # Check fixtures assigned to self
        assert self.db_session is not None  # Instance of MockAsyncSession from fixture
        assert self.entity_factory is not None  # Instance of MockEntityFactory from fixture
        assert self.rbac is not None  # Instance of RoleBasedAccessControl from fixture

    def test_has_permission(self):
        """Test permission checking functionality using instance attributes."""
        # Access self.rbac and self.test_roles set by the autouse fixture

        # Test permissions with default roles (self.test_roles)
        assert self.has_permission("read:own_data")
        assert self.has_permission("read:patient_data")
        assert not self.has_permission("delete:all_data")

        # Test with explicit roles
        assert self.has_permission("delete:all_data", roles=["admin"])
        assert not self.has_permission("delete:all_data", roles=["user"])

    def test_get_auth_token(self):
        """Test generation of authentication tokens using instance attributes."""
        # Access self.test_user_id and self.test_roles set by the autouse fixture

        # Get token with default values
        token = self.get_auth_token()
        assert isinstance(token, str)
        # Basic check for mock token structure
        assert token.startswith("mock_token.{")
        assert f"'sub': '{self.test_user_id}'" in token
        assert "'roles': ['user', 'clinician']" in token  # Based on BaseSecurityTest defaults

        # Test with custom values
        custom_user_id = "custom_user_123"
        custom_roles = ["admin", "auditor"]
        custom_claims = {"extra": "value"}

        token = self.get_auth_token(
            user_id=custom_user_id, roles=custom_roles, custom_claims=custom_claims
        )
        assert f"'sub': '{custom_user_id}'" in token
        assert f"'roles': {custom_roles!r}" in token  # Use repr for list comparison
        assert "'extra': 'value'" in token

    def test_get_auth_headers(self):
        """Test generation of authentication headers using instance methods."""
        # Access get_auth_token set by the autouse fixture

        # Get headers with default token
        headers = self.get_auth_headers()
        assert isinstance(headers, dict)
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Bearer mock_token.{")

        # Get the expected default token content
        default_token = self.get_auth_token()
        assert headers["Authorization"] == f"Bearer {default_token}"

        # Test with custom token
        custom_token = "custom.test.token"
        headers = self.get_auth_headers(token=custom_token)
        assert headers["Authorization"] == f"Bearer {custom_token}"

    # Patching should still work if the mock is correctly provided/used
    # The test method just needs access to the instance's db_session
    # No mock_session_class argument needed if we check self.db_session
    def test_db_session_setup(self):
        """Test database session fixture provides a mock session."""
        # Verify session is initialized by the autouse fixture
        assert self.db_session is not None
        # Optionally check if it's the correct mock type if needed
        # from app.tests.security.utils.test_mocks import MockAsyncSession
        # assert isinstance(self.db_session, MockAsyncSession)

    def test_entity_factory_setup(self):
        """Test entity factory fixture provides a mock factory."""
        # Verify entity factory is initialized by the autouse fixture
        assert self.entity_factory is not None
        # from app.tests.security.utils.test_mocks import MockEntityFactory
        # assert isinstance(self.entity_factory, MockEntityFactory)

        # Test creating entities using the instance's factory
        entity = self.entity_factory.create("patient", name="Test Patient")
        assert entity["type"] == "patient"
        assert entity["name"] == "Test Patient"
        assert "id" in entity

        # Test retrieving entities
        retrieved = self.entity_factory.get(entity["id"])
        assert retrieved == entity


# Remove unittest execution block
# if __name__ == "__main__":
#     unittest.main()
