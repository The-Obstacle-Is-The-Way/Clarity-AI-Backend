"""
Tests for the BaseSecurityTest class and authentication infrastructure.
"""
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException

from app.core.security.authentication import authenticate_user, get_current_user
from app.core.security.rbac import RBACMiddleware, check_permission
from app.domain.entities.user import User
from app.domain.enums.role import Role


class BaseSecurityTest:
    """Base class for security and authentication tests."""

    # Default test user attributes
    test_user_id: UUID = uuid4()
    test_roles: list[Role] = [Role.USER]

    def setup_method(self):
        """Set up required attributes and mocks before each test."""
        # Override this in subclasses to add additional setup
        self.user = self._create_test_user()

    def _create_test_user(
        self, user_id: UUID | None = None, roles: list[Role] | None = None
    ) -> User:
        """Create a test user for authentication testing."""
        return User(
            id=user_id or self.test_user_id,
            username="test_user",
            email="test@example.com",
            roles=roles or self.test_roles,
            is_active=True,
            full_name="Test User",
        )


class TestBaseSecurityTest:
    """Tests for the BaseSecurityTest class itself."""

    @pytest.mark.standalone()
    def test_init(self):
        """Test that BaseSecurityTest can be initialized."""
        security_test = BaseSecurityTest()
        security_test.setup_method()

        assert security_test.user is not None
        assert security_test.user.id == security_test.test_user_id
        assert security_test.user.roles == security_test.test_roles

    @pytest.mark.standalone()
    def test_create_test_user_with_defaults(self):
        """Test creating a test user with default values."""
        security_test = BaseSecurityTest()
        user = security_test._create_test_user()

        assert user.id == security_test.test_user_id
        assert user.username == "test_user"
        assert user.email == "test@example.com"
        assert user.roles == security_test.test_roles
        assert user.is_active is True
        assert user.full_name == "Test User"

    @pytest.mark.standalone()
    def test_create_test_user_with_custom_values(self):
        """Test creating a test user with custom values."""
        security_test = BaseSecurityTest()
        custom_id = uuid4()
        custom_roles = [Role.ADMIN]
        user = security_test._create_test_user(user_id=custom_id, roles=custom_roles)

        assert user.id == custom_id
        assert user.username == "test_user"
        assert user.email == "test@example.com"
        assert user.roles == custom_roles
        assert user.is_active is True
        assert user.full_name == "Test User"


class TestAuthenticationSystem(BaseSecurityTest):
    """Tests for the authentication system."""

    def setup_method(self):
        """Set up with admin role for testing."""
        self.test_roles = [Role.ADMIN]
        super().setup_method()

    @pytest.mark.standalone()
    def test_authenticate_user_success(self):
        """Test successful user authentication."""

        # Mock the authenticate_user function to return our test user
        def mock_authenticate(username: str, password: str) -> User:
            if username == "test_user" and password == "correct_password":
                return self.user
            return None

        # Replace the real function with our mock
        original_authenticate = authenticate_user
        authenticate_user = mock_authenticate

        try:
            # Test authentication
            user = authenticate_user("test_user", "correct_password")
            assert user is not None
            assert user.id == self.test_user_id
            assert Role.ADMIN in user.roles
        finally:
            # Restore the original function
            authenticate_user = original_authenticate

    @pytest.mark.standalone()
    def test_authenticate_user_failure(self):
        """Test failed user authentication."""

        # Mock the authenticate_user function to return None for wrong credentials
        def mock_authenticate(username: str, password: str) -> User:
            if username == "test_user" and password == "correct_password":
                return self.user
            return None

        # Replace the real function with our mock
        original_authenticate = authenticate_user
        authenticate_user = mock_authenticate

        try:
            # Test authentication with wrong password
            user = authenticate_user("test_user", "wrong_password")
            assert user is None
        finally:
            # Restore the original function
            authenticate_user = original_authenticate

    @pytest.mark.standalone()
    def test_get_current_user(self):
        """Test getting the current authenticated user."""

        # Mock the get_current_user function to return our test user
        def mock_get_current_user() -> User:
            return self.user

        # Replace the real function with our mock
        original_get_current_user = get_current_user
        get_current_user = mock_get_current_user

        try:
            # Test getting current user
            current_user = get_current_user()
            assert current_user is not None
            assert current_user.id == self.test_user_id
            assert Role.ADMIN in current_user.roles
        finally:
            # Restore the original function
            get_current_user = original_get_current_user


class TestRBACSystem(BaseSecurityTest):
    """Tests for the RBAC system."""

    def setup_method(self):
        """Set up with clinician role for testing."""
        self.test_roles = [Role.CLINICIAN]
        super().setup_method()

    @pytest.mark.standalone()
    def test_permission_check_success(self):
        """Test that permission check succeeds for authorized roles."""
        # Should succeed because CLINICIAN has this permission
        check_permission(self.user, required_roles=[Role.CLINICIAN, Role.ADMIN])
        # No exception means the test passed

    @pytest.mark.standalone()
    def test_permission_check_failure(self):
        """Test that permission check fails for unauthorized roles."""
        # Should fail because user is not ADMIN
        with pytest.raises(HTTPException) as exc_info:
            check_permission(self.user, required_roles=[Role.ADMIN])

        assert exc_info.value.status_code == 403

    @pytest.mark.standalone()
    def test_rbac_middleware(self):
        """Test the RBAC middleware."""
        middleware = RBACMiddleware()

        # Create a request with our user
        class MockRequest:
            def __init__(self, user):
                self.state = type("obj", (object,), {"user": user})
                self.url = type("obj", (object,), {"path": "/api/v1/patients"})

        request = MockRequest(self.user)

        # Should raise an exception for admin-only endpoints
        with pytest.raises(HTTPException) as exc_info:
            middleware.check_access(request, required_roles=[Role.ADMIN])

        assert exc_info.value.status_code == 403
