"""Unit tests for the refactored Authentication Middleware in the presentation layer.

This module tests the authentication middleware which enforces secure
access to protected resources and routes in our HIPAA-compliant system.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID # For direct UUID usage if needed

from starlette.requests import Request as StarletteRequest
from fastapi import FastAPI, Request, Response, status
from starlette.authentication import AuthCredentials, UnauthenticatedUser
from starlette.datastructures import Headers, State # State might still be in scope for request creation
from starlette.responses import JSONResponse

# Import the refactored middleware and its Pydantic model
from app.presentation.middleware.authentication import AuthenticationMiddleware, AuthenticatedUser

# Domain entities & interfaces needed for mocks
from app.core.domain.entities.user import User as DomainUser, UserStatus
from app.core.interfaces.services.jwt_service import IJwtService
from app.core.interfaces.repositories.user_repository_interface import IUserRepository

# Exceptions
from app.domain.exceptions.auth_exceptions import AuthenticationException
# UserNotFoundException is raised by the middleware itself, not directly by user_repo in these tests typically
# from app.domain.exceptions.auth_exceptions import UserNotFoundException
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenExpiredException,
)

# Assuming TokenPayload is used by IJwtService.decode_token or its mock
# This import might be needed if the mock_jwt_service directly returns this type
from app.infrastructure.security.jwt_service import TokenPayload 

import logging
logger = logging.getLogger(__name__)

@pytest.fixture
def app_fixture(): # Renamed from 'app' to avoid conflict if 'app' is used as a var name
    """Create a FastAPI app for testing."""
    return FastAPI()

@pytest.fixture
def mock_jwt_service_fixture(): # Renamed fixture
    """Create an AsyncMock JWT service adhering to IJwtService."""
    mock_service = AsyncMock(spec=IJwtService)

    # decode_token is the primary method used by the middleware
    # It needs to be an AsyncMock and its side_effect should handle token strings
    async def decode_side_effect(token_str: str):
        if token_str == "valid.jwt.token":
            return TokenPayload(
                sub="user123",
                exp=9999999999, 
                iat=1713830000, 
                jti="unique-id-valid", 
                type="access", 
                scopes=["read:patients", "write:clinical_notes"]
            )
        elif token_str == "expired.jwt.token":
            raise TokenExpiredException("Token has expired")
        elif token_str == "invalid.jwt.token" or token_str == "malformed.jwt.token":
            raise InvalidTokenException("Invalid or malformed token")
        elif token_str.startswith("user_"): # For specific user ID tests
            user_id_part = token_str.split("_", 1)[1]
            return TokenPayload(
                sub=user_id_part, 
                exp=9999999999, 
                iat=1713830000, 
                jti=f"jti-{user_id_part}", 
                type="access", 
                scopes=["test_scope_user_specific"] # Specific scope for these user tokens
            )
        raise InvalidTokenException(f"Mock decode_token received unexpected token: {token_str}")

    mock_service.decode_token = AsyncMock(side_effect=decode_side_effect)
    return mock_service

@pytest.fixture
def mock_user_repo_fixture(): # Renamed fixture
    """Create an AsyncMock User Repository adhering to IUserRepository."""
    mock_repo = AsyncMock(spec=IUserRepository)

    async def get_user_by_id_side_effect(user_id: str | UUID):
        user_id_str = str(user_id) # Ensure string for comparison
        if user_id_str == "user123":
            return DomainUser(
                id=UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"), # Fixed UUID for user123
                username="doctor_user", email="doctor@example.com", 
                full_name="Dr. Valid User", status=UserStatus.ACTIVE, 
                roles=["psychiatrist"], password_hash="hashed_pass"
            )
        elif user_id_str == "inactive_user":
            return DomainUser(
                id=UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12"), # Fixed UUID
                username="inactive_user", email="inactive@example.com",
                full_name="Inactive User", status=UserStatus.INACTIVE,
                roles=["patient"], password_hash="hashed_pass"
            )
        elif user_id_str == "not_found_user":
            return None
        elif user_id_str == "repo_error_user": # For testing unexpected repo errors
            raise ValueError("Simulated repository error")
        # Add more specific user cases if needed for tests
        logger.warning(f"Mock user_repo.get_user_by_id called with unhandled ID: {user_id_str}")
        return None

    mock_repo.get_user_by_id = AsyncMock(side_effect=get_user_by_id_side_effect)
    return mock_repo

@pytest.fixture
def auth_middleware_fixture(app_fixture, mock_jwt_service_fixture, mock_user_repo_fixture):
    """Fixture to create AuthenticationMiddleware with mocked dependencies."""
    # Define some default public paths for the test middleware instance
    test_public_paths = {"/health", "/docs"}
    return AuthenticationMiddleware(
        app=app_fixture,
        jwt_service=mock_jwt_service_fixture,
        user_repo=mock_user_repo_fixture,
        public_paths=test_public_paths
    )

@pytest.fixture
def base_scope():
    """Base ASGI scope for creating requests."""
    return {
        "type": "http",
        "headers": [],
        "method": "GET",
        "path": "/api/protected_resource", 
        "state": State(), # Add state object to scope
        "app": MagicMock(spec=FastAPI) # Mock app if needed by request or middleware
    }

@pytest.fixture
def authenticated_request_fixture(base_scope): # Renamed
    """Creates a StarletteRequest with a valid JWT bearer token."""
    token = "valid.jwt.token"
    # Create a new scope for each request to avoid shared state issues
    scope = base_scope.copy()
    scope["headers"] = [(b"authorization", f"Bearer {token}".encode())]
    return StarletteRequest(scope)

@pytest.fixture
def unauthenticated_request_fixture(base_scope): # Renamed
    """Creates a StarletteRequest without an auth token."""
    scope = base_scope.copy()
    scope["headers"] = [] # Ensure no auth header
    return StarletteRequest(scope)

# Helper for call_next in tests
async def mock_call_next_base(request: Request) -> Response:
    return JSONResponse({"message": "Called next!"}, status_code=status.HTTP_200_OK)

@pytest.mark.asyncio
class TestAuthenticationMiddleware:

    async def test_valid_authentication(self, auth_middleware_fixture, authenticated_request_fixture, mock_user_repo_fixture):
        """Test successful authentication with a valid token."""
        
        async def call_next_assertions(request: Request):
            assert isinstance(request.scope.get("user"), AuthenticatedUser)
            authenticated_user: AuthenticatedUser = request.scope["user"]
            assert str(authenticated_user.id) == "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11" # Matches mock_user_repo
            
            auth_creds = request.scope.get("auth")
            assert isinstance(auth_creds, AuthCredentials)
            assert "read:patients" in auth_creds.scopes
            assert "write:clinical_notes" in auth_creds.scopes
            return JSONResponse({"status": "success"}, status_code=status.HTTP_200_OK)

        response = await auth_middleware_fixture.dispatch(authenticated_request_fixture, call_next_assertions)
        assert response.status_code == status.HTTP_200_OK
        assert json.loads(response.body) == {"status": "success"}
        mock_user_repo_fixture.get_user_by_id.assert_awaited_once_with("user123")

    async def test_missing_token(self, auth_middleware_fixture, unauthenticated_request_fixture):
        response = await auth_middleware_fixture.dispatch(unauthenticated_request_fixture, mock_call_next_base)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = json.loads(response.body)
        assert "token required" in response_data["detail"].lower()

    @pytest.mark.parametrize("token_name, expected_message_part", [
        ("invalid.jwt.token", "invalid or malformed token"),
        ("expired.jwt.token", "token has expired"),
    ])
    async def test_token_errors(self, auth_middleware_fixture, base_scope, token_name, expected_message_part, mock_jwt_service_fixture):
        scope = base_scope.copy()
        scope["headers"] = [(b"authorization", f"Bearer {token_name}".encode())]
        request = StarletteRequest(scope)
        
        response = await auth_middleware_fixture.dispatch(request, mock_call_next_base)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = json.loads(response.body)
        assert expected_message_part.lower() in response_data["detail"].lower()
        mock_jwt_service_fixture.decode_token.assert_awaited_with(token_name)

    async def test_public_path_access(self, auth_middleware_fixture, authenticated_request_fixture, mock_jwt_service_fixture):
        request = authenticated_request_fixture # Can use any request for this
        request.scope["path"] = "/health" # Set path to a public one

        async def call_next_public_assertions(req: Request):
            # User should be UnauthenticatedUser as auth is skipped
            assert isinstance(req.scope.get("user"), UnauthenticatedUser)
            assert req.scope.get("auth") is None
            return JSONResponse({"status": "healthy"}, status_code=status.HTTP_200_OK)

        response = await auth_middleware_fixture.dispatch(request, call_next_public_assertions)
        assert response.status_code == status.HTTP_200_OK
        assert json.loads(response.body) == {"status": "healthy"}
        mock_jwt_service_fixture.decode_token.assert_not_awaited() # Ensure JWT service wasn't called

    async def test_inactive_user(self, auth_middleware_fixture, base_scope, mock_user_repo_fixture):
        token = "user_inactive_user" # This token maps to inactive_user in mock_jwt_service
        scope = base_scope.copy()
        scope["headers"] = [(b"authorization", f"Bearer {token}".encode())]
        request = StarletteRequest(scope)

        response = await auth_middleware_fixture.dispatch(request, mock_call_next_base)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        response_data = json.loads(response.body)
        assert "user account is inactive" in response_data["detail"].lower()
        mock_user_repo_fixture.get_user_by_id.assert_awaited_once_with("inactive_user")

    async def test_user_not_found(self, auth_middleware_fixture, base_scope, mock_user_repo_fixture):
        token = "user_not_found_user" # Maps to not_found_user in mock_jwt_service
        scope = base_scope.copy()
        scope["headers"] = [(b"authorization", f"Bearer {token}".encode())]
        request = StarletteRequest(scope)

        response = await auth_middleware_fixture.dispatch(request, mock_call_next_base)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = json.loads(response.body)
        assert "user associated with token not found" in response_data["detail"].lower()
        mock_user_repo_fixture.get_user_by_id.assert_awaited_once_with("not_found_user")

    async def test_unexpected_repository_error(self, auth_middleware_fixture, base_scope, mock_user_repo_fixture):
        """Test how middleware handles unexpected errors from the user repository."""
        token = "user_repo_error_user" # Maps to repo_error_user in mock_jwt_service, which makes repo raise ValueError
        scope = base_scope.copy()
        scope["headers"] = [(b"authorization", f"Bearer {token}".encode())]
        request = StarletteRequest(scope)

        response = await auth_middleware_fixture.dispatch(request, mock_call_next_base)
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        response_data = json.loads(response.body)
        assert "internal server error occurred during authentication" in response_data["detail"].lower()
        mock_user_repo_fixture.get_user_by_id.assert_awaited_once_with("repo_error_user")

    async def test_authentication_scopes_propagation(self, auth_middleware_fixture, base_scope):
        """Test that scopes from JWT are correctly propagated to AuthCredentials."""
        # This token from mock_jwt_service_fixture has specific scopes
        token = "user_specific_scopes_token" # Let's assume this token will provide unique scopes
        
        # Modify mock_jwt_service_fixture's decode_token side_effect for this one token
        original_side_effect = auth_middleware_fixture.jwt_service.decode_token.side_effect
        async def custom_decode_side_effect(token_str: str):
            if token_str == token: # Target our specific token
                return TokenPayload(
                    sub="user_for_scopes_test",
                    exp=9999999999, 
                    iat=1713830000, 
                    jti="jti-scopes-test", 
                    type="access", 
                    scopes=["scope1", "scope2", "special_scope"]
                )
            return await original_side_effect(token_str) # Fallback to original mock behavior
        auth_middleware_fixture.jwt_service.decode_token.side_effect = custom_decode_side_effect
        
        # Ensure mock_user_repo returns a valid user for "user_for_scopes_test"
        original_user_repo_side_effect = auth_middleware_fixture.user_repo.get_user_by_id.side_effect
        async def custom_user_repo_side_effect(user_id):
            if str(user_id) == "user_for_scopes_test":
                # Provide missing required args for DomainUser
                return DomainUser(
                    id=UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13"), 
                    email="scopes@test.com", 
                    status=UserStatus.ACTIVE,
                    username="scopes_user", # Added
                    full_name="Scopes Test User", # Added
                    password_hash="dummy_hash_scopes" # Added
                    # roles=[] # Roles aren't strictly needed for this test, keep it simple
                )
            return await original_user_repo_side_effect(user_id)
        auth_middleware_fixture.user_repo.get_user_by_id.side_effect = custom_user_repo_side_effect

        scope = base_scope.copy()
        scope["headers"] = [(b"authorization", f"Bearer {token}".encode())]
        request = StarletteRequest(scope)

        async def call_next_scope_assertions(req: Request):
            auth_creds = req.scope.get("auth")
            assert isinstance(auth_creds, AuthCredentials)
            assert "scope1" in auth_creds.scopes
            assert "special_scope" in auth_creds.scopes
            assert len(auth_creds.scopes) == 3
            return JSONResponse({"scopes_status": "checked"}, status_code=status.HTTP_200_OK)
        
        response = await auth_middleware_fixture.dispatch(request, call_next_scope_assertions)
        assert response.status_code == status.HTTP_200_OK

        # Restore original side effects to avoid impacting other tests if fixtures are test-scoped
        auth_middleware_fixture.jwt_service.decode_token.side_effect = original_side_effect
        auth_middleware_fixture.user_repo.get_user_by_id.side_effect = original_user_repo_side_effect

