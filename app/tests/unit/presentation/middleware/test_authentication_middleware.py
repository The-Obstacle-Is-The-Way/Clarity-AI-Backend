"""Unit tests for the refactored Authentication Middleware in the presentation layer.

This module tests the authentication middleware which enforces secure
access to protected resources and routes in our HIPAA-compliant system.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
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
from app.infrastructure.security.jwt.jwt_service import TokenPayload 

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
                sub="a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", # Use a valid UUID string
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
            # For repo_error_user, ensure the sub is a valid UUID string that maps to an error in user_repo
            if user_id_part == "repo_error_user":
                sub_value = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a15" # Dedicated UUID for repo error test
            elif user_id_part == "not_found_user":
                sub_value = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a14" # Dedicated UUID for not_found test
            elif user_id_part == "inactive_user":
                 sub_value = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12" # Already a UUID string
            else: # Default case for other user_ tokens if any, or could raise error
                sub_value = user_id_part # Fallback, assuming it might be a valid UUID string
            
            return TokenPayload(
                sub=sub_value, 
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
        if user_id_str == "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11": # For valid.jwt.token (user123)
            return DomainUser(
                id=UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"), 
                username="doctor_user", email="doctor@example.com", 
                full_name="Dr. Valid User", status=UserStatus.ACTIVE, 
                roles=["psychiatrist"], password_hash="hashed_pass"
            )
        elif user_id_str == "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12": # For user_inactive_user token
            return DomainUser(
                id=UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12"), 
                username="inactive_user", email="inactive@example.com",
                full_name="Inactive User", status=UserStatus.INACTIVE,
                roles=["patient"], password_hash="hashed_pass"
            )
        elif user_id_str == "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a14": # For user_not_found_user token
            return None
        elif user_id_str == "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a15": # For user_repo_error_user token
            raise ValueError("Simulated repository error")
        # Add more specific user cases if needed for tests
        logger.warning(f"Mock user_repo.get_user_by_id called with unhandled ID: {user_id_str}")
        return None

    mock_repo.get_user_by_id = AsyncMock(side_effect=get_user_by_id_side_effect)
    return mock_repo

@pytest.fixture
def auth_middleware_fixture(app_fixture, mock_jwt_service_fixture):
    """Fixture to create AuthenticationMiddleware with mocked dependencies."""
    # Define some default public paths for the test middleware instance
    test_public_paths = {"/health", "/docs"}
    # Public path regexes can be an empty list or None if not specifically testing regexes here
    test_public_path_regexes = [] 
    return AuthenticationMiddleware(
        app=app_fixture,
        jwt_service=mock_jwt_service_fixture,
        public_paths=test_public_paths,
        public_path_regexes=test_public_path_regexes # ADDED, can be None or empty list
    )

@pytest.fixture
def base_scope():
    """Base ASGI scope for creating requests."""
    app_instance_for_scope = FastAPI() 
    # app_instance_for_scope.state will be a Starlette State object by default.
    return {
        "type": "http",
        "headers": [],
        "method": "GET",
        "path": "/api/protected_resource", 
        # "state": State(),  # REMOVED - Let Request object initialize its own state.
        "app": app_instance_for_scope
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

    @patch('app.infrastructure.persistence.sqlalchemy.repositories.user_repository.SQLAlchemyUserRepository')
    async def test_valid_authentication(self, MockSQLAlchemyUserRepository, auth_middleware_fixture, authenticated_request_fixture, mock_user_repo_fixture):
        """Test successful authentication with a valid token."""
        
        mock_repo_instance = MockSQLAlchemyUserRepository.return_value
        mock_repo_instance.get_user_by_id = mock_user_repo_fixture.get_user_by_id

        # Now request.app.state exists, so we can directly set attributes on it
        authenticated_request_fixture.app.state.actual_session_factory = MagicMock()
        authenticated_request_fixture.app.state.settings = MagicMock() # also ensure settings is present if middleware checks it

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
        mock_repo_instance.get_user_by_id.assert_awaited_once_with(UUID('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11')) # Mocked instance's method is called, check with UUID

    async def test_missing_token(self, auth_middleware_fixture, unauthenticated_request_fixture):
        # Ensure app.state attributes are set for this request fixture too if dispatch might access them
        # even for paths that result in early exit (like missing token)
        unauthenticated_request_fixture.app.state.actual_session_factory = MagicMock()
        unauthenticated_request_fixture.app.state.settings = MagicMock()

        response = await auth_middleware_fixture.dispatch(unauthenticated_request_fixture, mock_call_next_base)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = json.loads(response.body)
        assert "token required" in response_data["detail"].lower()

    @patch('app.infrastructure.persistence.sqlalchemy.repositories.user_repository.SQLAlchemyUserRepository')
    @pytest.mark.parametrize("token_name, expected_message_part", [
        ("invalid.jwt.token", "invalid or malformed token"),
        ("expired.jwt.token", "token has expired"),
    ])
    async def test_token_errors(self, MockSQLAlchemyUserRepository, auth_middleware_fixture, base_scope, token_name, expected_message_part, mock_jwt_service_fixture):
        scope = base_scope.copy()
        scope["headers"] = [(b"authorization", f"Bearer {token_name}".encode())]
        request = StarletteRequest(scope)

        # request.app is from base_scope, which now has .state mocked
        request.app.state.actual_session_factory = MagicMock()
        request.app.state.settings = MagicMock()
        
        response = await auth_middleware_fixture.dispatch(request, mock_call_next_base)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = json.loads(response.body)
        assert expected_message_part.lower() in response_data["detail"].lower()
        mock_jwt_service_fixture.decode_token.assert_awaited_with(token_name)

    @patch('app.infrastructure.persistence.sqlalchemy.repositories.user_repository.SQLAlchemyUserRepository')
    async def test_public_path_access(self, MockSQLAlchemyUserRepository, auth_middleware_fixture, authenticated_request_fixture, mock_jwt_service_fixture):
        request = authenticated_request_fixture
        request.scope["path"] = "/health"

        # request.app is from base_scope (via authenticated_request_fixture), .state is mocked
        request.app.state.actual_session_factory = MagicMock()
        request.app.state.settings = MagicMock()

        async def call_next_public_assertions(req: Request):
            # User should be UnauthenticatedUser as auth is skipped
            assert isinstance(req.scope.get("user"), UnauthenticatedUser)
            assert req.scope.get("auth") is None
            return JSONResponse({"status": "healthy"}, status_code=status.HTTP_200_OK)

        response = await auth_middleware_fixture.dispatch(request, call_next_public_assertions)
        assert response.status_code == status.HTTP_200_OK
        assert json.loads(response.body) == {"status": "healthy"}
        mock_jwt_service_fixture.decode_token.assert_not_awaited() # Ensure JWT service wasn't called

    @patch('app.infrastructure.persistence.sqlalchemy.repositories.user_repository.SQLAlchemyUserRepository')
    async def test_inactive_user(self, MockSQLAlchemyUserRepository, auth_middleware_fixture, base_scope, mock_user_repo_fixture):
        mock_repo_instance = MockSQLAlchemyUserRepository.return_value
        mock_repo_instance.get_user_by_id = mock_user_repo_fixture.get_user_by_id

        token = "user_inactive_user"
        scope = base_scope.copy()
        scope["headers"] = [(b"authorization", f"Bearer {token}".encode())]
        request = StarletteRequest(scope)

        request.app.state.actual_session_factory = MagicMock()
        request.app.state.settings = MagicMock()

        response = await auth_middleware_fixture.dispatch(request, mock_call_next_base)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        response_data = json.loads(response.body)
        assert "user account is inactive" in response_data["detail"].lower()
        mock_repo_instance.get_user_by_id.assert_awaited_once_with(UUID('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12')) # Check with UUID

    @patch('app.infrastructure.persistence.sqlalchemy.repositories.user_repository.SQLAlchemyUserRepository')
    async def test_user_not_found(self, MockSQLAlchemyUserRepository, auth_middleware_fixture, base_scope, mock_user_repo_fixture):
        mock_repo_instance = MockSQLAlchemyUserRepository.return_value
        mock_repo_instance.get_user_by_id = mock_user_repo_fixture.get_user_by_id

        token = "user_not_found_user"
        scope = base_scope.copy()
        scope["headers"] = [(b"authorization", f"Bearer {token}".encode())]
        request = StarletteRequest(scope)

        request.app.state.actual_session_factory = MagicMock()
        request.app.state.settings = MagicMock()

        response = await auth_middleware_fixture.dispatch(request, mock_call_next_base)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_data = json.loads(response.body)
        assert "user associated with token not found" in response_data["detail"].lower()
        # Check with the UUID string defined in mock_jwt_service_fixture for 'not_found_user'
        mock_repo_instance.get_user_by_id.assert_awaited_once_with(UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a14"))

    @patch('app.infrastructure.persistence.sqlalchemy.repositories.user_repository.SQLAlchemyUserRepository')
    async def test_unexpected_repository_error(self, MockSQLAlchemyUserRepository, auth_middleware_fixture, base_scope, mock_user_repo_fixture):
        """Test how middleware handles unexpected errors from the user repository."""
        mock_repo_instance = MockSQLAlchemyUserRepository.return_value
        mock_repo_instance.get_user_by_id = mock_user_repo_fixture.get_user_by_id
        
        token = "user_repo_error_user" 
        scope = base_scope.copy()
        scope["headers"] = [(b"authorization", f"Bearer {token}".encode())]
        request = StarletteRequest(scope)

        request.app.state.actual_session_factory = MagicMock()
        request.app.state.settings = MagicMock()

        response = await auth_middleware_fixture.dispatch(request, mock_call_next_base)
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        response_data = json.loads(response.body)
        assert "internal server error occurred during authentication" in response_data["detail"].lower()
        # Assert that get_user_by_id was called with the specific UUID that triggers the error
        mock_repo_instance.get_user_by_id.assert_awaited_once_with(UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a15"))

    @patch('app.infrastructure.persistence.sqlalchemy.repositories.user_repository.SQLAlchemyUserRepository')
    async def test_authentication_scopes_propagation(self, MockSQLAlchemyUserRepository, auth_middleware_fixture, base_scope, mock_jwt_service_fixture, mock_user_repo_fixture):
        mock_repo_instance = MockSQLAlchemyUserRepository.return_value
        # ... (custom_decode_side_effect and custom_user_repo_side_effect definitions remain the same)
        async def custom_decode_side_effect(token_str: str):
            if token_str == "scoped.token":
                return TokenPayload(
                    sub="a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13", # CHANGED to valid UUID string
                    exp=9999999999, 
                    iat=1713830000, 
                    jti="jti-scoped", 
                    type="access", 
                    scopes=["scope1", "scope2", "admin:all"]
                )
            raise InvalidTokenException(f"Unexpected token in custom_decode_side_effect: {token_str}")
        
        original_decode_token = mock_jwt_service_fixture.decode_token
        mock_jwt_service_fixture.decode_token = AsyncMock(side_effect=custom_decode_side_effect)

        async def custom_user_repo_side_effect(user_id: str | UUID):
            # CHANGED to expect the UUID string used in custom_decode_side_effect
            if str(user_id) == "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13": 
                return DomainUser(
                    id=UUID("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13"), 
                    username="scoped_user", email="scoped@example.com",
                    full_name="Scoped User", status=UserStatus.ACTIVE,
                    roles=["user"], password_hash="hashed_pass"
                )
            return None
        mock_repo_instance.get_user_by_id = AsyncMock(side_effect=custom_user_repo_side_effect)

        token_str = "scoped.token"
        scope = base_scope.copy()
        scope["headers"] = [(b"authorization", f"Bearer {token_str}".encode())]
        request = StarletteRequest(scope)

        request.app.state.actual_session_factory = MagicMock()
        request.app.state.settings = MagicMock()

        async def call_next_scope_assertions(req: Request):
            assert isinstance(req.scope.get("user"), AuthenticatedUser)
            assert str(req.scope["user"].id) == "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13"
            
            auth_creds = req.scope.get("auth")
            assert isinstance(auth_creds, AuthCredentials)
            assert "scope1" in auth_creds.scopes
            assert "scope2" in auth_creds.scopes
            assert "admin:all" in auth_creds.scopes
            return JSONResponse({"status": "scoped_success"}, status_code=status.HTTP_200_OK)

        response = await auth_middleware_fixture.dispatch(request, call_next_scope_assertions)
        assert response.status_code == status.HTTP_200_OK
        assert json.loads(response.body) == {"status": "scoped_success"}
        mock_jwt_service_fixture.decode_token.assert_awaited_once_with(token_str)
        mock_repo_instance.get_user_by_id.assert_awaited_once_with(UUID('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a13'))

        # Restore original decode_token on the shared mock_jwt_service_fixture
        mock_jwt_service_fixture.decode_token = original_decode_token

