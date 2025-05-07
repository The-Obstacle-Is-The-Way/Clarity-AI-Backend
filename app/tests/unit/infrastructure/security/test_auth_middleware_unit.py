"""Unit tests for Authentication Middleware functionality.

This module tests the authentication middleware which enforces secure
access to protected resources and routes in our HIPAA-compliant system.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.requests import Request as StarletteRequest # Import real Request

# Using pytest-asyncio for async tests
from fastapi import FastAPI, Request, Response, status
from starlette.authentication import AuthCredentials, UnauthenticatedUser
from starlette.datastructures import Headers, State
from starlette.responses import JSONResponse

from app.core.domain.entities.user import User  # Import User model for mocking
from app.core.domain.entities.user import UserStatus # Import UserStatus enum
from app.domain.exceptions.auth_exceptions import AuthenticationException
from app.domain.exceptions import EntityNotFoundError

# Import exceptions from their correct locations
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenExpiredException,
)
from app.infrastructure.security.auth_service import (
    AuthenticationService,  # Assuming needed for mocking type
)

# Import the TokenPayload model
from app.infrastructure.security.jwt_service import JWTService

# Assuming RoleBasedAccessControl is correctly defined/imported
# If not, define a mock or import the actual class
try:
    from app.infrastructure.security.rbac import RoleBasedAccessControl
except ImportError:
    class RoleBasedAccessControl: # Mock if not available
        def has_permission(self, roles: list, permission: str) -> bool:
            print(f"Mock RBAC check: Roles={roles}, Permission={permission}")
            # Default allow for basic tests, override in specific tests
            return True

# Import the middleware being tested
from app.core.security.middleware import AuthenticationMiddleware as AuthMiddleware

# Mock TokenAuthorizationError if it's a custom exception used internally
# class TokenAuthorizationError(Exception):
#     """Mock TokenAuthorizationError for testing"""
#     pass

# Mock classes needed for tests if they are not imported elsewhere
# class JWTAuthBackend:
#     """Mock JWT authentication backend for testing."""
#     pass
# class CognitoAuthBackend:
#     """Mock Cognito authentication backend for testing."""
#     pass

@pytest.fixture
def auth_config():
    """Create a mock auth config for testing."""
    config = MagicMock()
    config.enabled = True
    config.auth_header_name = "Authorization"
    config.auth_scheme = "Bearer"
    # Use actual paths from middleware defaults or pass specific ones
    config.exempt_paths = ["/health", "/docs", "/redoc", "/openapi.json", "/"] 
    config.strict_scopes = True
    config.admin_role = "admin"
    return config

@pytest.fixture
def app():
    """Create a FastAPI app for testing."""
    return FastAPI()

@pytest.fixture
def mock_jwt_service():
    """Create an AsyncMock JWT service."""
    # Import TokenPayload here to ensure it's in scope for decode_side_effect
    from app.infrastructure.security.jwt_service import TokenPayload
    mock_service = MagicMock(spec=JWTService) # Mock the service instance
    
    # Create individual AsyncMocks for each method we need to configure
    mock_decode_token_method = MagicMock() 
    
    # Configure the side effect of the method mock
    def decode_side_effect(token): # No longer async
        if token == "valid.jwt.token":
            return TokenPayload(
                sub="user123",
                exp=9999999999,  # Far future timestamp
                iat=1713830000,  # Past timestamp
                jti="unique-id",
                type="access",
                scopes=["read:patients", "write:clinical_notes"]
            )
        elif token == "expired.jwt.token":
            raise TokenExpiredException("Token has expired")
        elif token == "invalid.jwt.token" or token == "malformed.jwt.token":
             raise InvalidTokenException("Invalid or malformed token")
        else:
            # Handle tokens representing specific user IDs for other tests
            # Example token format: user_inactive_user, user_not_found_user, etc.
            if token.startswith("user_"):
                 user_id_part = token.split("_", 1)[1] # Extract user ID part after "user_"
                 return TokenPayload(
                     sub=user_id_part, 
                     exp=9999999999, 
                     iat=1713830000, 
                     jti=f"jti-{user_id_part}", 
                     type="access", 
                     scopes=["test_scope"]
                 )
            # Default case if token format is unexpected in tests
            raise InvalidTokenException(f"Unexpected token format in test: {token}")
            
    mock_decode_token_method.side_effect = decode_side_effect
    # Assign the configured method mock to the service mock
    mock_service.decode_token = mock_decode_token_method
    
    return mock_service

@pytest.fixture
def mock_auth_service():
    """Create an AsyncMock authentication service."""
    mock_service = AsyncMock(spec=AuthenticationService)
    
    # Create an AsyncMock for the get_user_by_id method
    mock_get_user_method = AsyncMock()

    # Configure the side effect for get_user_by_id
    async def get_user_side_effect(user_id):
        if user_id == "user123":
            # Standard valid, active user
            return User(
                id="user123", 
                email="doctor@example.com", 
                username="doctor_user", # Added username
                full_name="Dr. User", # Added full_name
                status=UserStatus.ACTIVE, # Use status
                roles={"psychiatrist"}, # roles should be a set
                password_hash="dummy_hash", # Use a non-empty placeholder
            )
        elif user_id == "inactive_user":
             # Inactive user
             return User(
                id="inactive_user", 
                email="inactive@example.com", 
                username="inactive_username", # Added username
                full_name="Inactive User", # Added full_name
                status=UserStatus.INACTIVE, # Use status
                roles={"patient"}, 
                password_hash="dummy_hash" # Use a non-empty placeholder
            )
        elif user_id == "not_found_user":
            # Middleware's validate_token_and_get_user will raise UserNotFoundException
            return None 
        elif user_id == "auth_error_user":
            # User that causes a generic AuthenticationError (used for testing 401 from specific handler)
            raise AuthenticationException("Simulated auth service error") 
        else:
            # Default: return None for any other unexpected IDs
            logger.warning(f"mock_auth_service received unexpected user_id: {user_id}")
            return None
            
    mock_get_user_method.side_effect = get_user_side_effect
    # Assign the configured method mock to the service mock
    mock_service.get_user_by_id = mock_get_user_method
    
    return mock_service
    
@pytest.fixture
def auth_middleware(app, mock_jwt_service, mock_auth_service, auth_config):
    """Create an authentication middleware instance with async mocks."""
    async def get_mock_auth():
        return mock_auth_service
    async def get_mock_jwt(): # This getter will now be used
        return mock_jwt_service

    middleware = AuthMiddleware(
        app=app,
        auth_service=get_mock_auth, 
        jwt_service=get_mock_jwt, # Pass the mock_jwt_service via its getter
        public_paths=list(auth_config.exempt_paths)
    )
    return middleware

# Using Starlette Headers directly, ensure tests provide dicts or valid Headers objects
# If custom MockHeaders is needed due to specific interactions, define it here.

@pytest.fixture
def authenticated_request(mock_jwt_service): # Pass service if needed to generate token
    """Create a realistic Starlette request object for authentication tests."""
    scope = {
        "type": "http", 
        "headers": [], # Headers will be set per test by modifying scope['headers']
        "method": "GET", 
        "path": "/api/patients", 
        "state": State(),
        "app": FastAPI() # Mock app instance
    }
    return StarletteRequest(scope) # Use a real Starlette Request

@pytest.fixture
def unauthenticated_request():
    """Create a mock request without an authentication token."""
    mock_request = MagicMock(spec=Request)
    mock_request.method = "GET"
    mock_request.url = MagicMock()
    mock_request.url.path = "/api/patients"
    state = State()
    headers_list: list[tuple[bytes, bytes]] = []
    mock_request.scope = {
        "type": "http", "method": "GET", "path": "/api/patients",
        "headers": headers_list, "app": FastAPI(), "state": state
    }
    mock_request.headers = Headers(scope=mock_request.scope)
    mock_request.state = state
    mock_request.cookies = {}
    return mock_request


@pytest.mark.asyncio # Ensure all tests are marked for asyncio
class TestAuthMiddleware:
    """Test suite for the authentication middleware (async)."""

    async def test_valid_authentication(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request,
        mock_jwt_service: MagicMock, 
        mock_auth_service: AsyncMock
    ):
        """Test successful authentication with a valid token."""
        token = "valid.jwt.token"
        # Set headers directly in scope
        authenticated_request.scope['headers'] = [(b"authorization", f"Bearer {token}".encode())]

        async def mock_call_next(request: Request) -> Response:
            """Mock call_next, asserting that the user and auth are correctly set."""
            assert isinstance(request.scope["user"], User)
            assert request.scope["user"].id == "user123"
            assert isinstance(request.scope["auth"], AuthCredentials)
            assert "read:patients" in request.scope["auth"].scopes
            return JSONResponse({"status": "success"}, status_code=status.HTTP_200_OK)

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next)

        assert response.status_code == 200 # Expect 200 for valid auth
        assert json.loads(response.body) == {"status": "success"}
        # Assert await was called on async mocks
        mock_jwt_service.decode_token.assert_called_once_with("valid.jwt.token")
        mock_auth_service.get_user_by_id.assert_awaited_once_with("user123")

    async def test_missing_token(
        self,
        auth_middleware: AuthMiddleware,
        unauthenticated_request: Request
    ):
        """Test handling of a request without an authentication token."""
        async def mock_call_next(request: Request) -> Response:
             pytest.fail("call_next should not be invoked for missing token on protected route")
             return JSONResponse({}) # Should not happen

        response = await auth_middleware.dispatch(unauthenticated_request, mock_call_next)
        
        # Expect 401 Unauthorized
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "required" in response_body["detail"].lower()
        assert "no token" in response_body["detail"].lower() # Check for specific message

    async def test_invalid_token(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, 
        mock_jwt_service: MagicMock
    ):
        """Test that an invalid token results in a 401 Unauthorized response."""
        token = "invalid.jwt.token"
        authenticated_request.scope['headers'] = [(b"authorization", f"Bearer {token}".encode())]

        async def mock_call_next(request: Request) -> Response:
            pytest.fail("call_next should not be invoked for invalid token")
            return JSONResponse({}) 

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next)
        
        # Middleware specific exception handling should yield 401
        assert response.status_code == status.HTTP_401_UNAUTHORIZED 
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "invalid or malformed token" in response_body["detail"].lower()
        mock_jwt_service.decode_token.assert_called_once_with("invalid.jwt.token")

    async def test_expired_token(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, 
        mock_jwt_service: MagicMock
    ):
        """Test that an expired token results in a 401 Unauthorized response."""
        token = "expired.jwt.token"
        authenticated_request.scope['headers'] = [(b"authorization", f"Bearer {token}".encode())]

        async def mock_call_next(request: Request) -> Response:
            pytest.fail("call_next should not be invoked for expired token")
            return JSONResponse({}) 

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next)
        
        # Middleware specific exception handling should yield 401
        assert response.status_code == status.HTTP_401_UNAUTHORIZED 
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "token has expired" in response_body["detail"].lower()
        mock_jwt_service.decode_token.assert_called_once_with("expired.jwt.token")

    async def test_exempt_path(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, 
        mock_jwt_service: MagicMock, 
        mock_auth_service: AsyncMock
    ):
        """Test that exempt paths are correctly handled and bypass token validation."""
        # Modify the request path directly in scope
        authenticated_request.scope["path"] = "/health" 

        async def mock_call_next(request: Request) -> Response:
            """Mock call_next, asserting that the user is unauthenticated."""
            assert isinstance(request.scope["user"], UnauthenticatedUser)
            assert request.scope["auth"] is None
            return JSONResponse(content={"status": "healthy"})

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next)
        
        assert response.status_code == 200
        assert json.loads(response.body) == {"status": "healthy"}
        # Ensure token validation services were NOT called
        mock_jwt_service.decode_token.assert_not_called()
        mock_auth_service.get_user_by_id.assert_not_called()

    # test_testing_mode_middleware might need rethinking or removal
    # if TESTING mode bypass is handled differently or removed.
    # Skipping for now as it depends on settings logic not shown.

    async def test_authentication_with_roles_success(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request,
        mock_jwt_service: MagicMock,
        mock_auth_service: AsyncMock
    ):
        """Test successful authentication for a user with roles."""
        token = "valid.jwt.token" # Uses the same valid token as test_valid_authentication
        authenticated_request.scope['headers'] = [(b"authorization", f"Bearer {token}".encode())]
        # Ensure path is what's expected if it was changed by another test using the same fixture instance
        authenticated_request.scope["path"] = "/api/patients/roles" 

        async def mock_call_next_success(request: Request) -> Response:
            """Mock call_next, asserting user and auth are set after successful auth."""
            assert isinstance(request.scope["user"], User) # Check scope
            assert request.scope["user"].id == "user123" 
            assert isinstance(request.scope["auth"], AuthCredentials) # Check scope
            assert "read:patients" in request.scope["auth"].scopes # Align with valid.jwt.token scopes
            return JSONResponse({"auth": "ok"}, status_code=status.HTTP_200_OK)

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next_success)

        assert response.status_code == 200
        assert json.loads(response.body) == {"auth": "ok"}
        mock_jwt_service.decode_token.assert_called_once_with("valid.jwt.token")
        mock_auth_service.get_user_by_id.assert_awaited_once_with("user123")

    async def test_inactive_user_authentication_failure(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, 
        mock_jwt_service: MagicMock,
        mock_auth_service: AsyncMock
    ):
        """Test that an inactive user results in a 403 Forbidden response."""
        token = "user_inactive_user"
        authenticated_request.scope['headers'] = [(b"authorization", f"Bearer {token}".encode())]
        # Ensure path is not an exempt one if modified by other tests
        authenticated_request.scope["path"] = "/api/protected/inactive_check"

        async def mock_call_next_fail(request: Request) -> Response:
            pytest.fail("call_next should not be invoked for inactive user")
            return JSONResponse({}) 

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)

        # Middleware returns 403 for inactive user
        assert response.status_code == status.HTTP_403_FORBIDDEN 
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "user account is inactive" in response_body["detail"].lower()
        # Verify services were called correctly
        mock_jwt_service.decode_token.assert_called_once_with("user_inactive_user")
        mock_auth_service.get_user_by_id.assert_awaited_once_with("inactive_user") 

    async def test_user_not_found_authentication_failure(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, 
        mock_jwt_service: MagicMock,
        mock_auth_service: AsyncMock
    ):
        """Test that a user not found results in a 401 Unauthorized response."""
        token = "user_not_found_user"
        authenticated_request.scope['headers'] = [(b"authorization", f"Bearer {token}".encode())]
        authenticated_request.scope["path"] = "/api/protected/notfound_check"

        async def mock_call_next_fail(request: Request) -> Response:
            pytest.fail("call_next should not be invoked for user not found")
            return JSONResponse({}) 

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED 
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "user associated with token not found" in response_body["detail"].lower() 
        # Verify services were called correctly
        mock_jwt_service.decode_token.assert_called_once_with("user_not_found_user")
        mock_auth_service.get_user_by_id.assert_awaited_once_with("not_found_user") 

    async def test_token_parsing_failure(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, 
        mock_jwt_service: MagicMock
    ):
        """Test that a malformed token results in a 401 Unauthorized response."""
        token = "malformed.jwt.token"
        authenticated_request.scope['headers'] = [(b"authorization", f"Bearer {token}".encode())]
        authenticated_request.scope["path"] = "/api/protected/malformed_check"

        async def mock_call_next_fail(request: Request) -> Response:
            pytest.fail("call_next should not be invoked for malformed token")
            return JSONResponse({}) 

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)

        # Middleware specific exception handling should yield 401
        assert response.status_code == status.HTTP_401_UNAUTHORIZED 
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "invalid or malformed token" in response_body["detail"].lower()
        mock_jwt_service.decode_token.assert_called_once_with("malformed.jwt.token")

    async def test_unexpected_error_handling(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, 
        mock_jwt_service: MagicMock, 
        mock_auth_service: AsyncMock
    ):
        """Test that an unexpected auth service error results in a 401 response (specific AuthenticationException)."""
        token = "user_auth_error_user" 
        authenticated_request.scope['headers'] = [(b"authorization", f"Bearer {token}".encode())]
        authenticated_request.scope["path"] = "/api/protected/error_check"

        async def mock_call_next_fail(request: Request) -> Response:
            """This should not be called if an exception occurs early."""
            pytest.fail("mock_call_next_fail was called unexpectedly.")
            return JSONResponse({"status": "Should not happen"}, status_code=status.HTTP_200_OK)

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)
        
        mock_jwt_service.decode_token.assert_called_once_with(token)
        mock_auth_service.get_user_by_id.assert_awaited_once_with("auth_error_user")

        # Middleware currently returns 401 for this specific AuthenticationException
        assert response.status_code == status.HTTP_401_UNAUTHORIZED 
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "simulated auth service error" in response_body["detail"].lower()

# Ensure imports at the top include necessary items like pytest, User, etc.
# Add any missing imports based on the refactored code.

# Add logger import if not present
import logging

logger = logging.getLogger(__name__)
