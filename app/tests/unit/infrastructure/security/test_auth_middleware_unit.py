"""Unit tests for Authentication Middleware functionality.

This module tests the authentication middleware which enforces secure
access to protected resources and routes in our HIPAA-compliant system.
"""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

# Using pytest-asyncio for async tests
from fastapi import FastAPI, Request, Response, status
from starlette.authentication import AuthCredentials, UnauthenticatedUser
from starlette.datastructures import Headers, State
from starlette.responses import JSONResponse

from app.core.domain.entities.user import User  # Import User model for mocking
from app.domain.exceptions.auth_exceptions import AuthenticationException

# Import exceptions from their correct locations
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenExpiredException,
)
from app.infrastructure.security.auth_service import (
    AuthenticationService,  # Assuming needed for mocking type
)

# Import the TokenPayload model
from app.infrastructure.security.jwt.jwt_service import (  # Assuming JWTService is needed for mocking type
    JWTService,
    TokenPayload,
)

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
    mock_service = AsyncMock(spec=JWTService) # Mock the service instance
    
    # Create individual AsyncMocks for each method we need to configure
    mock_verify_token_method = AsyncMock() 
    
    # Configure the side effect of the method mock
    async def verify_side_effect(token):
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
            
    mock_verify_token_method.side_effect = verify_side_effect
    # Assign the configured method mock to the service mock
    mock_service.verify_token = mock_verify_token_method
    
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
                is_active=True, 
                roles=["psychiatrist"],
                hashed_password="", # Not needed for auth middleware check
                scopes=["read:patients", "write:clinical_notes", "prescribe:medications"]
            )
        elif user_id == "inactive_user":
             # Inactive user
             return User(id="inactive_user", email="inactive@example.com", is_active=False, roles=["patient"], hashed_password="")
        elif user_id == "not_found_user":
            # User that should trigger UserNotFoundException (return None initially was wrong)
            return None # The middleware should handle None by raising UserNotFoundException
        elif user_id == "auth_error_user":
            # User that causes a generic AuthenticationError (used for 500 test)
            # Make sure this error propagates correctly
            raise AuthenticationException("Simulated auth service error for testing 500 response") 
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
    # Define async getters for the dependency injection override
    async def get_mock_jwt():
        return mock_jwt_service
    async def get_mock_auth():
        return mock_auth_service

    middleware = AuthMiddleware(
        app=app,
        # Provide the async getters
        auth_service=get_mock_auth, 
        jwt_service=get_mock_jwt,   
        public_paths=list(auth_config.exempt_paths) 
    )
    return middleware

# Using Starlette Headers directly, ensure tests provide dicts or valid Headers objects
# If custom MockHeaders is needed due to specific interactions, define it here.

@pytest.fixture
def authenticated_request(mock_jwt_service): # Pass service if needed to generate token
    """Create a mock request with a valid authentication token."""
    mock_request = MagicMock(spec=Request)
    mock_request.method = "GET"
    mock_request.url = MagicMock()
    mock_request.url.path = "/api/patients"
    state = State()
    # Use a token string that the mock_jwt_service will validate correctly
    headers_list: list[tuple[bytes, bytes]] = [(b"authorization", b"Bearer valid.jwt.token")]
    mock_request.scope = {
        "type": "http", "method": "GET", "path": "/api/patients",
        "headers": headers_list, "app": FastAPI(), "state": state
    }
    mock_request.headers = Headers(scope=mock_request.scope)
    mock_request.state = state
    # Mock cookies if needed
    mock_request.cookies = {}
    return mock_request

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
        mock_jwt_service: AsyncMock, # Use AsyncMock type hint
        mock_auth_service: AsyncMock  # Use AsyncMock type hint
    ):
        """Test successful authentication with a valid token."""
        
        # Define our response validator (must be async)
        async def mock_call_next(request: Request) -> Response:
            """Mock the next call in the middleware chain."""
            assert hasattr(request.state, "user")
            assert isinstance(request.state.user, User)
            assert request.state.user.id == "user123"
            assert hasattr(request.state, "auth")
            assert isinstance(request.state.auth, AuthCredentials)
            # Check roles/scopes based on the mock user
            assert "psychiatrist" in request.state.auth.scopes 
            return JSONResponse(content={"status": "success"})
    
        # Dispatch the request through the middleware (already async)
        response = await auth_middleware.dispatch(authenticated_request, mock_call_next)
    
        # Verify the response and service calls
        assert response.status_code == 200
        assert json.loads(response.body) == {"status": "success"}
        # Assert await was called on async mocks
        mock_jwt_service.verify_token.assert_awaited_once_with("valid.jwt.token")
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
        authenticated_request: Request, # Re-use but modify token
        mock_jwt_service: AsyncMock
    ):
        """Test handling of an invalid or malformed token."""
        # Modify request to have an invalid token based on mock setup
        authenticated_request.scope['headers'] = [(b"authorization", b"Bearer invalid.jwt.token")]
        authenticated_request.headers = Headers(scope=authenticated_request.scope)

        async def mock_call_next(request: Request) -> Response:
             pytest.fail("call_next should not be invoked for invalid token")
             return JSONResponse({}) 

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "invalid" in response_body["detail"].lower() 
        mock_jwt_service.verify_token.assert_awaited_once_with("invalid.jwt.token")

    async def test_expired_token(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, # Re-use but modify token
        mock_jwt_service: AsyncMock
    ):
        """Test handling of an expired token."""
        authenticated_request.scope['headers'] = [(b"authorization", b"Bearer expired.jwt.token")]
        authenticated_request.headers = Headers(scope=authenticated_request.scope)

        async def mock_call_next(request: Request) -> Response:
             pytest.fail("call_next should not be invoked for expired token")
             return JSONResponse({}) 

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "expired" in response_body["detail"].lower()
        mock_jwt_service.verify_token.assert_awaited_once_with("expired.jwt.token")

    async def test_exempt_path(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, # Use any request, token won't be checked
        mock_jwt_service: AsyncMock, # Need mock to assert it wasn't called
        mock_auth_service: AsyncMock  # Need mock to assert it wasn't called
    ):
        """Test that exempt paths bypass authentication checks."""
        # Change request path to an exempt one
        authenticated_request.url.path = "/health"
        authenticated_request.scope['path'] = "/health"
        
        called_next = False
        async def mock_call_next(request: Request) -> Response:
            nonlocal called_next
            called_next = True
            # User should remain UnauthenticatedUser for public paths
            assert isinstance(request.state.user, UnauthenticatedUser)
            assert request.state.auth is None
            return JSONResponse(content={"status": "healthy"})

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next)
        
        assert called_next is True
        assert response.status_code == 200
        assert json.loads(response.body) == {"status": "healthy"}
        # Ensure token validation services were NOT called
        mock_jwt_service.verify_token.assert_not_awaited()
        mock_auth_service.get_user_by_id.assert_not_awaited()

    # test_testing_mode_middleware might need rethinking or removal
    # if TESTING mode bypass is handled differently or removed.
    # Skipping for now as it depends on settings logic not shown.

    async def test_authentication_with_roles_success(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request,
        mock_jwt_service: AsyncMock,
        mock_auth_service: AsyncMock
    ):
        """Test successful authentication attaches user with correct roles/scopes."""
        # Uses the default 'valid.jwt.token' which maps to 'user123'
        # The mock_auth_service returns a user with roles ['psychiatrist']
        
        async def mock_call_next_success(request: Request) -> Response:
            assert isinstance(request.state.user, User)
            assert request.state.user.id == "user123"
            assert request.state.user.roles == ["psychiatrist"] # Verify roles on user
            assert isinstance(request.state.auth, AuthCredentials)
            # Verify scopes attached to auth credentials match user roles
            assert request.state.auth.scopes == ["psychiatrist"] 
            return JSONResponse(content={"auth": "ok"})

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next_success)

        assert response.status_code == 200
        assert json.loads(response.body) == {"auth": "ok"}
        mock_jwt_service.verify_token.assert_awaited_once_with("valid.jwt.token")
        mock_auth_service.get_user_by_id.assert_awaited_once_with("user123")

    async def test_inactive_user_authentication_failure(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, # Modify token
        mock_jwt_service: AsyncMock,
        mock_auth_service: AsyncMock
    ):
        """Test authentication fails correctly for an inactive user."""
        # Setup token and mock to represent an inactive user
        token = "Bearer user_inactive_user"
        authenticated_request.scope['headers'] = [(b"authorization", token.encode())]
        authenticated_request.headers = Headers(scope=authenticated_request.scope)
        
        # Mock JWT to return payload for inactive_user
        # Mock Auth to return inactive User object is already configured in fixture
        # Need to configure JWT verify mock for this specific token if not covered by default
        # (Fixture mock_jwt_service updated to handle this pattern)

        async def mock_call_next_fail(request: Request) -> Response:
             pytest.fail("call_next should not be invoked for inactive user")
             return JSONResponse({}) 

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)

        assert response.status_code == status.HTTP_403_FORBIDDEN # Specific code for inactive
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "inactive" in response_body["detail"].lower()
        # Verify services were called correctly
        mock_jwt_service.verify_token.assert_awaited_once_with("user_inactive_user")
        mock_auth_service.get_user_by_id.assert_awaited_once_with("inactive_user") 

    async def test_user_not_found_authentication_failure(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, # Modify token
        mock_jwt_service: AsyncMock,
        mock_auth_service: AsyncMock
    ):
        """Test authentication fails correctly when user is not found."""
        token = "Bearer user_not_found_user"
        authenticated_request.scope['headers'] = [(b"authorization", token.encode())]
        authenticated_request.headers = Headers(scope=authenticated_request.scope)
        # Mocks are configured in fixtures to raise UserNotFoundException for 'not_found_user'

        async def mock_call_next_fail(request: Request) -> Response:
             pytest.fail("call_next should not be invoked for user not found")
             return JSONResponse({}) 

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED # Standard unauthorized
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "not found" in response_body["detail"].lower()
        # Verify services were called correctly
        mock_jwt_service.verify_token.assert_awaited_once_with("user_not_found_user")
        mock_auth_service.get_user_by_id.assert_awaited_once_with("not_found_user") 

    async def test_token_parsing_failure(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, # Modify token
        mock_jwt_service: AsyncMock
    ):
        """Test handling of a token that causes a parsing/validation error in JWT service."""
        token = "Bearer malformed.jwt.token"
        authenticated_request.scope['headers'] = [(b"authorization", token.encode())]
        authenticated_request.headers = Headers(scope=authenticated_request.scope)
        # mock_jwt_service fixture configured to raise InvalidTokenException for this

        async def mock_call_next_fail(request: Request) -> Response:
             pytest.fail("call_next should not be invoked for malformed token")
             return JSONResponse({}) 

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response_body = json.loads(response.body)
        assert "detail" in response_body
        assert "invalid" in response_body["detail"].lower() or "malformed" in response_body["detail"].lower()
        mock_jwt_service.verify_token.assert_awaited_once_with("malformed.jwt.token")

    async def test_unexpected_error_handling(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, # Modify token
        mock_jwt_service: AsyncMock, # Mock JWT interaction
        mock_auth_service: AsyncMock  # Mock Auth interaction that raises error
    ):
        """Test that unexpected errors during auth are handled gracefully (500)."""
        token = "Bearer user_auth_error_user"
        authenticated_request.scope['headers'] = [(b"authorization", token.encode())]
        authenticated_request.headers = Headers(scope=authenticated_request.scope)
        # mock_auth_service fixture configured to raise AuthenticationException for this user ID

        async def mock_call_next_fail(request: Request) -> Response:
             pytest.fail("call_next should not be invoked when an unexpected error occurs")
             return JSONResponse({}) 

        response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR # Expect 500
        response_body = json.loads(response.body)
        assert "detail" in response_body
        # HIPAA: Ensure generic error message
        assert "internal error" in response_body["detail"].lower() 
        assert "authentication" in response_body["detail"].lower()
        # Verify services were called
        mock_jwt_service.verify_token.assert_awaited_once_with("user_auth_error_user")
        mock_auth_service.get_user_by_id.assert_awaited_once_with("auth_error_user") 

# Ensure imports at the top include necessary items like pytest, User, etc.
# Add any missing imports based on the refactored code.

# Add logger import if not present
import logging

logger = logging.getLogger(__name__)
