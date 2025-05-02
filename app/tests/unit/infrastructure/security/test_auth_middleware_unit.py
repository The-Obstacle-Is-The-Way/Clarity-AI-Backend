"""Unit tests for Authentication Middleware functionality.

This module tests the authentication middleware which enforces secure
access to protected resources and routes in our HIPAA-compliant system.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request, Response, status
from starlette.authentication import AuthCredentials, UnauthenticatedUser
from starlette.datastructures import Headers, State
from starlette.responses import JSONResponse

# Assuming these exceptions are correctly defined in the domain layer
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenExpiredException,
)

# Import the TokenPayload model which is essential for our JWT verification
from app.infrastructure.security.jwt.jwt_service import TokenPayload

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
from app.presentation.middleware.authentication_middleware import (
    AuthenticationMiddleware as AuthMiddleware,
)

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
    config.exempt_paths = ["/health", "/docs", "/redoc", "/openapi.json"]
    config.strict_scopes = True # Assuming this is a valid config option
    config.admin_role = "admin" # Assuming this is a valid config option
    # JWT specific configs might be needed if JWTAuthBackend is used directly
    # config.jwt_algorithm = "HS256"
    # config.jwt_secret_key = "test_secret_key"
    # config.jwt_expiry_minutes = 60
    return config

@pytest.fixture
def app():
    """Create a FastAPI app for testing."""
    return FastAPI()

@pytest.fixture
def mock_jwt_service():
    """Create a mock JWT service for testing."""
    mock_service = MagicMock()
    # Configure mock verify_token method for successful validation by default
    mock_service.verify_token = AsyncMock()
    mock_service.verify_token.return_value = TokenPayload(
        sub="user123",
        exp=1713840000,  # Future timestamp
        iat=1713830000,  # Past timestamp
        jti="unique-id",
        type="access",
        scopes=["read:patients", "write:clinical_notes"]
    )
    return mock_service

@pytest.fixture
def mock_auth_service():
    """Create a mock authentication service for testing."""
    mock_service = MagicMock()
    mock_service.get_user_by_id = AsyncMock()
    
    # Create a real-like user model that can be properly accessed
    user_mock = MagicMock()
    user_mock.id = "user123"
    user_mock.email = "doctor@example.com"
    user_mock.is_active = True
    user_mock.roles = ["psychiatrist"]
    user_mock.scopes = ["read:patients", "write:clinical_notes", "prescribe:medications"]
    
    mock_service.get_user_by_id.return_value = user_mock
    return mock_service
    
@pytest.fixture
def auth_middleware(app, mock_jwt_service, mock_auth_service, auth_config):
    """Create an authentication middleware instance for testing."""
    # Create using the actual constructor signature
    # Remove incorrect auth_service and jwt_service arguments
    middleware = AuthMiddleware(
        app=app,
        # auth_service=mock_auth_service, # REMOVED
        # jwt_service=mock_jwt_service,   # REMOVED
        public_paths=list(auth_config.exempt_paths) # Pass as list
        # Optionally pass settings or regex if needed by tests using this fixture
    )
    return middleware

# Using Starlette Headers directly, ensure tests provide dicts or valid Headers objects
# If custom MockHeaders is needed due to specific interactions, define it here.

@pytest.fixture
def authenticated_request():
    """Create a mock request with a valid authentication token."""
    mock_request = MagicMock(spec=Request)
    mock_request.method = "GET"
    mock_request.url = MagicMock()
    mock_request.url.path = "/api/patients"
    
    # Create proper state object that mimics Starlette behavior
    state = State()
    
    # Provide headers as a list of tuples for scope
    headers_list: list[tuple[bytes, bytes]] = [(b"authorization", b"Bearer valid.jwt.token")]
    mock_request.scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/patients",
        "headers": headers_list,
        "app": FastAPI(), # Add app to scope
        "state": state # Use proper State object
    }
    
    # Use Starlette Headers
    mock_request.headers = Headers(scope=mock_request.scope)
    mock_request.state = state  # Explicitly set state for easier access in tests
    
    return mock_request

@pytest.fixture
def unauthenticated_request():
    """Create a mock request without an authentication token."""
    mock_request = MagicMock(spec=Request)
    mock_request.method = "GET"
    mock_request.url = MagicMock()
    mock_request.url.path = "/api/patients"
    
    # Create proper state object that mimics Starlette behavior
    state = State()
    
    # Empty headers list (no auth token)
    headers_list: list[tuple[bytes, bytes]] = []
    
    mock_request.scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/patients",
        "headers": headers_list,
        "app": FastAPI(), # Add app to scope
        "state": state # Use proper State object
    }
    mock_request.headers = Headers(scope=mock_request.scope)
    mock_request.state = state  # Explicitly set state for easier access in tests
    
    return mock_request


class TestAuthMiddleware:
    """Test suite for the authentication middleware."""

    @pytest.mark.asyncio
    async def test_valid_authentication(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request,
        mock_jwt_service: MagicMock,
        mock_auth_service: MagicMock
    ):
        """Test successful authentication with a valid token."""
        # Override settings to ensure we're not in testing mode
        settings_mock = MagicMock()
        settings_mock.TESTING = False
        settings_mock.API_V1_STR = "/api/v1"
        
        with patch('app.presentation.middleware.authentication_middleware.get_settings', return_value=settings_mock):
            # Configure the jwt_service to return a valid token payload
            token_payload = TokenPayload(
                sub="user123",
                exp=1713840000,  # Future timestamp
                iat=1713830000,  # Past timestamp
                jti="unique-id",
                type="access",
                scopes=["read:patients", "write:notes"]
            )
            mock_jwt_service.verify_token.return_value = token_payload
            
            # Create a properly structured user mock for the auth service to return
            user_mock = MagicMock()
            user_mock.id = "user123"
            user_mock.is_active = True
            user_mock.roles = ["psychiatrist"]
            
            # Configure auth service to return our user mock when called with the subject ID
            mock_auth_service.get_user_by_id.return_value = user_mock
            
            # Define our response validator
            async def mock_call_next(request: Request) -> Response:
                """Mock the next call in the middleware chain."""
                # Verify user is correctly set in request state
                assert hasattr(request.state, "user")
                assert request.state.user is user_mock
                assert request.state.user.id == "user123"
                
                # Verify roles are correctly passed to AuthCredentials
                assert hasattr(request.state, "auth")
                assert isinstance(request.state.auth, AuthCredentials)
                assert "psychiatrist" in request.state.auth.scopes
                
                return JSONResponse(content={"status": "success"})
    
            # Dispatch the request through the middleware
            response = await auth_middleware.dispatch(authenticated_request, mock_call_next)
    
            # Verify the response and service calls
            assert response.status_code == 200
            assert json.loads(response.body) == {"status": "success"}
            mock_jwt_service.verify_token.assert_called_once_with("valid.jwt.token")
            mock_auth_service.get_user_by_id.assert_called_once_with("user123")

    @pytest.mark.asyncio
    async def test_missing_token(
        self,
        auth_middleware: AuthMiddleware,
        unauthenticated_request: Request
    ):
        """Test handling of a request without an authentication token."""
        # In our implementation, missing tokens proceed as unauthenticated
        # This is a design choice for our middleware architecture
        
        # HIPAA applications can have both public and protected resources
        # Proceed as unauthenticated for public resources, reject for protected ones
        calls = []
        
        async def mock_call_next(request: Request) -> Response:
            """Mock the next call in the middleware chain."""
            # Should be reached with unauthenticated state
            calls.append(1)
            # Verify user is unauthenticated
            assert isinstance(request.state.user, UnauthenticatedUser)
            assert request.state.auth is None
            return JSONResponse(content={"status": "unauthenticated access"})

        response = await auth_middleware.dispatch(unauthenticated_request, mock_call_next)

        # Verify we reached the next middleware/route handler
        assert len(calls) == 1
        assert response.status_code == 200
        assert json.loads(response.body) == {"status": "unauthenticated access"}

    @pytest.mark.asyncio
    async def test_invalid_token(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request,
        mock_jwt_service: MagicMock
    ):
        """Test handling of a request with an invalid token."""
        # Override settings to ensure we're not in testing mode
        settings_mock = MagicMock()
        settings_mock.TESTING = False
        settings_mock.API_V1_STR = "/api/v1"
        
        with patch('app.presentation.middleware.authentication_middleware.get_settings', return_value=settings_mock):
            # Configure the mock JWT service to raise an InvalidTokenException
            # This simulates an invalid JWT signature or structure - important for HIPAA security
            mock_jwt_service.verify_token.side_effect = InvalidTokenException("Invalid token signature")
    
            async def mock_call_next(request: Request) -> Response:
                # This should not be reached as the middleware should block invalid tokens
                pytest.fail("Middleware should have blocked the request with invalid token")
                return Response()
    
            response = await auth_middleware.dispatch(authenticated_request, mock_call_next)
    
            # Verify the correct HIPAA-compliant error response
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            content = json.loads(response.body)
            assert "Invalid token" in content["detail"]
            assert response.headers.get("WWW-Authenticate") == "Bearer"
            
            # Verify the token verification was attempted
            mock_jwt_service.verify_token.assert_called_once_with("valid.jwt.token")

    @pytest.mark.asyncio
    async def test_expired_token(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request,
        mock_jwt_service: MagicMock
    ):
        """Test handling of a request with an expired token."""
        # Override settings to ensure we're not in testing mode
        settings_mock = MagicMock()
        settings_mock.TESTING = False
        settings_mock.API_V1_STR = "/api/v1"
        
        with patch('app.presentation.middleware.authentication_middleware.get_settings', return_value=settings_mock):
            # Configure the mock JWT service to raise a TokenExpiredException
            # HIPAA requires strict session timeouts and proper expiration handling
            mock_jwt_service.verify_token.side_effect = TokenExpiredException("Token has expired")
    
            async def mock_call_next(request: Request) -> Response:
                # This should not be reached as the middleware should block expired tokens
                pytest.fail("Middleware should have blocked the request with expired token")
                return Response()
    
            response = await auth_middleware.dispatch(authenticated_request, mock_call_next)
    
            # Verify the correct HIPAA-compliant error response
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            content = json.loads(response.body)
            assert "expired" in content["detail"].lower()
            assert response.headers.get("WWW-Authenticate") == "Bearer"
            
            # Verify the token verification was attempted
            mock_jwt_service.verify_token.assert_called_once_with("valid.jwt.token")

    @pytest.mark.asyncio
    async def test_exempt_path(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request, # Use an authenticated request to show it's bypassed
        mock_jwt_service: MagicMock
    ):
        """Test that exempt paths bypass authentication."""
        # Override settings to ensure we're not in testing mode
        settings_mock = MagicMock()
        settings_mock.TESTING = False
        settings_mock.API_V1_STR = "/api/v1"
        
        with patch('app.presentation.middleware.authentication_middleware.get_settings', return_value=settings_mock):
            # Modify the request to use an exempt path from auth_config fixture
            authenticated_request.scope["path"] = "/health"
            # Recreate headers based on updated scope
            authenticated_request.headers = Headers(scope=authenticated_request.scope)
            # Update the URL mock since path is used from there
            authenticated_request.url.path = "/health"
            
            # Reset the mock to ensure clean test
            mock_jwt_service.verify_token.reset_mock()
    
            async def mock_call_next(request: Request) -> Response:
                """Mock the next call, checking that default state is preserved for exempt paths."""
                # For public paths, the middleware should leave user as UnauthenticatedUser
                assert isinstance(request.state.user, UnauthenticatedUser)
                assert request.state.auth is None
                return JSONResponse(content={"status": "healthy"})
    
            response = await auth_middleware.dispatch(authenticated_request, mock_call_next)
    
            # Verify proper response and no JWT verification
            assert response.status_code == 200
            assert json.loads(response.body) == {"status": "healthy"}
            # Ensure JWT service was NOT called for exempt paths
            mock_jwt_service.verify_token.assert_not_called()


    @pytest.mark.asyncio
    async def test_testing_mode_middleware(
        self,
        app: FastAPI,
        mock_jwt_service: MagicMock,
        mock_auth_service: MagicMock,
        auth_config: MagicMock,
        authenticated_request: Request
    ):
        """Test behavior when middleware is in testing mode."""
        # The actual middleware checks for TESTING flag in settings
        # so we'll patch get_settings to return a MagicMock with TESTING=True
        settings_mock = MagicMock()
        settings_mock.TESTING = True
        
        with patch('app.presentation.middleware.authentication_middleware.get_settings', return_value=settings_mock):
            # Create middleware with testing mode
            testing_middleware = AuthMiddleware(
                app=app,
                auth_service=mock_auth_service,
                jwt_service=mock_jwt_service,
                public_paths=set(auth_config.exempt_paths)
            )
            
            async def mock_call_next(request: Request) -> Response:
                """Mock the next call, verifying unauthenticated user is set in testing mode."""
                # In testing mode, the middleware should set an unauthenticated user
                assert hasattr(request.state, "user")
                assert isinstance(request.state.user, UnauthenticatedUser)
                assert request.state.auth is None
                return JSONResponse(content={"status": "success"})

            response = await testing_middleware.dispatch(authenticated_request, mock_call_next)

            assert response.status_code == 200
            assert json.loads(response.body) == {"status": "success"}
            # Verify JWT service was not called in testing mode
            mock_jwt_service.verify_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_authentication_with_roles_success(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request,
        mock_jwt_service: MagicMock,
        mock_auth_service: MagicMock
    ):
        """Test successful authentication with role-based scopes."""
        # Override settings to ensure we're not in testing mode
        settings_mock = MagicMock()
        settings_mock.TESTING = False
        settings_mock.API_V1_STR = "/api/v1"
        
        with patch('app.presentation.middleware.authentication_middleware.get_settings', return_value=settings_mock):
            # Configure JWT service to return a valid token payload with user ID
            token_payload = TokenPayload(
                sub="user123",
                exp=1713840000,  # Future timestamp
                iat=1713830000,  # Past timestamp
                jti="unique-id",
                type="access",
                scopes=["read:patients"]
            )
            mock_jwt_service.verify_token.return_value = token_payload
            
            # Configure auth service to return a user with specific roles
            mock_user = MagicMock()
            mock_user.id = "user123"
            mock_user.is_active = True
            mock_user.roles = ["psychiatrist"]
            mock_auth_service.get_user_by_id.return_value = mock_user
            
            # Reset mocks for clean test
            mock_jwt_service.verify_token.reset_mock()
            mock_auth_service.get_user_by_id.reset_mock()
            
            # Set request path to a protected endpoint
            authenticated_request.scope["path"] = "/api/patients"
            authenticated_request.scope["method"] = "GET"
            authenticated_request.headers = Headers(scope=authenticated_request.scope)
            authenticated_request.url.path = "/api/patients"
            authenticated_request.method = "GET"
            
            # This flag helps us verify if our assertions ran
            checks_executed = []
            
            async def mock_call_next_success(request: Request) -> Response:
                # Verify user and auth credentials are set correctly
                # These checks must pass for proper HIPAA-compliant role-based access
                assert hasattr(request.state, "user")
                assert request.state.user.id == "user123"
                
                # Verify roles are correctly passed to AuthCredentials
                assert hasattr(request.state, "auth")
                assert isinstance(request.state.auth, AuthCredentials)
                assert "psychiatrist" in request.state.auth.scopes
                
                # Mark that we ran our assertions
                checks_executed.append(True)
                return JSONResponse(content={"status": "success"})
            
            response = await auth_middleware.dispatch(authenticated_request, mock_call_next_success)
            
            # Verify our assertions in mock_call_next_success were actually run
            assert len(checks_executed) > 0
            
            # Verify the response and service calls
            assert response.status_code == 200
            assert json.loads(response.body) == {"status": "success"}
            mock_jwt_service.verify_token.assert_called_once_with("valid.jwt.token")
            mock_auth_service.get_user_by_id.assert_called_once_with("user123")

    @pytest.mark.asyncio
    async def test_inactive_user_authentication_failure(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request,
        mock_jwt_service: MagicMock,
        mock_auth_service: MagicMock
    ):
        """Test authentication failure with an inactive user account."""
        # Override settings to ensure we're not in testing mode
        settings_mock = MagicMock()
        settings_mock.TESTING = False
        settings_mock.API_V1_STR = "/api/v1"
        
        with patch('app.presentation.middleware.authentication_middleware.get_settings', return_value=settings_mock):
            # Configure JWT service to return a valid token payload
            token_payload = TokenPayload(
                sub="user123",
                exp=1713840000,  # Future timestamp
                iat=1713830000,  # Past timestamp
                jti="unique-id",
                type="access",
                scopes=["read:patients"]
            )
            mock_jwt_service.verify_token.return_value = token_payload
            
            # Configure auth service to return an inactive user
            # HIPAA compliance requires strict handling of inactive accounts
            mock_user = MagicMock()
            mock_user.id = "user123"
            mock_user.is_active = False  # Inactive user
            mock_user.roles = ["psychiatrist"]
            mock_auth_service.get_user_by_id.return_value = mock_user
    
            # Reset mocks for clean test
            mock_jwt_service.verify_token.reset_mock()
            mock_auth_service.get_user_by_id.reset_mock()
    
            async def mock_call_next_fail(request: Request) -> Response:
                pytest.fail("Middleware should have blocked the request with inactive user")
                return Response()  # pragma: no cover
    
            response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)
            
            # Verify correct HIPAA-compliant error response
            assert response.status_code == status.HTTP_403_FORBIDDEN
            content = json.loads(response.body)
            assert "inactive" in content["detail"].lower()
            assert response.headers.get("WWW-Authenticate") == "Bearer"
            
            # Verify service calls
            mock_jwt_service.verify_token.assert_called_once_with("valid.jwt.token")
            mock_auth_service.get_user_by_id.assert_called_once_with("user123")

    @pytest.mark.asyncio
    async def test_user_not_found_authentication_failure(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request,
        mock_jwt_service: MagicMock,
        mock_auth_service: MagicMock
    ):
        """Test authentication failure when user is not found in the database."""
        # Override settings to ensure we're not in testing mode
        settings_mock = MagicMock()
        settings_mock.TESTING = False
        settings_mock.API_V1_STR = "/api/v1"
        
        with patch('app.presentation.middleware.authentication_middleware.get_settings', return_value=settings_mock):
            # Configure JWT service to return a valid token payload
            token_payload = TokenPayload(
                sub="user123",
                exp=1713840000,  # Future timestamp
                iat=1713830000,  # Past timestamp
                jti="unique-id",
                type="access",
                scopes=["read:patients"]
            )
            mock_jwt_service.verify_token.return_value = token_payload
            
            # Configure auth service to return None (user not found)
            # This simulates a scenario where a token contains a valid subject ID,
            # but the corresponding user no longer exists in the database - a critical HIPAA security case
            mock_auth_service.get_user_by_id.return_value = None
    
            # Reset mocks for clean test
            mock_jwt_service.verify_token.reset_mock()
            mock_auth_service.get_user_by_id.reset_mock()
    
            async def mock_call_next_fail(request: Request) -> Response:
                pytest.fail("Middleware should have blocked the request with non-existent user")
                return Response()  # pragma: no cover
    
            response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)
            
            # Verify correct HIPAA-compliant error response
            # For non-existent users, we use 401 Unauthorized instead of 403 Forbidden to avoid
            # revealing whether the user exists or not (important for HIPAA security)
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            content = json.loads(response.body)
            assert "not found" in content["detail"].lower()
            assert response.headers.get("WWW-Authenticate") == "Bearer"
            
            # Verify service calls
            mock_jwt_service.verify_token.assert_called_once_with("valid.jwt.token")
            mock_auth_service.get_user_by_id.assert_called_once_with("user123")

    @pytest.mark.asyncio
    async def test_token_parsing_failure(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request,
        mock_jwt_service: MagicMock
    ):
        """Test authentication failure when token is malformed and can't be parsed."""
        # Override settings to ensure we're not in testing mode
        settings_mock = MagicMock()
        settings_mock.TESTING = False
        settings_mock.API_V1_STR = "/api/v1"
        
        with patch('app.presentation.middleware.authentication_middleware.get_settings', return_value=settings_mock):
            # Set the Authorization header to a badly formatted value
            authenticated_request.scope["headers"] = [(b"authorization", b"Bearer not-even-three-parts")]
            authenticated_request.headers = Headers(scope=authenticated_request.scope)
    
            # Configure the mock JWT service to raise an InvalidTokenException
            # This is critical for HIPAA security - ensuring malformed tokens are properly rejected
            mock_jwt_service.verify_token.side_effect = InvalidTokenException("Token format is invalid")
            
            # Reset mock for clean test
            mock_jwt_service.verify_token.reset_mock()
    
            async def mock_call_next_fail(request: Request) -> Response:
                pytest.fail("Middleware should have blocked the request with malformed token")
                return Response()  # pragma: no cover
    
            response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)
            
            # Verify correct HIPAA-compliant error response
            # We must ensure proper error responses that don't leak sensitive information
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            content = json.loads(response.body)
            assert "invalid" in content["detail"].lower()
            assert response.headers.get("WWW-Authenticate") == "Bearer"
            
            # Verify service call
            mock_jwt_service.verify_token.assert_called_once_with("not-even-three-parts")

    @pytest.mark.asyncio
    async def test_unexpected_error_handling(
        self,
        auth_middleware: AuthMiddleware,
        authenticated_request: Request,
        mock_jwt_service: MagicMock,
        mock_auth_service: MagicMock
    ):
        """Test handling of unexpected errors during authentication - critical for HIPAA compliance."""
        # Override settings to ensure we're not in testing mode
        settings_mock = MagicMock()
        settings_mock.TESTING = False
        settings_mock.API_V1_STR = "/api/v1"
        
        with patch('app.presentation.middleware.authentication_middleware.get_settings', return_value=settings_mock):
            # Configure JWT service to raise an unexpected (non-standard) exception
            # This simulates an internal server error that should be properly handled
            # without leaking sensitive information (crucial for HIPAA compliance)
            mock_jwt_service.verify_token.side_effect = Exception("Unexpected internal error that should not be exposed")
            
            # Reset mock for clean test
            mock_jwt_service.verify_token.reset_mock()
    
            async def mock_call_next_fail(request: Request) -> Response:
                pytest.fail("Middleware should have blocked the request on unexpected errors")
                return Response()  # pragma: no cover
    
            response = await auth_middleware.dispatch(authenticated_request, mock_call_next_fail)
            
            # In HIPAA environments, we need to ensure that no sensitive information is leaked
            # even during unexpected errors, so we should get a generic 500 response
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            content = json.loads(response.body)
            
            # The error message should be generic and not expose any internal details
            # This is crucial for HIPAA compliance to avoid data leakage
            assert content["detail"] == "Internal server error during authentication"
            
            # No authentication header should be in the response for 500 errors
            # as it could potentially leak sensitive information
            assert "WWW-Authenticate" not in response.headers
            
            # Verify the service was called
            mock_jwt_service.verify_token.assert_called_once_with("valid.jwt.token")
        
    # Additional HIPAA-compliant security tests can be added for:
    # - Audit logging of authentication attempts
    # - Session timeouts
    # - Account lockouts after multiple failed attempts
    # - Token revocation

    # Add more tests for edge cases, different header formats, specific error handling, etc.
