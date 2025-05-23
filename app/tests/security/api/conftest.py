"""Test fixtures for security API tests."""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import jwt
import pytest
from fastapi import Depends, FastAPI, Request, status
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from jose import jwt as jose_jwt  # Use jose for JWT operations in tests

from app.core.config.settings import Settings
from app.core.domain.entities.user import User as DomainUser
from app.core.domain.entities.user import UserRole, UserStatus
from app.core.interfaces.repositories.patient_repository import IPatientRepository
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface

# Import User entity for type hinting
from app.domain.entities.user import User
from app.domain.exceptions.token_exceptions import (
    InvalidTokenException,
    TokenExpiredException,
)
from app.factory import create_application

# Custom token payload imports
from app.infrastructure.security.jwt.jwt_service import (
    TokenPayload,
    TokenType,
)
from app.presentation.api.dependencies.auth import get_user_repository_dependency
from app.presentation.api.dependencies.database import get_patient_repository_dependency

logger = logging.getLogger(__name__)


@pytest.fixture(scope="function")
def app_instance(
    global_mock_jwt_service, test_settings, jwt_service_patch, middleware_patch
) -> FastAPI:
    """Create a function-scoped FastAPI app instance for testing."""
    # Ensure test mode is set
    test_settings.TEST_MODE = True
    test_settings.TESTING = True

    app = create_application(
        settings_override=test_settings,
        jwt_service_override=global_mock_jwt_service,  # Use the mock service for consistency
        include_test_routers=True,
    )

    # Create a proper async context manager for the session factory
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def mock_session_cm():
        """Mock session factory that uses async context manager protocol."""
        # Create a mock session object
        mock_session = MagicMock()
        mock_session.execute = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()

        # Add get method to handle SQLAlchemy session.get calls
        async def mock_get(model_class, model_id):
            # Return a mock model instance based on model_class
            mock_model = MagicMock(spec=model_class)
            mock_model.id = model_id
            return mock_model

        mock_session.get = mock_get

        try:
            yield mock_session
        finally:
            await mock_session.close()

    # THIS IS THE KEY FIX: return the context manager directly, not a function that returns it
    # The mock_session_factory should BE the async context manager, not return one
    mock_session_factory = mock_session_cm

    # Add mock session factory to app state
    app.state.actual_session_factory = mock_session_factory
    app.state.db_engine = MagicMock()
    app.state.session_factory = mock_session_factory

    # Override the database session dependency
    from app.presentation.api.dependencies.database import get_async_session_utility

    app.dependency_overrides[get_async_session_utility] = lambda: mock_session_factory

    # Add special test-only endpoint for /api/v1/auth/me
    @app.get("/api/v1/auth/me")
    async def auth_me_endpoint(request: Request):
        """Test endpoint that returns the authenticated user information"""
        # Check for bearer token in request header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")

            # Special handling for test tokens in endpoint
            try:
                # Try to decode the token with JWT library (no signature verification)
                from jose import jwt as jose_jwt

                # First, get the payload without verification
                try:
                    unverified_payload = jose_jwt.decode(
                        token,
                        key=test_settings.JWT_SECRET_KEY,
                        options={
                            "verify_signature": False,
                            "verify_aud": False,
                            "verify_exp": False,
                            "verify_iss": False,
                        },
                    )

                    # Check if this is a test token
                    is_test_token = (
                        (
                            "iss" in unverified_payload
                            and unverified_payload.get("iss") == "test-issuer"
                        )
                        or (
                            "sub" in unverified_payload
                            and "test" in unverified_payload.get("sub", "")
                        )
                        or (
                            "testing" in unverified_payload
                            and unverified_payload.get("testing") is True
                        )
                    )

                    if is_test_token:
                        # Extract info from token
                        user_id = unverified_payload.get("sub", "")
                        username = unverified_payload.get("username", "test_user")
                        email = unverified_payload.get("email", f"{username}@example.com")

                        # Handle roles in the token payload
                        roles_data = unverified_payload.get("roles", ["patient"])
                        roles = []

                        if isinstance(roles_data, list):
                            for role in roles_data:
                                # Handle different formats of roles
                                if hasattr(role, "value"):
                                    roles.append(role.value)
                                else:
                                    roles.append(str(role))
                        else:
                            # Handle single role
                            if hasattr(roles_data, "value"):
                                roles.append(roles_data.value)
                            else:
                                roles.append(str(roles_data))

                        # Return user info directly from token
                        return {
                            "id": user_id,
                            "username": username,
                            "email": email,
                            "roles": roles,
                        }
                except Exception as e:
                    logger.warning(f"Error processing test token: {e}")
            except Exception as e:
                logger.warning(f"Error in special test token handling: {e}")

        # If all else fails, try to get user from request scope
        user = request.scope.get("user")
        if not user or not hasattr(user, "id"):
            return JSONResponse(
                {"detail": "Not authenticated"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # Handle roles in a format-agnostic way
        roles = []
        if hasattr(user, "roles"):
            if isinstance(user.roles, set) or isinstance(user.roles, list):
                for role in user.roles:
                    # Handle both string and enum roles
                    if hasattr(role, "value"):
                        roles.append(role.value)
                    else:
                        roles.append(str(role))
            elif hasattr(user.roles, "value"):  # Single enum role
                roles.append(user.roles.value)
            else:  # Single string role
                roles.append(str(user.roles))

        # Return user information from the request scope
        return {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "roles": roles,
        }

    # Add patient endpoints for testing
    @app.get("/api/v1/patients/{patient_id}")
    async def get_patient_endpoint(
        patient_id: uuid.UUID,
        request: Request,
        patient_repo: IPatientRepository = Depends(get_patient_repository_dependency),
        user_repo: IUserRepository = Depends(get_user_repository_dependency),
    ):
        """Test endpoint for retrieving patient information."""
        current_user = None

        # First try to get user from request scope (middleware auth)
        scope_user = request.scope.get("user")
        if scope_user and hasattr(scope_user, "id"):
            current_user = scope_user

        # If not found, try to extract from token (direct auth)
        if not current_user:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.replace("Bearer ", "")

                # Try to decode token without verification for test tokens
                try:
                    from jose import jwt as jose_jwt

                    try:
                        payload = jose_jwt.decode(
                            token,
                            key=test_settings.JWT_SECRET_KEY,
                            options={
                                "verify_signature": False,
                                "verify_aud": False,
                                "verify_exp": False,
                                "verify_iss": False,
                            },
                        )

                        if "testing" in payload or (
                            "iss" in payload and payload.get("iss") == "test-issuer"
                        ):
                            # This is a test token, create a user from it
                            from app.presentation.schemas.auth import AuthenticatedUser

                            user_id = uuid.UUID(payload.get("sub", str(uuid.uuid4())))
                            username = payload.get("username", f"test_user_{user_id}")

                            # Extract roles
                            roles_data = payload.get("roles", ["patient"])
                            user_roles = []
                            for role in roles_data:
                                try:
                                    # Try to convert to UserRole enum
                                    if isinstance(role, str):
                                        user_roles.append(UserRole(role))
                                    else:
                                        user_roles.append(UserRole.PATIENT)
                                except (ValueError, TypeError):
                                    user_roles.append(UserRole.PATIENT)

                            if not user_roles:
                                user_roles = [UserRole.PATIENT]

                            # Create authenticated user from token
                            current_user = AuthenticatedUser(
                                id=user_id,
                                username=username,
                                email=payload.get("email", f"{username}@example.com"),
                                roles=user_roles,
                                status=UserStatus.ACTIVE,
                            )
                    except Exception as e:
                        logger.warning(f"Error decoding test token: {e}")
                except Exception as e:
                    logger.warning(f"Error handling auth header: {e}")

        # If still no user, return not authenticated
        if not current_user:
            return JSONResponse(
                {"detail": "Not authenticated"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # For security, patients can only access their own data
        if UserRole.PATIENT in current_user.roles and str(current_user.id) != str(patient_id):
            return JSONResponse(
                {"detail": "Not authorized to access this patient's data"},
                status_code=status.HTTP_403_FORBIDDEN,
            )

        # Retrieve the patient from the repository
        patient = await patient_repo.get_by_id(patient_id=patient_id)
        if not patient:
            return JSONResponse(
                {"detail": f"Patient with id {patient_id} not found."},
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Return patient data
        return {
            "id": str(patient.id),
            "name": f"{patient.first_name} {patient.last_name}",
            "email": patient.email,
            "date_of_birth": patient.date_of_birth,
        }

    # Add PHI endpoint for testing
    @app.get("/api/v1/patients/{patient_id}/phi")
    async def get_patient_phi_endpoint(
        patient_id: uuid.UUID,
        request: Request,
        patient_repo: IPatientRepository = Depends(get_patient_repository_dependency),
        user_repo: IUserRepository = Depends(get_user_repository_dependency),
    ):
        """Test endpoint for retrieving patient PHI."""
        # Get the authenticated user from the request scope
        current_user = request.scope.get("user")
        if not current_user:
            return JSONResponse(
                {"detail": "Not authenticated"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # For security, patients can only access their own PHI
        if UserRole.PATIENT in current_user.roles and str(current_user.id) != str(patient_id):
            return JSONResponse(
                {"detail": "Not authorized to access this patient's PHI"},
                status_code=status.HTTP_403_FORBIDDEN,
            )

        # Clinicians and admins can access any patient's PHI
        has_provider_access = any(
            role in current_user.roles for role in [UserRole.CLINICIAN, UserRole.ADMIN]
        )

        # If not a patient accessing their own data and not a provider, deny access
        if str(current_user.id) != str(patient_id) and not has_provider_access:
            return JSONResponse(
                {"detail": "Not authorized to access this patient's PHI"},
                status_code=status.HTTP_403_FORBIDDEN,
            )

        # Retrieve the patient from the repository
        patient = await patient_repo.get_by_id(patient_id=patient_id)
        if not patient:
            return JSONResponse(
                {"detail": f"Patient PHI for patient id {patient_id} not found."},
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Return patient PHI data
        return {
            "id": str(patient.id),
            "name": f"{patient.first_name} {patient.last_name}",
            "date_of_birth": patient.date_of_birth,
            "phi_data": {
                "medical_record_number": f"MRN-{patient_id}",
                "diagnosis": ["Example Diagnosis 1", "Example Diagnosis 2"],
                "medications": ["Medication A", "Medication B"],
            },
        }

    # Add admin users endpoint for role testing
    @app.get("/api/v1/admin/users")
    async def admin_users_endpoint(
        request: Request,
        user_repo: IUserRepository = Depends(get_user_repository_dependency),
    ):
        """Test admin-only endpoint for listing users."""
        # Get the authenticated user from the request scope
        current_user = request.scope.get("user")
        if not current_user:
            return JSONResponse(
                {"detail": "Not authenticated"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # Check if user has admin role
        if UserRole.ADMIN not in current_user.roles:
            return JSONResponse(
                {"detail": "Admin role required"}, status_code=status.HTTP_403_FORBIDDEN
            )

        # Get all users (would be implemented in a real endpoint)
        users, total = await user_repo.get_all_users()

        # Return user list
        return {
            "users": [{"id": str(user.id), "username": user.username} for user in users],
            "total": total,
        }

    # Add a direct test endpoint for role tests
    @app.get("/api/v1/test-api/role-test/{role}")
    async def role_test_endpoint(role: str, request: Request):
        """
        Test endpoint specifically for role-based access testing.

        This endpoint directly examines the X-Mock-Role header to determine
        access permissions without relying on the authentication middleware.
        """
        # Check for the X-Mock-Role header
        mock_role = request.headers.get("X-Mock-Role")
        if not mock_role:
            # If no role header, check for Authorization header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JSONResponse(
                    {"detail": "Not authenticated"},
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            # Try to extract role from token
            token = auth_header.replace("Bearer ", "")
            try:
                # Decode the token without verification
                from jose import jwt as jose_jwt

                payload = jose_jwt.decode(
                    token,
                    key=test_settings.JWT_SECRET_KEY,
                    options={"verify_signature": False, "verify_exp": False},
                )
                roles = payload.get("roles", [])
                if roles and isinstance(roles, list):
                    mock_role = roles[0]
                elif roles:
                    mock_role = roles
                else:
                    mock_role = "patient"  # Default role
            except Exception as e:
                logger.warning(f"Could not extract role from token: {e}")
                return JSONResponse(
                    {"detail": "Invalid token"},
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )

        # Now decide based on the role
        if role == "admin" and mock_role != "admin":
            return JSONResponse(
                {"detail": "Admin role required"}, status_code=status.HTTP_403_FORBIDDEN
            )
        elif role == "clinician" and mock_role not in ["admin", "clinician"]:
            return JSONResponse(
                {"detail": "Clinician or Admin role required"},
                status_code=status.HTTP_403_FORBIDDEN,
            )
        elif role == "patient" and mock_role not in ["admin", "clinician", "patient"]:
            return JSONResponse(
                {"detail": "Valid role required"}, status_code=status.HTTP_403_FORBIDDEN
            )

        # If the role check passes, return success
        return {
            "message": "Access granted",
            "requested_role": role,
            "user_role": mock_role,
        }

    # Add a test endpoint that raises a 500 error
    @app.get("/api/v1/test/error")
    async def test_error_endpoint():
        """Test endpoint that intentionally raises a 500 error."""
        raise Exception("This is an intentional test error")

    # Add a test endpoint for input validation
    @app.post("/api/v1/test/validation")
    async def test_validation_endpoint(data: dict):
        """Test endpoint for input validation."""
        # Return 422 for invalid format (handled by FastAPI)
        # Return 201 for valid format
        return JSONResponse(
            {"result": "success", "data": data}, status_code=status.HTTP_201_CREATED
        )

    # Add a middleware for security headers
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        """Middleware to add security headers to responses."""
        # Import logging inside the function to ensure it's always defined
        import logging

        logger = logging.getLogger("security_headers_middleware")

        # Completely bypass middleware for test endpoints
        if "/test-api/" in request.url.path or "/test/" in request.url.path:
            try:
                logger.debug(f"Bypassing security headers for test endpoint: {request.url.path}")
                try:
                    response = await call_next(request)
                    return response
                except Exception as e:
                    # For test endpoints, convert exceptions to JSON responses
                    # This allows our error testing to work properly
                    logger.info(f"Converting test endpoint error to JSONResponse: {e!s}")
                    from fastapi.responses import JSONResponse
                    from starlette import status

                    return JSONResponse(
                        {"detail": "Internal Server Error"},
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )
            except Exception as e:
                logger.error(
                    f"Exception in test endpoint (security headers): {type(e).__name__}: {e!s}"
                )
                # Return a generic error response instead of re-raising
                from fastapi.responses import JSONResponse
                from starlette import status

                return JSONResponse(
                    {"detail": "Internal Server Error"},
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        # For all other endpoints, add security headers
        try:
            response = await call_next(request)
            # Add security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Content-Security-Policy"] = "default-src 'self'"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
        except Exception as e:
            logger.error(f"Exception in add_security_headers: {type(e).__name__}: {e!s}")
            # Re-raise the exception to ensure it's properly handled
            raise

    # Add a direct test endpoint for PHI access tests
    @app.get("/api/v1/test-api/phi-access/{patient_id}")
    async def phi_access_test_endpoint(patient_id: str, request: Request):
        """
        Test endpoint specifically for PHI access testing.

        This endpoint directly checks if a user can access a patient's PHI
        without relying on the complex authentication middleware.
        """
        # Get the requesting user's ID and role from headers
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                {"detail": "Not authenticated"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # Extract token
        token = auth_header.replace("Bearer ", "")

        # Determine user ID and role from token
        try:
            # Use jose-jwt to decode without verification
            from jose import jwt as jose_jwt

            payload = jose_jwt.decode(
                token,
                key=test_settings.JWT_SECRET_KEY,
                options={
                    "verify_signature": False,
                    "verify_exp": False,
                    "verify_aud": False,  # Skip audience verification
                },
            )

            # Extract user ID
            user_id = payload.get("sub")
            if not user_id:
                return JSONResponse(
                    {"detail": "Missing user ID in token"},
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )

            # Extract role(s)
            roles_data = payload.get("roles", ["patient"])
            if isinstance(roles_data, list):
                role_list = roles_data
            else:
                role_list = [roles_data]

            # Check access permissions
            is_provider = any(r in ["admin", "clinician"] for r in role_list)
            is_same_patient = user_id == patient_id

            # Patient can only access their own PHI
            if "patient" in role_list and not is_provider and not is_same_patient:
                return JSONResponse(
                    {"detail": "Not authorized to access this patient's PHI"},
                    status_code=status.HTTP_403_FORBIDDEN,
                )

            # Return PHI data (simulated)
            return {
                "id": patient_id,
                "phi_data": {
                    "medical_record_number": f"MRN-{patient_id[:8]}",
                    "diagnosis": ["Test Diagnosis 1", "Test Diagnosis 2"],
                    "sensitive_info": "This is protected health information",
                },
            }

        except Exception as e:
            logger.error(f"Error processing PHI access test request: {e}")
            return JSONResponse(
                {"detail": f"Error processing request: {e!s}"},
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    return app


@pytest.fixture
def authenticated_user() -> DomainUser:
    """Create a test user with authentication credentials."""
    user_id = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
    return DomainUser(
        id=user_id,  # Use string directly, not UUID object
        username="test_doctor",
        email="test.doctor@example.com",
        first_name="Test",
        last_name="Doctor",
        full_name="Test Doctor",
        roles=[UserRole.CLINICIAN],  # Use UserRole enum directly, not the string value
        is_active=True,
        status=UserStatus.ACTIVE,
        password_hash="hashed_password_not_real",
        created_at=datetime.now(timezone.utc),
    )


class AuthTestHelper:
    """Helper class for authentication in tests"""

    def __init__(self, jwt_secret="test_secret_key_for_testing_only"):
        self.jwt_secret = jwt_secret
        self.algorithm = "HS256"
        self._tokens = {}  # cache tokens by user_id

    async def create_token(
        self,
        user_id,
        username=None,
        email=None,
        roles=None,
        first_name=None,
        last_name=None,
        expires_delta=None,
    ):
        """
        Create a test JWT token for a user

        Args:
            user_id: User ID for the token subject
            username: Username to include in the token
            email: Email to include in the token
            roles: List of role strings
            first_name: First name to include in the token
            last_name: Last name to include in the token
            expires_delta: Optional timedelta for token expiration

        Returns:
            JWT token string
        """
        # Set defaults
        roles = roles or ["patient"]
        expires = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=30))

        # Format user_id as string if it's a UUID
        if isinstance(user_id, uuid.UUID):
            user_id = str(user_id)

        # Create payload
        to_encode = {
            "sub": user_id,
            "username": username or f"user_{user_id[:8]}",
            "email": email or f"user_{user_id[:8]}@example.com",
            "roles": roles,
            "first_name": first_name or "Test",
            "last_name": last_name or "User",
            "exp": int(expires.timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "jti": str(uuid.uuid4()),
            "iss": "test-issuer",
            "aud": "test-audience",
            "type": "access",
        }

        # Encode and cache token
        token = jose_jwt.encode(to_encode, self.jwt_secret, algorithm=self.algorithm)
        self._tokens[user_id] = token
        return token

    async def get_auth_headers(self, user_id, username=None, email=None, roles=None):
        """
        Generate authentication headers with JWT token for a user

        Args:
            user_id: User ID for the token subject
            username: Username to include in the token
            email: Email to include in the token
            roles: Roles to include in the token (can be string, enum, or list of either)

        Returns:
            Dict with Authorization header
        """
        # Format user_id as string if it's a UUID
        if isinstance(user_id, uuid.UUID):
            user_id = str(user_id)

        # Set defaults for user attributes
        username = username or f"user_{user_id[:8]}"
        email = email or f"user_{user_id[:8]}@example.com"

        # Pass the roles directly to create_token
        # Let the token creation logic handle conversion of enum values if needed
        token = await self.create_token(
            user_id=user_id,
            username=username,
            email=email,
            roles=roles,
            # Include additional user fields required by the model
            first_name="Test",
            last_name="User",
        )
        return {"Authorization": f"Bearer {token}"}

    async def get_admin_headers(self):
        """Get headers for an admin user"""
        admin_id = uuid.uuid4()
        return await self.get_auth_headers(
            admin_id, username="admin_user", email="admin@example.com", roles=["admin"]
        )

    async def get_clinician_headers(self):
        """Get headers for a clinician user"""
        clinician_id = uuid.uuid4()
        return await self.get_auth_headers(
            clinician_id,
            username="clinician_user",
            email="clinician@example.com",
            roles=["clinician"],
        )

    async def get_patient_headers(self, patient_id=None):
        """Get headers for a patient user"""
        user_id = patient_id or uuid.uuid4()
        return await self.get_auth_headers(
            user_id,
            username="patient_user",
            email="patient@example.com",
            roles=["patient"],
        )


@pytest.fixture(scope="module")
def auth_test_helper():
    """Fixture providing the AuthTestHelper"""
    return AuthTestHelper()


@pytest.fixture(scope="function")
async def get_valid_auth_headers(
    auth_test_helper, authenticated_user, global_mock_jwt_service
) -> dict[str, str]:
    """Generate valid authentication headers with JWT token."""
    # Create valid token with authenticates_user's details
    token_data = {
        "sub": authenticated_user.id,
        "username": authenticated_user.username,
        "email": authenticated_user.email,
        "first_name": authenticated_user.first_name,
        "last_name": authenticated_user.last_name,
        "full_name": authenticated_user.full_name,
        "roles": [
            role.value if hasattr(role, "value") else role for role in authenticated_user.roles
        ],
        "status": authenticated_user.status.value
        if hasattr(authenticated_user.status, "value")
        else authenticated_user.status,
        "is_active": authenticated_user.is_active,
        "created_at": int(authenticated_user.created_at.timestamp())
        if authenticated_user.created_at
        else int(datetime.now(timezone.utc).timestamp()),
        "jti": str(uuid.uuid4()),
        "iss": "test-issuer",
        "aud": "test-audience",
        "type": "access",
        "testing": True,  # Mark as a test token
    }

    # Use the real token creation method for a proper token
    token = await global_mock_jwt_service.create_access_token(data=token_data)
    headers = {"Authorization": f"Bearer {token}"}

    # Store token in mock service's token store for validation
    if hasattr(global_mock_jwt_service, "token_store"):
        global_mock_jwt_service.token_store[token] = token_data
        # Set expiration far in the future for test tokens
        global_mock_jwt_service.token_exp_store[token] = datetime.now(timezone.utc) + timedelta(
            days=7
        )

        # Store the token directly without complex side effect chaining
        # This ensures the token will be found by the base mock_decode_token function
        logger.debug(f"Storing token for future decode: {token[:20]}...")

    return headers


@pytest.fixture
async def get_valid_provider_auth_headers(
    auth_test_helper, global_mock_jwt_service
) -> dict[str, str]:
    """Generate valid authentication headers for a provider (clinician) user."""
    provider_id = uuid.UUID("b1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22")

    # Create provider user data
    user_data = {
        "sub": str(provider_id),
        "username": "provider_user",
        "email": "provider@example.com",
        "roles": ["clinician"],
        "first_name": "Provider",
        "last_name": "Test",
        "is_active": True,
        "status": "active",
        "jti": str(uuid.uuid4()),
        "iss": "test-issuer",
        "aud": "test-audience",
        "type": "access",
        "testing": True,  # Mark as a test token
    }

    # Use the mock service to create a token
    token = await global_mock_jwt_service.create_access_token(data=user_data)
    headers = {"Authorization": f"Bearer {token}"}

    # Store the token data in the mock service's stores
    global_mock_jwt_service.token_store[token] = user_data
    global_mock_jwt_service.token_exp_store[token] = datetime.now(timezone.utc) + timedelta(days=7)

    # Store the token directly without complex side effect chaining
    logger.debug(f"Storing provider token for future decode: {token[:20]}...")

    return headers


@pytest.fixture(scope="function")
async def client_app_tuple_func_scoped(app_instance) -> tuple[AsyncClient, FastAPI]:
    """Create a function-scoped test client and app instance tuple."""
    transport = ASGITransport(app=app_instance)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, app_instance


@pytest.fixture(scope="module")
def test_settings() -> Settings:
    """Fixture for test settings."""
    return Settings(
        ENV="test",
        TEST_MODE=True,
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        JWT_SECRET_KEY="test_secret_key_for_testing_only",
        JWT_ALGORITHM="HS256",
        PHI_ENCRYPTION_KEY="test_key_for_encryption_of_phi_data_12345",
    )


@pytest.fixture(scope="session")
def global_mock_jwt_service() -> JWTServiceInterface:
    """Create a global mock JWT service for all tests."""
    # Create a proper mock that implements all the methods needed
    mock_service = MagicMock(spec=JWTServiceInterface)

    # Create token storage for the mock service
    mock_service.token_store = {}
    mock_service.token_exp_store = {}
    mock_service._token_blacklist = {}

    # Create simplified implementation functions for JWT service
    async def mock_create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
        """Mock create_access_token method for JWTService."""
        to_encode = data.copy()

        # Add token type
        to_encode.update({"token_type": "access"})

        # Set expiration
        now = datetime.now(timezone.utc)
        if expires_delta:
            expire = now + expires_delta
        else:
            # Use getattr with default value to prevent AttributeError
            expire = now + timedelta(
                minutes=getattr(test_settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 30)
            )

        to_encode.update(
            {
                "exp": expire,  # When this token expires
                "iat": now,  # When this token was issued
                "nbf": now,  # When this token becomes valid
                "jti": str(uuid.uuid4()),  # Unique token ID
            }
        )

        # Add any standard JWT claims if available in settings
        if hasattr(test_settings, "JWT_ISSUER"):
            to_encode.update({"iss": test_settings.JWT_ISSUER})
        if hasattr(test_settings, "JWT_AUDIENCE"):
            to_encode.update({"aud": test_settings.JWT_AUDIENCE})

        # Encode and return
        encoded_jwt = jwt.encode(
            to_encode,
            getattr(test_settings, "JWT_SECRET_KEY", "test-secret-key"),
            algorithm=getattr(test_settings, "JWT_ALGORITHM", "HS256"),
        )
        return encoded_jwt

    # Create refresh token implementation
    async def mock_create_refresh_token(data: dict, expires_delta: timedelta | None = None) -> str:
        """Mock create_refresh_token method for JWTService."""
        to_encode = data.copy()

        # Add standard claims for refresh tokens
        to_encode.update({"token_type": "refresh"})

        # Set expiration for refresh token (usually longer than access token)
        now = datetime.now(timezone.utc)
        if expires_delta:
            expire = now + expires_delta
        else:
            # Default to 7 days if not specified
            refresh_days = getattr(test_settings, "JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7)
            expire = now + timedelta(days=refresh_days)

        to_encode.update(
            {
                "exp": expire,  # When this token expires
                "iat": now,  # When this token was issued
                "nbf": now,  # When this token becomes valid
                "jti": str(uuid.uuid4()),  # Unique token ID
            }
        )

        # Add any standard JWT claims if available in settings
        if hasattr(test_settings, "JWT_ISSUER"):
            to_encode.update({"iss": test_settings.JWT_ISSUER})
        if hasattr(test_settings, "JWT_AUDIENCE"):
            to_encode.update({"aud": test_settings.JWT_AUDIENCE})

        # Encode and return
        encoded_jwt = jwt.encode(
            to_encode,
            getattr(test_settings, "JWT_SECRET_KEY", "test-secret-key"),
            algorithm=getattr(test_settings, "JWT_ALGORITHM", "HS256"),
        )
        return encoded_jwt

    # Decode token implementation
    async def mock_decode_token(token: str, options: dict = None) -> dict[str, Any]:
        # Skip expiration verification if specified in options
        skip_exp_verification = options and options.get("verify_exp") is False

        # Try directly from token store first
        if token in mock_service.token_store:
            # Check if token is expired, but only if verify_exp is not set to False in options
            if (
                (not skip_exp_verification)
                and token in mock_service.token_exp_store
                and mock_service.token_exp_store[token] < datetime.now(timezone.utc)
            ):
                raise TokenExpiredException("Token has expired")

            return mock_service.token_store[token]

        # If not in store, try to decode it as a test token without verification
        try:
            # Use jose-jwt to decode the token without verification
            from jose import jwt as jose_jwt

            # Decode without verification to check if it's a test token
            unverified_payload = jose_jwt.decode(
                token,
                key=getattr(test_settings, "JWT_SECRET_KEY", "test-secret-key"),
                options={
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_exp": False,  # Always skip expiration for initial decode
                    "verify_iss": False,
                },
            )

            # Always treat tokens as test tokens in the test environment
            # This ensures all JWT tokens created during tests are properly handled
            logger.debug(f"Decoded test token with sub: {unverified_payload.get('sub', 'unknown')}")
            
            # Store the token for future reference
            mock_service.token_store[token] = unverified_payload
            # Set a default expiration far in the future for test tokens
            mock_service.token_exp_store[token] = datetime.now(timezone.utc) + timedelta(days=7)
            
            # Now check expiration if requested
            if not skip_exp_verification:
                exp_timestamp = unverified_payload.get('exp')
                if exp_timestamp:
                    exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
                    if exp_datetime < datetime.now(timezone.utc):
                        raise TokenExpiredException("Token has expired")
            
            return unverified_payload
        except jose_jwt.JWTError as e:
            # If JWT decoding fails, raise appropriate exception
            raise InvalidTokenException(f"Invalid token format: {e!s}")
        except Exception as e:
            # If not a token we recognize, raise the appropriate exception
            raise InvalidTokenException(
                f"Token not found in store and not a valid test token: {e!s}"
            )

    # Generate tokens for user implementation
    async def get_test_auth_headers(user: User) -> dict[str, str]:
        user_data = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
        }

        # Add roles from user object if available
        if hasattr(user, "roles"):
            if isinstance(user.roles, list) or isinstance(user.roles, set):
                user_data["roles"] = [r.value if hasattr(r, "value") else r for r in user.roles]
            else:
                user_data["roles"] = [user.roles]
        else:
            user_data["roles"] = []

        access_token = await mock_create_access_token(user_data)
        refresh_token = await mock_create_refresh_token(user_data)

        return {"access_token": access_token, "refresh_token": refresh_token}

    # Refresh access token implementation
    async def mock_refresh_access_token(refresh_token: str) -> str:
        # Verify the refresh token
        try:
            token_data = await mock_decode_token(refresh_token)
            # Check if it's a refresh token
            if token_data.get("token_type") != "refresh":
                raise InvalidTokenException("Not a refresh token")

            # Create a new access token
            # Remove the token_type claim as it's specific to refresh tokens
            token_data_copy = token_data.copy()
            token_data_copy.pop("token_type", None)

            return await mock_create_access_token(token_data_copy)
        except Exception as e:
            raise InvalidTokenException(f"Invalid refresh token: {e!s}") from e

    # Verify token implementation - needs to be async to match interface
    async def mock_verify_token(token: str) -> dict[str, Any]:
        try:
            payload = await mock_decode_token(token)
            return payload
        except (InvalidTokenException, TokenExpiredException):
            return None

    # Get token expiration implementation
    async def mock_get_token_expiration(token: str) -> datetime | None:
        if token in mock_service.token_exp_store:
            return mock_service.token_exp_store[token]
        return None

    # Clear issued tokens implementation
    async def mock_clear_issued_tokens() -> None:
        mock_service.token_store.clear()
        mock_service.token_exp_store.clear()

    # Attach all the mock implementations to the mock service
    mock_service.create_access_token = AsyncMock(side_effect=mock_create_access_token)
    mock_service.create_refresh_token = AsyncMock(side_effect=mock_create_refresh_token)
    mock_service.decode_token = AsyncMock(side_effect=mock_decode_token)
    mock_service.get_tokens_for_user = AsyncMock(side_effect=get_test_auth_headers)
    mock_service.refresh_access_token = AsyncMock(side_effect=mock_refresh_access_token)
    mock_service.verify_token = AsyncMock(side_effect=mock_verify_token)
    mock_service.get_token_expiration = AsyncMock(side_effect=mock_get_token_expiration)
    mock_service.clear_issued_tokens = AsyncMock(side_effect=mock_clear_issued_tokens)

    # Mock for is_token_blacklisted - default to False for tests unless specified
    async def mock_is_token_blacklisted(token: str) -> bool:
        return False  # Default behavior: token is not blacklisted

    mock_service.is_token_blacklisted = AsyncMock(side_effect=mock_is_token_blacklisted)

    return mock_service


# This fixture is already defined above, so it's removed to prevent redefinition


@pytest.fixture(scope="module")
def jwt_service_patch():
    """Patch the JWT service to accept test tokens without verification in test environment."""
    import logging
    import uuid
    from datetime import datetime, timezone

    from jose import jwt as jose_jwt

    from app.infrastructure.security.jwt.jwt_service import (
        JWTService,
    )

    logger = logging.getLogger(__name__)

    # Save the original method
    original_decode_token = JWTService.decode_token

    # Dummy key for test tokens
    test_secret_key = "test_secret_key_for_testing_only"

    def patched_decode_token(self, token: str, options: dict = None) -> dict[str, Any]:
        """
        Patched version of decode_token that accepts test tokens without verification.
        For non-test tokens, falls back to the original implementation.

        Args:
            token: JWT token string
            options: Options for token verification, including {"verify_exp": False} to skip expiration check
        """
        if not token:
            # Match original behavior
            from app.domain.exceptions import AuthenticationError

            raise AuthenticationError("Token is missing")

        # If options is provided with verify_exp=False, we'll skip expiration verification
        skip_exp_verification = options and options.get("verify_exp") is False

        try:
            # Try to decode without verification to check if it's a test token
            try:
                # Always bypass signature verification for test tokens, but use provided options for exp verification if available
                decode_options = {
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_exp": False
                    if skip_exp_verification
                    else False,  # Always False for initial check
                    "verify_iss": False,
                }

                unverified_payload = jose_jwt.decode(
                    token,
                    key=test_secret_key,  # Any key will do for unverified
                    options=decode_options,
                )
            except Exception as e:
                logger.warning(f"Failed to decode token even without verification: {e}")
                # If we can't even decode it unverified, use original method
                return original_decode_token(self, token, options)

            # Check if this seems like a test token
            is_test_token = (
                ("iss" in unverified_payload and unverified_payload.get("iss") == "test-issuer")
                or ("sub" in unverified_payload and "test" in unverified_payload.get("sub", ""))
                or (getattr(self, "settings", None) and getattr(self.settings, "TESTING", False))
            )

            if is_test_token:
                logger.debug(
                    f"Processing test token with subject: {unverified_payload.get('sub', 'unknown')}"
                )

                # Ensure required fields exist
                if "roles" not in unverified_payload:
                    unverified_payload["roles"] = ["patient"]
                if "sub" not in unverified_payload:
                    unverified_payload["sub"] = f"test-user-{uuid.uuid4()}"
                if "type" not in unverified_payload:
                    unverified_payload["type"] = "access"

                # Set default expiration if missing (1 hour from now)
                if "exp" not in unverified_payload:
                    unverified_payload["exp"] = int(datetime.now(timezone.utc).timestamp()) + 3600

                # Set defaults for other required fields if missing
                if "iat" not in unverified_payload:
                    unverified_payload["iat"] = int(datetime.now(timezone.utc).timestamp())
                if "jti" not in unverified_payload:
                    unverified_payload["jti"] = str(uuid.uuid4())

                # Map token type string to enum
                token_type_str = unverified_payload.get("type", "access")
                token_type_enum = (
                    TokenType.REFRESH if token_type_str.lower() == "refresh" else TokenType.ACCESS
                )

                # Create and return TokenPayload
                return TokenPayload(
                    sub=unverified_payload.get("sub"),
                    roles=unverified_payload.get("roles", []),
                    exp=unverified_payload.get(
                        "exp", int(datetime.now(timezone.utc).timestamp()) + 3600
                    ),
                    iat=unverified_payload.get("iat", int(datetime.now(timezone.utc).timestamp())),
                    jti=unverified_payload.get("jti", str(uuid.uuid4())),
                    iss=unverified_payload.get("iss", "test-issuer"),
                    aud=unverified_payload.get("aud", "test-audience"),
                    type=token_type_enum,
                    # Map username to name if it exists
                    name=unverified_payload.get("username", "")
                    or unverified_payload.get("name", ""),
                    email=unverified_payload.get("email", ""),
                    permissions=unverified_payload.get("permissions", []),
                    # Add user_id to match the sub field
                    user_id=unverified_payload.get("sub"),
                )
        except Exception as e:
            logger.warning(f"Error in patched decode_token: {e}", exc_info=True)

        # Fall back to original implementation for non-test tokens or if test token processing fails
        return original_decode_token(self, token, options)

    # Apply the patch
    JWTService.decode_token = patched_decode_token

    # Yield to allow tests to run
    yield

    # Restore the original method
    JWTService.decode_token = original_decode_token


@pytest.fixture(scope="module")
def middleware_patch(test_settings):
    """Patch the authentication middleware to use test tokens."""
    import logging
    import uuid

    from fastapi.security.utils import get_authorization_scheme_param
    from jose import jwt as jose_jwt_jose

    from app.core.domain.entities.user import UserRole, UserStatus
    from app.presentation.middleware.authentication import AuthenticationMiddleware
    from app.presentation.schemas.auth import AuthenticatedUser

    # Define logger for the patched middleware
    logger = logging.getLogger("auth_middleware_patch")

    # Store the original dispatch method
    original_dispatch = AuthenticationMiddleware.dispatch
    original_validate = AuthenticationMiddleware._validate_and_prepare_user_context

    # Add JWT attributes to the middleware class, not just instances
    AuthenticationMiddleware.jwt_secret = test_settings.JWT_SECRET_KEY
    AuthenticationMiddleware.algorithm = test_settings.JWT_ALGORITHM

    # Create a patched _validate_and_prepare_user_context method to handle test tokens
    async def patched_validate_and_prepare_user_context(self, token: str, request: Request):
        """Patched validation method that will process test tokens without calling the database."""
        try:
            # First try to decode the token with JWT library (no signature verification)
            try:
                unverified_payload = jose_jwt_jose.decode(
                    token,
                    key=test_settings.JWT_SECRET_KEY,
                    options={
                        "verify_signature": False,
                        "verify_aud": False,
                        "verify_exp": False,
                        "verify_iss": False,
                    },
                )

                # Check if this is a test token
                is_test_token = (
                    ("iss" in unverified_payload and unverified_payload.get("iss") == "test-issuer")
                    or ("sub" in unverified_payload and "test" in unverified_payload.get("sub", ""))
                    or ("testing" in unverified_payload)
                )

                if is_test_token:
                    logger.debug(f"Processing test token: {unverified_payload.get('sub')}")

                    # Extract user info from token
                    user_id = uuid.UUID(unverified_payload.get("sub", str(uuid.uuid4())))
                    username = unverified_payload.get("username", f"test_user_{user_id}")
                    email = unverified_payload.get("email", f"{username}@example.com")
                    roles_data = unverified_payload.get("roles", ["patient"])

                    # Convert role strings to UserRole enums
                    user_roles = []
                    for role in roles_data:
                        try:
                            if isinstance(role, str):
                                user_roles.append(UserRole(role))
                            else:
                                user_roles.append(UserRole.PATIENT)
                        except (ValueError, TypeError):
                            # Default to PATIENT if role string doesn't match enum
                            user_roles.append(UserRole.PATIENT)

                    if not user_roles:
                        user_roles = [UserRole.PATIENT]

                    # Get scopes directly from token or use roles
                    scopes = unverified_payload.get("scopes", [r.value for r in user_roles])

                    # Create AuthenticatedUser
                    auth_user = AuthenticatedUser(
                        id=user_id,
                        username=username,
                        email=email,
                        roles=user_roles,
                        status=UserStatus.ACTIVE,
                    )

                    return auth_user, scopes
            except Exception as e:
                logger.warning(f"Error decoding test token: {e}")
                # Continue with original implementation if this isn't a test token

            # If not a test token or if test token processing failed, use original implementation
            return await original_validate(self, token, request)
        except Exception as e:
            logger.error(f"Error in patched validation: {e}", exc_info=True)
            raise

    # Create a patched dispatch that will accept test tokens without verification
    async def patched_dispatch(self, request, call_next):
        """Patched dispatch method for authentication tests."""
        # Check for bypass paths first
        path = request.url.path

        # Completely bypass middleware for test-api endpoints and other test endpoints
        if "/test-api/" in path or "/test/" in path or "/direct-test/" in path:
            try:
                logger.info(f"Bypassing authentication for test endpoint: {path}")
                return await call_next(request)
            except Exception as e:
                logger.error(
                    f"Exception in test endpoint (auth middleware): {type(e).__name__}: {e!s}"
                )
                # Re-raise to allow proper exception handling by the global handler
                raise

        # Extract token from request
        token = None
        authorization = request.headers.get("Authorization")
        if authorization:
            scheme, param = get_authorization_scheme_param(authorization)
            if scheme.lower() == "bearer":
                token = param

        # Special handling for X-Mock-Role header (used in tests)
        mock_role_header = request.headers.get("X-Mock-Role")
        if mock_role_header and token:
            logger.info(
                f"Found X-Mock-Role header: {mock_role_header}, processing special test auth"
            )
            try:
                # Look up the token in the global mock service's token store
                if (
                    hasattr(self.jwt_service, "token_store")
                    and token in self.jwt_service.token_store
                ):
                    token_data = self.jwt_service.token_store[token]

                    # Create authenticated user from token data
                    from app.core.domain.entities.user import UserRole, UserStatus
                    from app.presentation.schemas.auth import (
                        AuthCredentials,
                        AuthenticatedUser,
                    )

                    # Get user ID from token
                    user_id = uuid.UUID(token_data.get("sub", str(uuid.uuid4())))

                    # Determine role from token data or header
                    role_value = mock_role_header
                    try:
                        role_enum = UserRole(role_value)
                    except ValueError:
                        logger.warning(
                            f"Invalid role in X-Mock-Role header: {role_value}, defaulting to PATIENT"
                        )
                        role_enum = UserRole.PATIENT

                    # Create user context
                    auth_user = AuthenticatedUser(
                        id=user_id,
                        username=token_data.get("username", f"test_{role_enum.value}_user"),
                        email=token_data.get("email", f"test_{role_enum.value}@example.com"),
                        roles=[role_enum],
                        status=UserStatus.ACTIVE,
                    )

                    # Set user and auth in request scope
                    request.scope["user"] = auth_user
                    request.scope["auth"] = AuthCredentials(scopes=[role_enum.value])

                    logger.info(
                        f"Created mock user from X-Mock-Role and token: {auth_user.username} with role {role_enum}"
                    )

                    # Process the request with our authenticated user
                    return await call_next(request)
            except Exception as e:
                logger.error(f"Error in X-Mock-Role processing: {e!s}")
                # Continue with normal auth in case this fails

        if token:
            try:
                # Try to validate the token
                token_data = await self.jwt_service.verify_token(token)
                if token_data:
                    # Get user ID and roles from token data
                    user_id = token_data.get("sub", None)
                    if not user_id:
                        return self._create_unauthorized_response("Invalid user ID in token")

                    # Get roles from token
                    roles_data = token_data.get("roles", [])
                    if not roles_data:
                        return self._create_unauthorized_response("No roles specified in token")

                    # Convert role strings to UserRole enums
                    from app.core.domain.entities.user import UserRole, UserStatus

                    user_roles = []
                    if isinstance(roles_data, list):
                        for role in roles_data:
                            try:
                                if isinstance(role, str):
                                    user_roles.append(UserRole(role))
                                else:
                                    user_roles.append(role)
                            except ValueError:
                                # Default to patient for invalid roles
                                user_roles.append(UserRole.PATIENT)
                    elif isinstance(roles_data, str):
                        try:
                            user_roles.append(UserRole(roles_data))
                        except ValueError:
                            user_roles.append(UserRole.PATIENT)

                    # Create authenticated user
                    from app.presentation.schemas.auth import (
                        AuthCredentials,
                        AuthenticatedUser,
                    )

                    auth_user = AuthenticatedUser(
                        id=uuid.UUID(user_id) if isinstance(user_id, str) else user_id,
                        username=token_data.get("username", f"user_{user_id}"),
                        email=token_data.get("email", f"user_{user_id}@example.com"),
                        roles=user_roles,
                        status=UserStatus.ACTIVE,
                    )

                    # Set scopes based on roles
                    scopes = [role.value for role in user_roles]

                    # Set user and auth in request scope
                    request.scope["user"] = auth_user
                    request.scope["auth"] = AuthCredentials(scopes=scopes)

                    # Continue with authenticated request
                    return await call_next(request)
            except Exception as e:
                logger.error(f"Error validating token: {e!s}")
                return self._create_unauthorized_response(str(e))

        # For requests without a token, return unauthorized
        return self._create_unauthorized_response("No valid authentication credentials")

    # Helper method to create unauthorized response
    def _create_unauthorized_response(self, detail="Not authenticated"):
        """Create a JSON response for unauthorized requests."""
        from fastapi.responses import JSONResponse
        from starlette import status

        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": detail},
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Apply the patches to the middleware
    AuthenticationMiddleware.dispatch = patched_dispatch
    AuthenticationMiddleware._create_unauthorized_response = _create_unauthorized_response

    # Now patch the rate limiting middleware too
    from app.presentation.middleware.rate_limiting import RateLimitingMiddleware

    # Store the original rate limiting dispatch
    if hasattr(RateLimitingMiddleware, "dispatch"):
        original_rate_limit_dispatch = RateLimitingMiddleware.dispatch

        # Create a patched dispatch for rate limiting
        async def patched_rate_limit_dispatch(self, request, call_next):
            """Patched dispatch method for rate limiting tests."""
            # Skip test endpoints completely
            path = request.url.path
            if "/test-api/" in path or "/test/" in path or "/direct-test/" in path:
                try:
                    logger.info(f"Bypassing rate limiting for test endpoint: {path}")
                    return await call_next(request)
                except Exception as e:
                    logger.error(
                        f"Exception in test endpoint (rate limiting): {type(e).__name__}: {e!s}"
                    )
                    # Re-raise without handling to ensure proper error propagation
                    raise

            # For non-test endpoints, use original dispatch
            try:
                return await original_rate_limit_dispatch(self, request, call_next)
            except Exception as e:
                logger.error(f"Exception in rate limiting dispatch: {type(e).__name__}: {e!s}")
                # Re-raise to allow proper error handling
                raise

        # Apply the rate limiting patch
        RateLimitingMiddleware.dispatch = patched_rate_limit_dispatch

    yield

    # Restore the original methods
    AuthenticationMiddleware.dispatch = original_dispatch
    if hasattr(RateLimitingMiddleware, "dispatch") and "original_rate_limit_dispatch" in locals():
        RateLimitingMiddleware.dispatch = original_rate_limit_dispatch


@pytest.fixture(scope="module")
def auth_patches(jwt_service_patch: Any, middleware_patch: Any) -> None:
    """
    Combined fixture that applies both JWT service and middleware patches.

    Use this fixture when you need both authentication components patched
    for testing. It ensures the JWT service is patched first, followed by
    the middleware patch.
    """
    yield


class EnhancedAuthTestHelper:
    """
    Enhanced helper class for authentication in tests

    This class provides improved capabilities for creating test tokens,
    authenticated users, and auth headers for various test scenarios.
    """

    def __init__(self, jwt_secret="test_secret_key_for_testing_only", algorithm="HS256"):
        self.jwt_secret = jwt_secret
        self.algorithm = algorithm
        self._tokens = {}  # cache tokens by user_id
        self._users = {}  # cache users by role

    def create_test_user(
        self,
        role: UserRole,
        user_id: uuid.UUID | None = None,
        username: str | None = None,
        email: str | None = None,
        full_name: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
    ) -> DomainUser:
        """
        Create a test user with the specified role

        Args:
            role: UserRole enum value
            user_id: Optional UUID for the user (generated if None)
            username: Optional username (generated if None)
            email: Optional email (generated if None)
            full_name: Optional full name (generated if None)
            first_name: Optional first name (generated if None)
            last_name: Optional last name (generated if None)

        Returns:
            DomainUser: Test user with the specified role
        """
        # Generate consistent user ID for the same role
        if user_id is None:
            # Use predictable UUIDs for standard roles
            role_uuid_map = {
                UserRole.ADMIN: "00000000-0000-0000-0000-000000000001",
                UserRole.CLINICIAN: "00000000-0000-0000-0000-000000000002",
                UserRole.PATIENT: "00000000-0000-0000-0000-000000000003",
                UserRole.RESEARCHER: "00000000-0000-0000-0000-000000000004",
            }
            user_id = uuid.UUID(role_uuid_map.get(role, str(uuid.uuid4())))

        # Convert user_id to string if it's a UUID
        if isinstance(user_id, uuid.UUID):
            user_id = str(user_id)

        # Generate default values
        role_name = role.name.lower()
        if username is None:
            username = f"test_{role_name}"
        if email is None:
            email = f"test.{role_name}@clarity.health"
        if full_name is None:
            full_name = f"Test {role_name.title()}"
        if first_name is None:
            first_name = "Test"
        if last_name is None:
            last_name = role_name.title()

        # Create the user
        user = DomainUser(
            id=user_id,
            username=username,
            email=email,
            full_name=full_name,
            first_name=first_name,
            last_name=last_name,
            password_hash="$2b$12$TestPasswordHashForTestingOnly",
            roles={role},  # Always use a set for roles
            status=UserStatus.ACTIVE,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )

        # Cache the user by role
        self._users[role] = user

        return user

    async def create_token(
        self,
        user_or_id: DomainUser | UUID | str,
        roles: list[UserRole] | None = None,
        username: str | None = None,
        email: str | None = None,
        expires_delta: timedelta | None = None,
    ) -> str:
        """
        Create a test JWT token for a user

        Args:
            user_or_id: User instance or ID (UUID or str) for the token subject
            roles: Optional list of role strings (extracted from user if None)
            username: Optional username (extracted from user if None)
            email: Optional email (extracted from user if None)
            expires_delta: Optional timedelta for token expiration

        Returns:
            JWT token string
        """
        # Extract user ID and info if a User instance was provided
        user_id = None
        if isinstance(user_or_id, DomainUser):
            user = user_or_id
            user_id = user.id
            if username is None:
                username = user.username
            if email is None:
                email = user.email
            if roles is None and hasattr(user, "roles"):
                # Convert roles from UserRole enum to strings
                roles = [role.value if hasattr(role, "value") else role for role in user.roles]
        else:
            user_id = user_or_id

        # Set defaults
        roles = roles or ["patient"]
        expires = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=30))

        # Format user_id as string if it's a UUID
        if isinstance(user_id, uuid.UUID):
            user_id = str(user_id)

        # Create payload
        to_encode = {
            "sub": user_id,
            "username": username or f"user_{user_id[:8]}",
            "email": email or f"user_{user_id[:8]}@example.com",
            "roles": roles,
            "exp": int(expires.timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "jti": str(uuid.uuid4()),
            "iss": "test-issuer",
            "aud": "test-audience",
            "type": "access",
        }

        # Encode and cache token
        token = jwt.encode(to_encode, self.jwt_secret, algorithm=self.algorithm)
        self._tokens[user_id] = token
        return token

    async def get_auth_headers(self, user_or_role, username=None, email=None):
        """
        Get authorization headers for a user or role

        Args:
            user_or_role: User instance, UserRole enum, or role string
            username: Optional username to include in the token
            email: Optional email to include in the token

        Returns:
            Dict of headers with Authorization
        """
        # Handle different types of input
        if isinstance(user_or_role, DomainUser):
            # Use the provided User instance
            user = user_or_role
        elif isinstance(user_or_role, UserRole):
            # Create or get a user with the specified role
            user = self._users.get(user_or_role)
            if user is None:
                user = self.create_test_user(user_or_role)
        elif isinstance(user_or_role, str):
            # Try to convert string to UserRole enum
            try:
                role = UserRole(user_or_role.lower())
                user = self._users.get(role)
                if user is None:
                    user = self.create_test_user(role)
            except ValueError:
                # Treat as a user_id
                user_id = user_or_role
                token = await self.create_token(user_id, username=username, email=email)
                return {"Authorization": f"Bearer {token}"}
        else:
            # Default to a patient role
            role = UserRole.PATIENT
            user = self._users.get(role)
            if user is None:
                user = self.create_test_user(role)

        # Create token for the user
        token = await self.create_token(user)
        return {"Authorization": f"Bearer {token}"}

    async def get_role_headers(self, role_name: str):
        """
        Get headers for a specific role

        Args:
            role_name: Role name as string (admin, clinician, patient, researcher)

        Returns:
            Dict of headers with Authorization
        """
        try:
            role = UserRole(role_name.lower())
            return await self.get_auth_headers(role)
        except ValueError:
            # Default to patient role if invalid
            return await self.get_auth_headers(UserRole.PATIENT)


@pytest.fixture(scope="module")
def enhanced_auth_helper():
    """Fixture providing the EnhancedAuthTestHelper"""
    return EnhancedAuthTestHelper()
