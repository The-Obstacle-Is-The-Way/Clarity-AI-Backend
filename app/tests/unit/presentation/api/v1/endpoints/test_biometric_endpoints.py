"""
Unit tests for biometric endpoints dependencies.

These tests verify that the biometric endpoints dependencies correctly
handle authentication and patient ID validation.
"""

from collections.abc import Generator  # Added Generator
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi import Depends, FastAPI, HTTPException, status  # Added status
from fastapi.security import OAuth2PasswordBearer
from fastapi.testclient import TestClient

# Corrected exception import syntax
from app.domain.exceptions import (
    AuthenticationError,
)  # Removed extra parenthesis after 'import'

# Assuming these dependencies exist in the specified path
# Corrected dependency import syntax
from app.presentation.api.dependencies.auth import get_current_user, get_jwt_service

# Create a mock OAuth2 scheme for testing
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
# Import service dependencies from the correct location
# Import schema from the correct location
# Assuming JWTService exists for mocking
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.domain.entities.user import User  # Added User import

# Corrected import path for UserRole enum
from app.domain.enums.role import Role as UserRole

# Correct import for the dependency function
from app.presentation.api.v1.routes.biometric_endpoints import (
    get_patient_id,
    require_admin_role,
    # router, # Removed - Endpoint modules typically don't export routers directly
    # get_biometric_twin_service, # Moved import to dependencies
    # BiometricDataBatchRequest, # This is a schema, should not be imported from endpoint
    # BiometricDataResponse # This is also a schema
    require_clinician_role,
)


@pytest.fixture
def mock_jwt_service():
    """Create a mock JWT service conforming to JWTService."""
    # Use autospec to ensure mock follows the interface
    mock = MagicMock(spec=JWTService)
    # Setup the decode_token method to be properly awaitable
    # Adjust methods based on JWTService (e.g., get_user_from_token)
    mock.decode_token = AsyncMock() # Keep if needed by other parts
    mock.get_user_from_token = AsyncMock() # Mock the method actually used by get_current_user
    return mock

@pytest.fixture
def app(mock_jwt_service): # Removed redundant decorator
    """Create a FastAPI test app with test endpoints."""
    app_instance = FastAPI()

    # Import UserRole here for use in mock definitions

    # --- Mock Dependency Setup --- 
    # Define override functions that return the mock service
    # No longer need override_get_jwt_service as we inject the mock directly
    # def override_get_jwt_service():
    #    return mock_jwt_service

    # Override get_current_user to use the mock_jwt_service correctly
    # (The existing override in the file already uses the injected mock service, 
    # but let's simplify the get_current_user override to directly return a user 
    # based on the mock_jwt_service.get_user_from_token mock setup in each test)
    async def override_get_current_user_for_test(
        token: str = Depends(oauth2_scheme), # Keep dependency signature
        # Inject the *mock* service here via the override below
        mock_jwt_service_instance: JWTService = Depends(get_jwt_service)
    ):
        if not token or token == "":
            raise HTTPException(status_code=401, detail="Not authenticated")
        try:
            # Delegate directly to the mocked method
            user = await mock_jwt_service_instance.get_user_from_token(token)
            if user is None: # If mock returns None, raise 401
                raise HTTPException(status_code=401, detail="Mocked user not found")
            return user
        except AuthenticationError as e:
            # Allow mock to raise AuthenticationError
            raise HTTPException(status_code=401, detail=str(e))
        except Exception as e:
            # Handle unexpected mock errors
            raise HTTPException(status_code=500, detail=f"Mock error: {e}")

    # Register the overrides - override get_jwt_service with the mock instance directly
    app_instance.dependency_overrides[get_jwt_service] = lambda: mock_jwt_service
    # Keep the get_current_user override, as it now correctly uses the overridden get_jwt_service
    # app_instance.dependency_overrides[get_current_user] = override_get_current_user_for_test
    # ^^ Actually, the original override should work now that get_jwt_service is imported and overridden.
    # Let's stick with overriding get_jwt_service only for simplicity, unless tests fail.

    # Define test endpoints using the dependencies
    @app_instance.get("/test/user-id")
    async def test_get_current_user_id_endpoint(
        current_user: User = Depends(get_current_user) # Depend on get_current_user
    ):
        return {"user_id": str(current_user.id)} # Extract ID from user object

    @app_instance.get("/test/patient/{patient_id}")
    async def test_get_patient_id_endpoint(
        patient_id: UUID = Depends(get_patient_id)
    ):
        return {"patient_id": str(patient_id)}

    @app_instance.get("/test/user-role")
    async def test_get_current_user_role_endpoint(
        current_user: User = Depends(get_current_user) # Depend on get_current_user
    ):
        return {"role": current_user.role} # Extract role from user object

    @app_instance.get("/test/clinician-only")
    async def test_require_clinician_role_endpoint(
        _: None = Depends(require_clinician_role),
        current_user: User = Depends(get_current_user) # Depend on get_current_user
    ):
        return {"user_id": str(current_user.id)} # Return user_id for assertion

    @app_instance.get("/test/admin-only")
    async def test_require_admin_role_endpoint(
        _: None = Depends(require_admin_role),
        current_user: User = Depends(get_current_user) # Depend on get_current_user
    ):
        return {"user_id": str(current_user.id)} # Return user_id for assertion

    return app_instance

@pytest.fixture
def client(app: FastAPI) -> Generator[TestClient, None, None]: # Corrected type hint
    """Create a test client for the FastAPI app."""
    # Need to use TestClient context manager if lifespan events are involved
    with TestClient(app) as test_client:
        yield test_client

# Correctly indented class definition
@pytest.mark.db_required() # Assuming this marker is correctly defined elsewhere
class TestBiometricEndpointsDependencies:
    """Tests for the biometric endpoints dependencies."""

    @pytest.mark.asyncio
    async def test_get_current_user_id_success(self, client: TestClient, mock_jwt_service):
        """Test that get_current_user_id returns the user ID from the token."""
        user_id = uuid4()
        # Use string role values from UserRole enum
        mock_user = User(id=user_id, email="test@example.com", username="test", role=UserRole.CLINICIAN.value, roles=[UserRole.CLINICIAN.value])
        mock_jwt_service.get_user_from_token.return_value = mock_user

        # Use the client fixture, which wraps the app
        response = client.get(
            "/test/user-id", headers={"Authorization": "Bearer test_token"}
        )
        
        assert response.status_code == 200
        assert response.json() == {"user_id": str(user_id)}
        mock_jwt_service.get_user_from_token.assert_called_once_with("test_token")

    @pytest.mark.asyncio
    async def test_get_current_user_id_missing_sub(
        self, client: TestClient, mock_jwt_service):
        """Test get_current_user handles token payload missing subject (via get_user_from_token returning None)."""
        # Simulate decode success but missing 'sub' leading to user not found
        mock_jwt_service.get_user_from_token.return_value = None 

        response = client.get(
            "/test/user-id", headers={"Authorization": "Bearer test_token"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        # Check detail message from get_current_user's credentials_exception
        assert "Could not validate credentials" in response.json().get("detail", "")

    @pytest.mark.asyncio
    async def test_get_current_user_id_authentication_exception(
        self, client: TestClient, mock_jwt_service):
        """Test that get_current_user handles AuthenticationError from jwt_service."""
        error_message = "Invalid token signature"
        mock_jwt_service.get_user_from_token.side_effect = AuthenticationError(error_message)

        response = client.get(
            "/test/user-id", headers={"Authorization": "Bearer test_token"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert error_message in response.json().get("detail", "")

    @pytest.mark.asyncio
    async def test_get_current_user_id_generic_exception(
        self, client: TestClient, mock_jwt_service):
        """Test that get_current_user handles generic exceptions from jwt_service."""
        # Simulate an unexpected error during user lookup
        mock_jwt_service.get_user_from_token.side_effect = Exception("Database connection failed")

        response = client.get(
            "/test/user-id", headers={"Authorization": "Bearer test_token"}
        )
        
        # get_current_user should catch generic Exception and return 401
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate credentials" in response.json().get("detail", "")

    @pytest.mark.asyncio
    async def test_get_patient_id(self, client: TestClient, mock_jwt_service):
        """Test the get_patient_id dependency happy path."""
        user_id = uuid4()
        patient_id_to_test = uuid4()
        # Use string role value
        mock_user = User(id=user_id, email="clinician@example.com", username="clinician", role=UserRole.CLINICIAN.value, roles=[UserRole.CLINICIAN.value])
        mock_jwt_service.get_user_from_token.return_value = mock_user

        response = client.get(
            f"/test/patient/{patient_id_to_test}", 
            headers={"Authorization": "Bearer clinician_token"}
        )
        
        assert response.status_code == 200
        assert response.json() == {"patient_id": str(patient_id_to_test)}

    @pytest.mark.asyncio
    async def test_get_current_user_role_success(
        self, client: TestClient, mock_jwt_service):
        """Test getting the user role successfully."""
        user_id = uuid4()
        # Use string role value
        mock_user = User(id=user_id, email="admin@example.com", username="admin", role=UserRole.ADMIN.value, roles=[UserRole.ADMIN.value])
        mock_jwt_service.get_user_from_token.return_value = mock_user

        response = client.get(
            "/test/user-role", headers={"Authorization": "Bearer admin_token"}
        )
        
        assert response.status_code == 200
        # Assert against the string enum value
        assert response.json() == {"role": UserRole.ADMIN.value}

    # --- Tests for require_clinician_role ---
    @pytest.mark.asyncio
    async def test_require_clinician_role_success(
        self, client: TestClient, mock_jwt_service):
        """Test clinician access to clinician-only route."""
        user_id = uuid4()
        # Use string role value
        mock_user = User(id=user_id, email="clinician@a.com", username="c", role=UserRole.CLINICIAN.value, roles=[UserRole.CLINICIAN.value])
        mock_jwt_service.get_user_from_token.return_value = mock_user

        response = client.get(
            "/test/clinician-only", headers={"Authorization": "Bearer clinician_token"}
        )
        assert response.status_code == 200
        assert response.json() == {"user_id": str(user_id)}

    @pytest.mark.asyncio
    async def test_require_clinician_role_admin(
        self, client: TestClient, mock_jwt_service):
        """Test admin access to clinician-only route (should succeed if admins have clinician privileges implicitly or explicitly). 
           Adjust logic if admins *cannot* access clinician routes.
        """
        user_id = uuid4()
        # Use string role values
        mock_user = User(id=user_id, email="admin@a.com", username="a", role=UserRole.ADMIN.value, roles=[UserRole.ADMIN.value, UserRole.CLINICIAN.value]) # Explicitly give both roles for clarity
        mock_jwt_service.get_user_from_token.return_value = mock_user

        response = client.get(
            "/test/clinician-only", headers={"Authorization": "Bearer admin_token"}
        )
        assert response.status_code == 200 # Change to 403 if Admin != Clinician access
        assert response.json() == {"user_id": str(user_id)}

    @pytest.mark.asyncio
    async def test_require_clinician_role_patient(
        self, client: TestClient, mock_jwt_service):
        """Test patient access to clinician-only route (should fail)."""
        user_id = uuid4()
        # Use string role value
        mock_user = User(id=user_id, email="patient@a.com", username="p", role=UserRole.PATIENT.value, roles=[UserRole.PATIENT.value])
        mock_jwt_service.get_user_from_token.return_value = mock_user

        response = client.get(
            "/test/clinician-only", headers={"Authorization": "Bearer patient_token"}
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert UserRole.CLINICIAN.value in response.json().get("detail", "")

    # --- Tests for require_admin_role ---
    @pytest.mark.asyncio
    async def test_require_admin_role_success(self, client: TestClient, mock_jwt_service):
        """Test admin access to admin-only route."""
        user_id = uuid4()
        # Use string role value
        mock_user = User(id=user_id, email="admin@a.com", username="a", role=UserRole.ADMIN.value, roles=[UserRole.ADMIN.value])
        mock_jwt_service.get_user_from_token.return_value = mock_user

        response = client.get(
            "/test/admin-only", headers={"Authorization": "Bearer admin_token"}
        )
        assert response.status_code == 200
        assert response.json() == {"user_id": str(user_id)}

    @pytest.mark.asyncio
    async def test_require_admin_role_clinician(
        self, client: TestClient, mock_jwt_service):
        """Test clinician access to admin-only route (should fail)."""
        user_id = uuid4()
        # Use string role value
        mock_user = User(id=user_id, email="clinician@a.com", username="c", role=UserRole.CLINICIAN.value, roles=[UserRole.CLINICIAN.value])
        mock_jwt_service.get_user_from_token.return_value = mock_user

        response = client.get(
            "/test/admin-only", headers={"Authorization": "Bearer clinician_token"}
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert UserRole.ADMIN.value in response.json().get("detail", "")

    # Add tests for missing role in token for require_ role dependencies
    # Add tests for invalid token / authentication errors
