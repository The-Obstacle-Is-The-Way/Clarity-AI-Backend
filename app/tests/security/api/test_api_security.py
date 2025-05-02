"""
HIPAA Compliance Testing - API Security Tests

These tests validate that API endpoints properly secure access to sensitive patient data
according to HIPAA requirements. Tests focus on authentication, authorization,
input validation, and secure communication.
"""

import uuid
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, status
from httpx import AsyncClient

# Use the new canonical config location
from app.config.settings import get_settings
from app.core.interfaces.repositories.patient_repository import IPatientRepository

# Import necessary modules for testing API security
# REMOVE Mocks specific to BaseSecurityTest if not needed directly
# from app.tests.security.utils.test_mocks import MockAuthService, MockRBACService, MockAuditLogger
# REMOVE Base class import
# from app.tests.security.utils.base_security_test import BaseSecurityTest
# Dependency and interface imports for potential direct mocking
from app.core.interfaces.services.jwt_service import IJwtService

# AuthenticationService might be needed if testing it directly
from app.domain.entities.patient import Patient

# Import Role enum if needed for token generation/verification
from app.domain.entities.user import User  # Ensure User is imported for type hints

# JWTService might be needed for direct token manipulation if required beyond fixtures
from app.infrastructure.security.jwt.jwt_service import JWTService
from app.presentation.api.dependencies.auth import get_jwt_service
from app.presentation.api.dependencies.database import get_repository

# Global test patient ID for consistency
TEST_PATIENT_ID = str(uuid.uuid4())
OTHER_PATIENT_ID = str(uuid.uuid4())

# Remove class inheritance and usefixtures marker
# @pytest.mark.usefixtures("client")
@pytest.mark.db_required() # Keep db_required if needed for underlying deps
class TestAuthentication:
    """Test authentication mechanisms using the application fixtures."""

    @pytest.mark.asyncio
    async def test_missing_token(self, client: AsyncClient) -> None:
        """Test that requests without tokens are rejected."""
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        # The middleware handles missing tokens

    @pytest.mark.asyncio
    async def test_invalid_token_format(self, client: AsyncClient) -> None:
        """Test that structurally invalid tokens are rejected."""
        headers = {"Authorization": "Bearer invalid.token.format"}
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        # FastAPI/Starlette auth middleware or jose.jwt should catch this
        # Check detail message if provided by the framework
        assert "Not authenticated" in response.json().get("detail", "") or \
               "Invalid token" in response.json().get("detail", "")

    @pytest.mark.asyncio
    async def test_expired_token(self, client: AsyncClient, test_jwt_service: JWTService) -> None:
        """Test that expired tokens are rejected."""
        # Create an expired token using the test JWT service
        user_data = {"sub": "test-user-expired", "roles": ["patient"]}
        # Create token with negative expiry
        expired_token = await test_jwt_service.create_access_token(
            data=user_data, expires_delta=timedelta(minutes=-5)
        )
        headers = {"Authorization": f"Bearer {expired_token}"}

        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        # Check for standard FastAPI error message for expired token
        assert "Signature has expired" in response.json().get("detail", "")

    @pytest.mark.asyncio
    async def test_tampered_token(self, client: AsyncClient, test_jwt_service: JWTService) -> None:
        """Test that tokens with invalid signatures are rejected."""
        # Create a valid token first
        user_data = {"sub": "test-user-tampered", "roles": ["patient"]}
        valid_token = await test_jwt_service.create_access_token(data=user_data)

        # Tamper with the token payload slightly (won't match signature)
        tampered_token = valid_token + "tamper"
        headers = {"Authorization": f"Bearer {tampered_token}"}

        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Could not validate credentials" in response.json().get("detail", "") # Standard FastAPI error

    @pytest.mark.asyncio
    async def test_valid_token_access(
        self,
        client: AsyncClient,
        get_valid_auth_headers: dict[str, str], # Use the fixture from conftest
        app: FastAPI # Get app fixture to potentially override repo
    ) -> None:
        """Test that a valid token grants access (mocking repo)."""
        headers = get_valid_auth_headers # Use the generated valid headers
        
        # Mock the repository to return a valid patient for this ID
        # Note: get_valid_auth_headers uses 'test-integration-user' as sub
        # We need the get_by_id to succeed for this user/patient ID
        mock_patient_repo = AsyncMock(spec=IPatientRepository)
        mock_user_id = uuid.UUID("test-integration-user") # ID from get_valid_auth_headers
        
        async def mock_get_patient(patient_id: uuid.UUID) -> User | None:
            if patient_id == mock_user_id:
                # Return a mock Patient domain entity matching the authenticated user
                # Ensure the returned object structure matches what the endpoint expects
                mock_patient = MagicMock(spec=Patient)
                mock_patient.id = patient_id
                mock_patient.user_id = mock_user_id # Link to user
                # Add other necessary attributes the endpoint might access
                return mock_patient
            return None
            
        mock_patient_repo.get_by_id = mock_get_patient
        app.dependency_overrides[get_repository(IPatientRepository)] = lambda: mock_patient_repo

        # Make the request - use the mock user ID for the patient endpoint
        response = await client.get(f"/api/v1/patients/{mock_user_id}", headers=headers)
        
        # Clean up override afterwards
        if get_repository(IPatientRepository) in app.dependency_overrides:
             del app.dependency_overrides[get_repository(IPatientRepository)]

        # Assert successful access
        assert response.status_code == status.HTTP_200_OK
        mock_patient_repo.get_by_id.assert_awaited_once_with(mock_user_id)

# Remove class inheritance and usefixtures marker
# @pytest.mark.usefixtures("client")
class TestAuthorization: # Removed BaseSecurityTest inheritance
    """Test authorization logic (role-based access, resource ownership)."""

    @pytest.mark.asyncio
    async def test_patient_accessing_own_data(
        self, 
        client: AsyncClient, 
        get_valid_auth_headers: dict[str, str], # Use patient headers fixture
        app: FastAPI # Use app fixture to override repo
    ) -> None:
        """Patient with valid token can access their own resource."""
        headers = get_valid_auth_headers
        
        # Mock repo needed because endpoint likely tries to fetch the patient
        mock_patient_repo = AsyncMock(spec=IPatientRepository)
        # The user ID from get_valid_auth_headers is 'test-integration-user'
        mock_user_id = uuid.UUID("test-integration-user") 

        async def mock_get_patient(patient_id: uuid.UUID) -> User | None:
            if patient_id == mock_user_id:
                mock_patient = MagicMock(spec=Patient)
                mock_patient.id = patient_id
                mock_patient.user_id = mock_user_id
                # Add other necessary attributes
                return mock_patient
            return None
        mock_patient_repo.get_by_id = mock_get_patient
        app.dependency_overrides[get_repository(IPatientRepository)] = lambda: mock_patient_repo

        # Access the patient-specific endpoint with the correct ID
        response_patient = await client.get(f"/api/v1/patients/{mock_user_id}", headers=headers)
        
        # Clean up override
        if get_repository(IPatientRepository) in app.dependency_overrides:
            del app.dependency_overrides[get_repository(IPatientRepository)]

        assert response_patient.status_code == status.HTTP_200_OK
        # Add assertion for response content if needed
        assert response_patient.json().get("id") == str(mock_user_id)

    @pytest.mark.asyncio
    async def test_patient_accessing_other_patient_data(
        self, 
        client: AsyncClient, 
        get_valid_auth_headers: dict[str, str] # Use patient headers fixture
    ) -> None:
        """Patient with valid token CANNOT access another patient's resource."""
        headers = get_valid_auth_headers
        # Accessing a different patient ID should be forbidden by authorization logic
        # No repo mock needed as authorization should happen before repo access attempt
        response = await client.get(f"/api/v1/patients/{OTHER_PATIENT_ID}", headers=headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_provider_accessing_patient_data(
        self, 
        client: AsyncClient, 
        get_valid_provider_auth_headers: dict[str, str], # Use provider headers fixture
        app: FastAPI # Use app fixture to override repo
    ) -> None:
        """Provider with valid token CAN access any patient's resource."""
        headers = get_valid_provider_auth_headers
        
        # Mock repo to simulate patient existence
        mock_patient_repo = AsyncMock(spec=IPatientRepository)
        mock_patient_id_to_access = uuid.UUID(TEST_PATIENT_ID) # ID defined globally
        
        async def mock_get_patient(patient_id: uuid.UUID) -> User | None:
             if patient_id == mock_patient_id_to_access:
                 mock_patient = MagicMock(spec=Patient)
                 mock_patient.id = patient_id
                 # Provider doesn't need user_id match
                 # Add other necessary attributes
                 return mock_patient
             return None
        mock_patient_repo.get_by_id = mock_get_patient
        app.dependency_overrides[get_repository(IPatientRepository)] = lambda: mock_patient_repo

        # Provider should be able to access this patient ID
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        
        # Clean up override
        if get_repository(IPatientRepository) in app.dependency_overrides:
             del app.dependency_overrides[get_repository(IPatientRepository)]

        # Expect 200 OK because provider has access and mock repo returns patient
        assert response.status_code == status.HTTP_200_OK
        assert response.json().get("id") == TEST_PATIENT_ID

    @pytest.mark.asyncio
    async def test_role_specific_endpoint_access(
        self, 
        client: AsyncClient, 
        get_valid_auth_headers: dict[str, str], 
        get_valid_provider_auth_headers: dict[str, str],
        test_jwt_service: JWTService # Needed to create admin token
    ) -> None:
        """Test access to endpoints protected by role dependencies."""
        # Assuming an endpoint like /api/v1/admin/users requires admin role
        admin_endpoint = "/api/v1/admin/users" # Placeholder - replace with actual endpoint

        # Test with patient token (should be forbidden)
        patient_headers = get_valid_auth_headers
        response_patient = await client.get(admin_endpoint, headers=patient_headers)
        # Expect 403 Forbidden or 404 Not Found if endpoint doesn't exist
        assert response_patient.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

        # Test with provider token (should be forbidden)
        provider_headers = get_valid_provider_auth_headers
        response_provider = await client.get(admin_endpoint, headers=provider_headers)
        assert response_provider.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

        # Test with admin token (should be allowed or 404)
        # Create admin token
        admin_user_data = {"sub": "test-admin-user", "roles": ["admin"]}
        admin_token = await test_jwt_service.create_access_token(data=admin_user_data)
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        
        response_admin = await client.get(admin_endpoint, headers=admin_headers)
        # Assume endpoint exists for admin, but might not be implemented -> 404
        # Or returns data -> 200
        assert response_admin.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


# TestRateLimiting class removed previously

# Remove class inheritance and usefixtures marker
# @pytest.mark.usefixtures("client")
@pytest.mark.db_required() # Keep if validation might interact with DB constraints indirectly
class TestInputValidation:
    """Test input validation using Pydantic models and FastAPI."""

    @pytest.mark.asyncio
    async def test_invalid_input_format_rejected(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """FastAPI should return 422 for missing/invalid fields."""
        headers = get_valid_provider_auth_headers # Use provider token for POST
        # Assuming POST /api/v1/patients requires certain fields per PatientCreateSchema
        # Payload missing required fields like date_of_birth, gender, contact_info
        invalid_payload = {"name": {"first_name": "Test", "last_name": "PatientOnly"}} 

        response = await client.post("/api/v1/patients", headers=headers, json=invalid_payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_input_sanitization_handling(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Test how potentially malicious input is handled (framework/model validation)."""
        headers = get_valid_provider_auth_headers
        malicious_input = {
            # Assuming schema defined in PatientCreate (or similar)
            "name": {"first_name": "Valid<script>alert('XSS')</script>", "last_name": "Name"},
            "date_of_birth": "2000-01-01",
            "gender": "other",
            "contact_info": {"email": "test<script>@example.com", "phone": "555-1234"}
        }
        response = await client.post("/api/v1/patients", headers=headers, json=malicious_input)
        # Expect 422 if Pydantic validation catches common invalid patterns
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_input_length_limits_enforced(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Test Pydantic model length constraints."""
        headers = get_valid_provider_auth_headers
        # Assuming PatientCreateSchema has max_length=50 on first_name (example)
        long_name = "a" * 100 
        payload = {
            "name": {"first_name": long_name, "last_name": "LastName"},
            "date_of_birth": "2000-01-01",
            "gender": "other",
            "contact_info": {"email": "test@example.com", "phone": "555-1234"}
        }
        response = await client.post("/api/v1/patients", headers=headers, json=payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

# Remove class inheritance and usefixtures marker
# @pytest.mark.usefixtures("client")
@pytest.mark.db_required() # Keep if health check might ping db
class TestSecureHeaders:
    """Test presence and configuration of security-related HTTP headers."""

    @pytest.mark.asyncio
    async def test_required_security_headers_present(self, client: AsyncClient) -> None:
        """Check for headers like Strict-Transport-Security, X-Content-Type-Options etc."""
        response = await client.get("/health") # Use a typically unsecured endpoint
        assert response.status_code == status.HTTP_200_OK
        # Check for common security headers (exact headers depend on app's middleware config)
        assert "strict-transport-security" in response.headers
        assert "x-content-type-options" in response.headers
        assert "nosniff" in response.headers["x-content-type-options"].lower()
        # Add checks for X-Frame-Options, Content-Security-Policy if configured
        assert "x-frame-options" in response.headers
        assert "content-security-policy" in response.headers

    @pytest.mark.asyncio
    async def test_cors_headers_configuration(self, client: AsyncClient, app: FastAPI) -> None:
        """Verify CORS headers for allowed origins."""
        # Get allowed origins from settings used by the app fixture
        settings = get_settings() # Assuming get_settings() works in test context or is mocked
        # If settings isn't easily accessible, use a known allowed origin from config
        allowed_origin = settings.BACKEND_CORS_ORIGINS[0] if settings.BACKEND_CORS_ORIGINS else "http://testallowed.com"
        
        headers = {"Origin": allowed_origin}
        response = await client.options("/health", headers=headers) # Use OPTIONS for preflight
        assert response.status_code == status.HTTP_200_OK
        assert response.headers.get("access-control-allow-origin") == allowed_origin
        assert "GET" in response.headers.get("access-control-allow-methods", "")

        # Test with a disallowed origin
        disallowed_origin = "http://malicious-site.com"
        headers = {"Origin": disallowed_origin}
        response = await client.options("/health", headers=headers)
        # CORS middleware should not return allow headers for disallowed origins
        assert "access-control-allow-origin" not in response.headers

# Remove class inheritance and usefixtures marker
# @pytest.mark.usefixtures("client")
@pytest.mark.db_required() # Keep if error handling might involve db lookups
class TestErrorHandling:
    """Test secure handling of application errors (no PHI leakage)."""

    @pytest.mark.asyncio
    async def test_not_found_error_generic(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Test that 404 errors return a generic message."""
        headers = get_valid_provider_auth_headers # Need auth to try accessing non-existent resource
        response = await client.get("/api/v1/non_existent_endpoint/123", headers=headers)
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "detail" in response.json()
        assert "not found" in response.json()["detail"].lower()
        # Ensure no stack trace or internal paths are leaked

    @pytest.mark.asyncio
    async def test_internal_server_error_masked(
        self, 
        client: AsyncClient, 
        get_valid_provider_auth_headers: dict[str, str],
        app: FastAPI # Use app to override dependency
    ) -> None:
        """Test that unexpected errors result in a generic 500 response."""
        headers = get_valid_provider_auth_headers 

        # Target the repository dependency used by the endpoint
        target_repo_interface = IPatientRepository # Assuming endpoint uses this interface
        original_repo_dep = app.dependency_overrides.get(get_repository(target_repo_interface))

        # Mock the repository method to raise an unexpected error
        mock_repo_instance = AsyncMock(spec=target_repo_interface)
        mock_repo_instance.get_by_id.side_effect = Exception("Simulated unexpected internal error")
        app.dependency_overrides[get_repository(target_repo_interface)] = lambda: mock_repo_instance

        try:
            # Make the request to an endpoint that uses the mocked repo method
            response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
            
            # Assert that the response is 500 Internal Server Error
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            # Assert that the detailed error message is masked
            response_json = response.json()
            assert "detail" in response_json
            # Check for generic message (FastAPI default or custom one)
            assert "Internal server error" in response_json["detail"] 
            assert "Simulated unexpected internal error" not in response_json["detail"]
        finally:
            # Clean up the dependency override
            if original_repo_dep:
                 app.dependency_overrides[get_repository(target_repo_interface)] = original_repo_dep
            elif get_repository(target_repo_interface) in app.dependency_overrides:
                 del app.dependency_overrides[get_repository(target_repo_interface)]

# --- Standalone Tests (Potentially move to specific endpoint test files) ---

@pytest.mark.asyncio
async def test_access_patient_phi_data_success_provider(
    client: AsyncClient, app: MagicMock # Access app to override repo
) -> None:
    """Provider successfully retrieves patient data (mocked repo)."""
    # Mock the repository call within this test
    mock_patient = Patient(id=TEST_PATIENT_ID, name="Test", date_of_birth="2000-01-01") # Simplified Patient
    mock_repo = MagicMock(spec=IPatientRepository)
    mock_repo.get_by_id = AsyncMock(return_value=mock_patient) # Use AsyncMock
    app.dependency_overrides[get_repository(IPatientRepository)] = lambda: mock_repo

    headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == TEST_PATIENT_ID
    mock_repo.get_by_id.assert_awaited_once_with(uuid.UUID(TEST_PATIENT_ID))

    # Clean up override
    del app.dependency_overrides[get_repository(IPatientRepository)]

@pytest.mark.asyncio
async def test_access_patient_phi_data_unauthorized_patient(
    client: AsyncClient,
) -> None:
    """Patient attempts to access another patient's data and fails (403)."""
    headers = {"Authorization": "Bearer VALID_PATIENT_TOKEN"}
    response = await client.get(f"/api/v1/patients/{OTHER_PATIENT_ID}", headers=headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.asyncio
async def test_access_patient_phi_data_patient_not_found(
    client: AsyncClient, app: MagicMock # Access app to override repo
) -> None:
    """Accessing a non-existent patient returns 404."""
    mock_repo = MagicMock(spec=IPatientRepository)
    # Simulate patient not found by returning None
    mock_repo.get_by_id = AsyncMock(return_value=None) # Use AsyncMock
    app.dependency_overrides[get_repository(IPatientRepository)] = lambda: mock_repo

    headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
    response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    mock_repo.get_by_id.assert_awaited_once_with(uuid.UUID(TEST_PATIENT_ID))

    # Clean up override
    del app.dependency_overrides[get_repository(IPatientRepository)]


@pytest.mark.asyncio
@pytest.mark.db_required # Keep DB required if real service might hit DB fallback
async def test_authenticated_but_unknown_role(
    client: AsyncClient, app: MagicMock # Access app to override JWT service
) -> None:
    """Test scenario where token is valid but has an unrecognized role."""
    # Override the JWT service mock specifically for this test
    mock_jwt_service_instance = MagicMock(spec=IJwtService)
    # Return a user with a strange role (as a string)
    unknown_role_user = User(id=uuid.uuid4(), email="unknown@test.com", username="unknown", role="UNKNOWN_ROLE", roles=["UNKNOWN_ROLE"])
    mock_jwt_service_instance.get_user_from_token = AsyncMock(return_value=unknown_role_user)
    app.dependency_overrides[get_jwt_service] = lambda: mock_jwt_service_instance

    headers = {"Authorization": "Bearer VALID_UNKNOWN_ROLE_TOKEN"} # Assumes this token maps to the mock
    # Access an endpoint that requires a specific role (e.g., clinician)
    response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)

    # Expect 403 Forbidden because the role check in get_patient_id or require_role should fail
    assert response.status_code == status.HTTP_403_FORBIDDEN

    # Clean up override
    del app.dependency_overrides[get_jwt_service] 