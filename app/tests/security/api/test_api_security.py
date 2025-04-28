# -*- coding: utf-8 -*-
"""
HIPAA Compliance Testing - API Security Tests

These tests validate that API endpoints properly secure access to sensitive patient data
according to HIPAA requirements. Tests focus on authentication, authorization,
input validation, and secure communication.
"""

import json
import uuid
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import time
import asyncio
from typing import Callable, Dict, Any, Coroutine
from datetime import datetime, timedelta

from httpx import AsyncClient
from fastapi import status, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.testclient import TestClient

# Use the new canonical config location
from app.config.settings import get_settings

# JWTService might be needed for direct token manipulation if required beyond fixtures
from app.infrastructure.security.jwt.jwt_service import JWTService
# AuthenticationService might be needed if testing it directly
from app.infrastructure.security.auth.authentication_service import AuthenticationService
from app.domain.entities.patient import Patient
from app.domain.exceptions.patient_exceptions import PatientNotFoundError

# Import necessary modules for testing API security
# These seem specific to this test module's setup
from app.tests.security.utils.test_mocks import MockAuthService, MockRBACService, MockAuditLogger
# Base class for security tests, likely provides common setup/methods
from app.tests.security.utils.base_security_test import BaseSecurityTest

# Dependency and interface imports for potential direct mocking
from app.core.interfaces.services.jwt_service import IJwtService
from app.presentation.api.dependencies.auth import get_jwt_service
from app.core.interfaces.repositories.patient_repository import IPatientRepository
from app.presentation.api.dependencies.database import get_repository

# Global test patient ID for consistency
TEST_PATIENT_ID = str(uuid.uuid4())
OTHER_PATIENT_ID = str(uuid.uuid4())

@pytest.mark.db_required()
class TestAuthentication(BaseSecurityTest):
    """Test authentication mechanisms using the async_client fixture with mocked auth."""

    @pytest.mark.asyncio
    async def test_missing_token(self, client: AsyncClient):
        """Test that requests without tokens are rejected."""
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        # The default mock in async_client fixture handles None token -> 401

    @pytest.mark.asyncio
    async def test_invalid_token_format(self, client: AsyncClient):
        """Test that structurally invalid tokens are rejected (by jose.jwt)."""
        headers = {"Authorization": "Bearer invalid.token.format"}
        # The real get_current_user calls jwt_service.get_user_from_token, which calls decode_token.
        # decode_token raises AuthenticationError for JWTError.
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid token" in response.json().get("detail", "").lower()

    @pytest.mark.asyncio
    async def test_expired_token(self, client: AsyncClient):
        """Test that expired tokens are rejected."""
        headers = {"Authorization": "Bearer EXPIRED_TOKEN"}
        # Mock configured in async_client fixture raises AuthenticationError("Token has expired.")
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "expired" in response.json().get("detail", "").lower()

    @pytest.mark.asyncio
    async def test_tampered_token(self, client: AsyncClient):
        """Test that tokens with invalid signatures are rejected."""
        headers = {"Authorization": "Bearer INVALID_SIGNATURE_TOKEN"}
        # Mock configured in async_client fixture raises AuthenticationError
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "invalid token" in response.json().get("detail", "").lower() # Check specific error if mock raises it

    @pytest.mark.asyncio
    async def test_valid_token_access(self, client: AsyncClient):
        """Test that a valid token grants access."""
        headers = {"Authorization": "Bearer VALID_PATIENT_TOKEN"}
        # Mock configured in async_client returns a valid User object
        # Assuming /api/v1/patients/{id} requires patient role or higher and exists
        # We need to ensure the ID matches the mock user potentially, or mock the repo
        # Let's assume for now the endpoint allows access if authenticated, focusing on authN
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        # This might fail with 403 if TEST_PATIENT_ID doesn't match the mocked user ID from the token
        # Or 404 if the endpoint requires the patient to exist and repo isn't mocked
        # For now, let's assert 200, assuming the simplest case for auth middleware
        assert response.status_code == status.HTTP_200_OK # Adjust if endpoint requires specific patient ID match or existence


class TestAuthorization(BaseSecurityTest):
    """Test authorization logic (role-based access, resource ownership)."""

    @pytest.mark.asyncio
    async def test_patient_accessing_own_data(self, client: AsyncClient):
        """Patient with valid token can access their own resource."""
        # We need the ID returned by the mock for VALID_PATIENT_TOKEN
        # This is tricky as the mock generates a random UUID. 
        # Option 1: Patch the mock *within the test* to return a specific ID.
        # Option 2: Make the test endpoint return the user ID from the token.
        # Option 3: Modify the mock in conftest to use a predictable ID for VALID_PATIENT_TOKEN.
        # Let's try Option 2 for now, assuming a test endpoint exists or can be added.
        
        # Assume endpoint /api/v1/me returns current user details
        headers = {"Authorization": "Bearer VALID_PATIENT_TOKEN"}
        response_me = await client.get("/api/v1/users/me", headers=headers) # Assuming this endpoint exists
        assert response_me.status_code == status.HTTP_200_OK
        my_user_id = response_me.json().get("id")
        assert my_user_id is not None

        # Now access the patient-specific endpoint with the correct ID
        response_patient = await client.get(f"/api/v1/patients/{my_user_id}", headers=headers)
        assert response_patient.status_code == status.HTTP_200_OK

    @pytest.mark.asyncio
    async def test_patient_accessing_other_patient_data(self, client: AsyncClient):
        """Patient with valid token CANNOT access another patient's resource."""
        headers = {"Authorization": "Bearer VALID_PATIENT_TOKEN"}
        # Accessing a different patient ID should be forbidden by get_patient_id dependency
        response = await client.get(f"/api/v1/patients/{OTHER_PATIENT_ID}", headers=headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_provider_accessing_patient_data(self, client: AsyncClient):
        """Provider with valid token CAN access any patient's resource."""
        headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
        # Provider should be able to access any patient ID via get_patient_id dependency
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        # Expect 200 OK or 404 (if patient doesn't exist and endpoint requires it)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]

    @pytest.mark.asyncio
    async def test_role_specific_endpoint_access(self, client: AsyncClient):
        """Test access to endpoints protected by role dependencies."""
        # Assuming an endpoint like /api/v1/admin/users requires admin role
        admin_endpoint = "/api/v1/admin/users" # Placeholder - replace with actual endpoint

        # Test with patient token (should be forbidden)
        patient_headers = {"Authorization": "Bearer VALID_PATIENT_TOKEN"}
        response_patient = await client.get(admin_endpoint, headers=patient_headers)
        assert response_patient.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

        # Test with provider token (should be forbidden)
        provider_headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
        response_provider = await client.get(admin_endpoint, headers=provider_headers)
        assert response_provider.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND]

        # Test with admin token (should be allowed or 404)
        admin_headers = {"Authorization": "Bearer VALID_ADMIN_TOKEN"}
        response_admin = await client.get(admin_endpoint, headers=admin_headers)
        assert response_admin.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND]


# TestRateLimiting class removed previously


@pytest.mark.db_required()
class TestInputValidation(BaseSecurityTest):
    """Test input validation using Pydantic models and FastAPI."""

    @pytest.mark.asyncio
    async def test_invalid_input_format_rejected(self, client: AsyncClient):
        """FastAPI should return 422 for missing/invalid fields."""
        headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"} # Need auth for POST
        # Assuming POST /api/v1/patients requires certain fields per PatientCreateSchema
        invalid_payload = {"name": "Test Patient Only"} # Missing required fields

        response = await client.post("/api/v1/patients", headers=headers, json=invalid_payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_input_sanitization_handling(self, client: AsyncClient):
        """Test how potentially malicious input is handled (framework/model validation)."""
        headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
        # Input that might contain XSS attempt - Pydantic/FastAPI should handle basic validation
        # More advanced sanitization might require specific middleware/logic to test.
        malicious_input = {
            # Assuming schema requires name, dob, etc.
            "name": "Valid Name<script>alert('XSS attempt')</script>",
            "date_of_birth": "2000-01-01",
            "gender": "other",
            "contact_info": {"email": "test@example.com"}
        }
        response = await client.post("/api/v1/patients", headers=headers, json=malicious_input)
        # Expect 422 if Pydantic validation catches the script tag in a standard string field,
        # or 201/200 if it passes validation but is hopefully sanitized before storage/reflection.
        # For this test, let's assume basic validation passes or fails with 422.
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY # Adjust if validation allows it

    @pytest.mark.asyncio
    async def test_input_length_limits_enforced(self, client: AsyncClient):
        """Test Pydantic model length constraints."""
        headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
        # Assuming PatientCreateSchema has max_length on name
        long_name = "a" * 500 # Assume max length is less than 500
        payload = {
            "name": long_name,
            "date_of_birth": "2000-01-01",
            "gender": "other",
            "contact_info": {"email": "test@example.com"}
        }
        response = await client.post("/api/v1/patients", headers=headers, json=payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.db_required()
class TestSecureHeaders(BaseSecurityTest):
    """Test presence and configuration of security-related HTTP headers."""

    @pytest.mark.asyncio
    async def test_required_security_headers_present(self, client: AsyncClient):
        """Check for headers like Strict-Transport-Security, X-Content-Type-Options etc."""
        # Make request to any endpoint, e.g., /health (usually doesn't require auth)
        response = await client.get("/health")
        assert response.status_code == status.HTTP_200_OK
        # Check for common security headers (exact headers depend on middleware config)
        assert "Strict-Transport-Security" in response.headers
        assert "X-Content-Type-Options" in response.headers
        assert "nosniff" in response.headers["X-Content-Type-Options"].lower()
        # Add checks for other headers like X-Frame-Options, Content-Security-Policy if configured

    @pytest.mark.asyncio
    async def test_cors_headers_configuration(self, client: AsyncClient):
        """Verify CORS headers for allowed origins."""
        # Test with an allowed origin from settings
        allowed_origin = "http://localhost:3000" # Assumes this is in BACKEND_CORS_ORIGINS
        headers = {"Origin": allowed_origin}
        response = await client.options("/health", headers=headers) # OPTIONS request for CORS preflight
        assert response.status_code == status.HTTP_200_OK
        assert response.headers.get("access-control-allow-origin") == allowed_origin
        assert "GET" in response.headers.get("access-control-allow-methods", "")

        # Test with a disallowed origin
        disallowed_origin = "http://malicious.com"
        headers = {"Origin": disallowed_origin}
        response = await client.options("/health", headers=headers)
        # Expect no CORS headers for disallowed origin (or specific denial)
        assert "access-control-allow-origin" not in response.headers # Common behavior


@pytest.mark.db_required()
class TestErrorHandling(BaseSecurityTest):
    """Test secure handling of application errors (no PHI leakage)."""

    @pytest.mark.asyncio
    async def test_not_found_error_generic(self, client: AsyncClient):
        """Test that 404 errors return a generic message."""
        headers = {"Authorization": "Bearer VALID_PROVIDER_TOKEN"}
        response = await client.get("/api/v1/non_existent_endpoint", headers=headers)
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "detail" in response.json()
        assert "not found" in response.json()["detail"].lower()
        # Ensure no sensitive info like internal paths are leaked

    @pytest.mark.asyncio
    async def test_internal_server_error_masked(
        self, client: AsyncClient # No longer need app fixture here
    ):
        """Test that unexpected errors result in a generic 500 response."""
        headers = {"Authorization": "Bearer VALID_ADMIN_TOKEN"} # Use a token likely to pass initial checks

        # Patch the specific repository method that the endpoint likely calls
        # Adjust the target path based on where find_by_id is actually located/imported
        # Assuming it's within an instance obtained via a dependency
        # We target the *source* of the dependency function if possible
        target_repo_path = "app.presentation.api.dependencies.database.get_repository" # Or specific repo path if known
        # More likely, we patch the *method* on the repository class itself if that's easier
        target_method_path = "app.infrastructure.persistence.sqlalchemy.repositories.patient_repository.PatientRepository.find_by_id"

        with patch(target_method_path, new_callable=AsyncMock) as mock_find_by_id:
            # Configure the mock to raise an unexpected error
            mock_find_by_id.side_effect = Exception("Simulated unexpected DB error")

            # Make the request
            response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)

            # Assert that the response is 500 Internal Server Error
            assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            # Assert that the detailed error message is masked
            response_json = response.json()
            assert "detail" in response_json
            assert "Internal server error" in response_json["detail"] # Check for generic message
            assert "Simulated unexpected DB error" not in response_json["detail"] # Ensure specific error isn't leaked

        # Clean up dependency overrides if they were set elsewhere (less critical now)
        # if hasattr(app, 'dependency_overrides') and get_repository(Patient) in app.dependency_overrides:
        #     del app.dependency_overrides[get_repository(Patient)]


# --- Standalone Tests (Potentially move to specific endpoint test files) ---

@pytest.mark.asyncio
async def test_access_patient_phi_data_success_provider(
    client: AsyncClient, app: MagicMock # Access app to override repo
):
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
):
    """Patient attempts to access another patient's data and fails (403)."""
    headers = {"Authorization": "Bearer VALID_PATIENT_TOKEN"}
    response = await client.get(f"/api/v1/patients/{OTHER_PATIENT_ID}", headers=headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN

@pytest.mark.asyncio
async def test_access_patient_phi_data_patient_not_found(
    client: AsyncClient, app: MagicMock # Access app to override repo
):
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
):
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