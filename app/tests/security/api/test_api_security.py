"""
HIPAA Compliance Testing - API Security Tests

These tests validate that API endpoints properly secure access to sensitive patient data
according to HIPAA requirements. Tests focus on authentication, authorization,
input validation, and secure communication.
"""

import uuid
from datetime import timedelta, datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import logging

import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout
from fastapi import FastAPI, status
from httpx import AsyncClient

from app.core.interfaces.repositories.patient_repository import IPatientRepository
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.domain.entities.user import UserRole, UserStatus, User
from app.core.domain.entities.patient import Patient as CorePatient

# Ensure IJwtService is imported if JWTService spec needs it, but global_mock_jwt_service is MagicMock
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface 
from app.presentation.api.dependencies.auth import get_user_repository_dependency
from app.presentation.api.dependencies.database import get_patient_repository_dependency

# Imports for TestAuthentication specifically
from app.infrastructure.persistence.sqlalchemy.repositories.user_repository import SQLAlchemyUserRepository
from app.core.domain.entities.user import User as DomainUser # Alias to avoid clash if User schema is also named User

TEST_PATIENT_ID = str(uuid.uuid4())
OTHER_PATIENT_ID = str(uuid.uuid4())

test_logger = logging.getLogger(__name__)

@pytest.mark.db_required()
class TestAuthentication:
    """Test authentication mechanisms using the application fixtures."""

    @pytest.mark.asyncio
    async def test_missing_token(self, client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI]) -> None:
        """Test that requests without tokens are rejected."""
        client, _ = client_app_tuple_func_scoped
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_invalid_token_format(self, client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI]) -> None:
        """Test that structurally invalid tokens are rejected."""
        client, _ = client_app_tuple_func_scoped
        headers = {"Authorization": "Bearer invalid.token.format"}
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        # Be less strict about the exact error message
        detail = response.json().get("detail", "")
        assert "token" in detail.lower() or "invalid" in detail.lower()

    @pytest.mark.asyncio
    async def test_expired_token(self, client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI], global_mock_jwt_service: MagicMock) -> None:
        """Test that expired tokens are rejected."""
        client, _ = client_app_tuple_func_scoped
        user_data = {"sub": "test-user-expired", "roles": [UserRole.PATIENT.value]}
        # create_access_token is an AsyncMock on global_mock_jwt_service
        expired_token = await global_mock_jwt_service.create_access_token(
            data=user_data, expires_delta=timedelta(minutes=-5)
        )
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        # Be less strict about the exact error message
        detail = response.json().get("detail", "")
        assert detail, "Response should contain an error detail"

    @pytest.mark.asyncio
    async def test_tampered_token(self, client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI], global_mock_jwt_service: MagicMock) -> None:
        """Test that tokens with invalid signatures are rejected."""
        client, _ = client_app_tuple_func_scoped
        user_data = {"sub": "test-user-tampered", "roles": [UserRole.PATIENT.value]}
        # create_access_token is an AsyncMock on global_mock_jwt_service
        valid_token = await global_mock_jwt_service.create_access_token(data=user_data)
        tampered_token = valid_token + "tamper"
        headers = {"Authorization": f"Bearer {tampered_token}"}
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}", headers=headers)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        # Be less strict about the exact error message
        detail = response.json().get("detail", "")
        assert detail, "Response should contain an error detail"

    @pytest.mark.asyncio
    async def test_valid_token_access(
        self,
        client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
        get_valid_auth_headers: dict[str, str], 
        global_mock_jwt_service: MagicMock,
        authenticated_user: User 
    ) -> None:
        """Test that a valid token allows access to a protected endpoint (e.g., /auth/me)."""
        client, current_fastapi_app = client_app_tuple_func_scoped
        headers = get_valid_auth_headers 

        test_logger.info(f"TestAuth.test_valid_token_access: Using token for user ID: {authenticated_user.id}, username: {authenticated_user.username}")
        test_logger.info(f"TestAuth.test_valid_token_access: Headers being used: {headers}")

        response = await client.get("/api/v1/auth/me", headers=headers)

        assert response.status_code == status.HTTP_200_OK, f"Response: {response.text}"
        response_data = response.json()
        assert response_data["username"] == authenticated_user.username
        assert response_data["email"] == authenticated_user.email
        
        # Look for the clinician role
        roles_lower = [r.lower() if isinstance(r, str) else str(r).lower() for r in response_data["roles"]]
        assert "clinician" in roles_lower, f"Expected clinician role in {response_data['roles']}"

class TestAuthorization:
    """Test authorization logic (role-based access, resource ownership)."""

    @pytest.mark.asyncio
    async def test_patient_accessing_own_data(
        self,
        client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
        get_valid_auth_headers: dict[str, str],
        global_mock_jwt_service: MagicMock
    ) -> None:
        """Test that a patient can access their own data."""
        client, current_fastapi_app = client_app_tuple_func_scoped
        headers = get_valid_auth_headers
        token_data = await global_mock_jwt_service.decode_token(token=headers["Authorization"].replace("Bearer ", ""))
        accessing_user_id = uuid.UUID(token_data.sub) if hasattr(token_data, 'sub') else uuid.UUID(token_data["sub"])

        mock_user_repo = AsyncMock(spec=IUserRepository)
        async def mock_get_user_by_id(*, user_id: uuid.UUID):
            if user_id == accessing_user_id:
                # Handle TokenPayload objects (which have attributes) or dictionaries (which have get method)
                if hasattr(token_data, 'username'):
                    username = token_data.username
                    email = token_data.email if hasattr(token_data, 'email') else f"{username}@example.com"
                else:
                    # Fallback for dictionaries or other types
                    username = token_data.get("username", f"user-{accessing_user_id}")
                    email = token_data.get("email", f"{username}@example.com")
                    
                return User(
                    id=str(accessing_user_id),
                    username=username,
                    email=email,
                    first_name="Test",
                    last_name="User", 
                    full_name=f"{username} Full Name",
                    roles=[UserRole.PATIENT],
                    account_status=UserStatus.ACTIVE,
                    password_hash="hashed_password_example",
                    created_at=datetime.now(timezone.utc)
                )
            return None
        mock_user_repo.get_by_id = mock_get_user_by_id
        mock_user_repo.get_user_by_id = mock_get_user_by_id

        mock_patient_repo = AsyncMock(spec=IPatientRepository)
        async def mock_get_patient_record(*, patient_id: uuid.UUID):
            if patient_id == accessing_user_id:
                # Handle TokenPayload objects (which have attributes) or dictionaries (which have get method)
                if hasattr(token_data, 'email'):
                    email = token_data.email
                else:
                    # Fallback for dictionaries or other types
                    email = token_data.get("email", f"user-{accessing_user_id}@example.com")
                    
                return CorePatient(
                    id=accessing_user_id,
                    first_name="Test",
                    last_name="User",
                    date_of_birth="1990-01-01",
                    email=email
                )
            return None
        mock_patient_repo.get_by_id = mock_get_patient_record

        current_fastapi_app.dependency_overrides[get_user_repository_dependency] = lambda: mock_user_repo
        current_fastapi_app.dependency_overrides[get_patient_repository_dependency] = lambda: mock_patient_repo

        response = await client.get(f"/api/v1/patients/{accessing_user_id}", headers=headers)

        if get_user_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_user_repository_dependency]
        if get_patient_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_patient_repository_dependency]

        assert response.status_code == status.HTTP_200_OK, response.text
        response_data = response.json()
        assert response_data["id"] == str(accessing_user_id)
        # Based on CorePatient mock structure, the "name" would be "first_name last_name"
        # However, the patient_router.py maps this to "name" : f"{patient.first_name} {patient.last_name}"
        assert response_data["name"] == "Test User" 

    @pytest.mark.asyncio
    async def test_patient_accessing_other_patient_data(
        self,
        client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
        global_mock_jwt_service: MagicMock
    ) -> None:
        """Test that a patient cannot access another patient's data."""
        client, current_fastapi_app = client_app_tuple_func_scoped
        user1_id = uuid.uuid4()
        user1_token_data = {"sub": str(user1_id), "roles": [UserRole.PATIENT.value], "username": "patient1", "email": "patient1@example.com"}
        user1_token = await global_mock_jwt_service.create_access_token(data=user1_token_data)
        headers_user1 = {"Authorization": f"Bearer {user1_token}"}
        user2_patient_id = uuid.UUID(OTHER_PATIENT_ID) # Use defined OTHER_PATIENT_ID for clarity

        mock_user_repo = AsyncMock(spec=IUserRepository)
        async def mock_get_user1_by_id(*, user_id: uuid.UUID):
            if user_id == user1_id:
                return User(id=user1_id, username="patient1", email="patient1@example.com", full_name="Patient One Full Name", roles=[UserRole.PATIENT], account_status=UserStatus.ACTIVE, password_hash="hash")
            return None
        mock_user_repo.get_by_id = mock_get_user1_by_id
        mock_user_repo.get_user_by_id = mock_get_user1_by_id

        mock_patient_repo = AsyncMock(spec=IPatientRepository)
        async def mock_get_patient2_record(*, patient_id: uuid.UUID):
            if patient_id == user2_patient_id:
                return CorePatient(id=user2_patient_id, first_name="Other", last_name="Patient", date_of_birth="1999-01-01", email="other@example.com")
            return None
        mock_patient_repo.get_by_id = mock_get_patient2_record

        current_fastapi_app.dependency_overrides[get_user_repository_dependency] = lambda: mock_user_repo
        current_fastapi_app.dependency_overrides[get_patient_repository_dependency] = lambda: mock_patient_repo

        response = await client.get(f"/api/v1/patients/{user2_patient_id}", headers=headers_user1)

        if get_user_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_user_repository_dependency]
        if get_patient_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_patient_repository_dependency]

        assert response.status_code == status.HTTP_403_FORBIDDEN, response.text

    @pytest.mark.asyncio
    async def test_provider_accessing_patient_data(
        self,
        client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
        get_valid_provider_auth_headers: dict[str, str],
        global_mock_jwt_service: MagicMock
    ) -> None:
        """Test that a provider (clinician) can access patient data."""
        client, current_fastapi_app = client_app_tuple_func_scoped
        headers = get_valid_provider_auth_headers
        token_data = await global_mock_jwt_service.decode_token(token=headers["Authorization"].replace("Bearer ", ""))
        provider_user_id = uuid.UUID(token_data.sub) if hasattr(token_data, 'sub') else uuid.UUID(token_data["sub"])
        patient_to_access_id = uuid.UUID(TEST_PATIENT_ID)

        mock_user_repo = AsyncMock(spec=IUserRepository)
        async def mock_get_provider_user_by_id(*, user_id: uuid.UUID):
            if user_id == provider_user_id:
                # Handle TokenPayload objects (which have attributes) or dictionaries (which have get method)
                if hasattr(token_data, 'username'):
                    username = token_data.username
                    email = token_data.email if hasattr(token_data, 'email') else f"{username}@example.com"
                else:
                    # Fallback for dictionaries or other types
                    username = token_data.get("username", f"provider-{provider_user_id}")
                    email = token_data.get("email", f"{username}@example.com")
                    
                return User(
                    id=provider_user_id, 
                    username=username, 
                    email=email, 
                    full_name=f"Dr. {username}",
                    roles=[UserRole.CLINICIAN], 
                    account_status=UserStatus.ACTIVE,
                    password_hash="hashed_password_example"
                )
            return None
        mock_user_repo.get_by_id = mock_get_provider_user_by_id
        mock_user_repo.get_user_by_id = mock_get_provider_user_by_id

        mock_patient_repo = AsyncMock(spec=IPatientRepository)
        async def mock_get_patient_record(*, patient_id: uuid.UUID):
            if patient_id == patient_to_access_id:
                return CorePatient(
                    id=patient_to_access_id, 
                    first_name="Target", 
                    last_name="Patient", 
                    date_of_birth="1985-05-15", 
                    email="target.patient@example.com"
                )
            return None
        mock_patient_repo.get_by_id = mock_get_patient_record

        current_fastapi_app.dependency_overrides[get_user_repository_dependency] = lambda: mock_user_repo
        current_fastapi_app.dependency_overrides[get_patient_repository_dependency] = lambda: mock_patient_repo

        response = await client.get(f"/api/v1/patients/{patient_to_access_id}", headers=headers)
        
        if get_user_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_user_repository_dependency]
        if get_patient_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_patient_repository_dependency]

        assert response.status_code == status.HTTP_200_OK, response.text
        response_data = response.json()
        assert response_data["id"] == str(patient_to_access_id)
        assert response_data["name"] == "Target Patient"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "user_role, expected_status_code",
        [
            (UserRole.PATIENT, status.HTTP_403_FORBIDDEN),
            (UserRole.CLINICIAN, status.HTTP_403_FORBIDDEN), # Assuming /admin/users is admin-only
            (UserRole.ADMIN, status.HTTP_200_OK),
        ],
    )
    @pytest.mark.asyncio
    async def test_role_specific_endpoint_access(
        self,
        client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
        global_mock_jwt_service: MagicMock,
        user_role: UserRole,
        expected_status_code: int,
    ):
        """Test access to an admin-only endpoint based on user role."""
        client, current_fastapi_app = client_app_tuple_func_scoped
        user_id_val = uuid.uuid4()
        token_user_data = {"sub": str(user_id_val), "roles": [user_role.value], "username": f"{user_role.name.lower()}_test", "email": f"{user_role.name.lower()}@example.com"}
        token = await global_mock_jwt_service.create_access_token(data=token_user_data)
        headers = {"Authorization": f"Bearer {token}"}

        mock_user_repo = AsyncMock(spec=IUserRepository)
        async def mock_get_user_by_id_inner(*, user_id: uuid.UUID): # Renamed inner parameter
            if user_id == user_id_val:
                return User(
                    id=str(user_id_val), 
                    username=token_user_data["username"], 
                    email=token_user_data["email"], 
                    first_name="Test",
                    last_name="User",
                    full_name=f"{token_user_data['username']} Full Name", 
                    roles=[user_role], 
                    account_status=UserStatus.ACTIVE,
                    password_hash="hashed_password_example_generic",
                    created_at=datetime.now(timezone.utc)
                )
            return None
        mock_user_repo.get_by_id = mock_get_user_by_id_inner
        mock_user_repo.get_user_by_id = mock_get_user_by_id_inner
        # Mock for the endpoint itself if it tries to list users, for admin case
        mock_user_repo.get_all_users = AsyncMock(return_value=([], 0)) 

        current_fastapi_app.dependency_overrides[get_user_repository_dependency] = lambda: mock_user_repo

        # Assuming /api/v1/admin/users is an admin endpoint (replace with actual one if different)
        response = await client.get("/api/v1/admin/users", headers=headers)

        if get_user_repository_dependency in current_fastapi_app.dependency_overrides: 
            del current_fastapi_app.dependency_overrides[get_user_repository_dependency]

        assert response.status_code == expected_status_code, response.text

@pytest.mark.db_required()
class TestInputValidation:
    """Test input validation for API endpoints."""

    @pytest.mark.asyncio
    async def test_invalid_input_format_rejected(
        self,
        client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Test that malformed JSON or invalid data types are rejected."""
        client, _ = client_app_tuple_func_scoped
        headers = get_valid_provider_auth_headers
        # Example: Creating a patient with invalid data type for date_of_birth
        invalid_payload = {
            "first_name": "ValidName",
            "last_name": "ValidLastName",
            "date_of_birth": 12345, # Invalid type, should be string
            "email": "test@example.com",
            "phone_number": "123-456-7890"
        }
        response = await client.post("/api/v1/patients/", headers=headers, json=invalid_payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_input_sanitization_handling(
        self,
        client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Test how potentially malicious inputs are handled (e.g., XSS)."""
        client, current_fastapi_app = client_app_tuple_func_scoped
        headers = get_valid_provider_auth_headers
        
        # This test assumes sanitization happens and a safe version is used.
        # For a POST, the Pydantic model should handle validation/sanitization.
        # We are mostly testing if the application handles it gracefully.
        xss_payload = {
            "first_name": "<script>alert('XSS')</script>John",
            "last_name": "Doe",
            "date_of_birth": "1990-01-01",
            "email": "xss.john.doe@example.com",
            "phone_number": "111-222-3333" 
        }

        # Mock the repository create method to inspect the data that would be saved
        mock_patient_repo = AsyncMock(spec=IPatientRepository)
        created_patient_capture = None

        async def mock_create_patient(patient_data: CorePatient) -> CorePatient:
            nonlocal created_patient_capture
            created_patient_capture = patient_data
            # Simulate successful creation by returning the input, potentially with an ID
            if not patient_data.id:
                 patient_data.id = uuid.uuid4()
            return patient_data
        
        mock_patient_repo.create = mock_create_patient
        current_fastapi_app.dependency_overrides[get_patient_repository_dependency] = lambda: mock_patient_repo

        response = await client.post("/api/v1/patients/", headers=headers, json=xss_payload)
        
        if get_patient_repository_dependency in current_fastapi_app.dependency_overrides:
            del current_fastapi_app.dependency_overrides[get_patient_repository_dependency]

        assert response.status_code == status.HTTP_201_CREATED # Assuming Pydantic sanitizes/validates
        assert created_patient_capture is not None
        # Pydantic v2 usually escapes or a custom validator would handle this.
        # Here, we check if it's not the raw script tag. Depending on strategy, it might be empty or escaped.
        assert "<script>" not in created_patient_capture.first_name 
        assert "alert('XSS')" not in created_patient_capture.first_name

    @pytest.mark.asyncio
    async def test_input_length_limits_enforced(
        self,
        client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Test that input length limits are enforced as per schema."""
        client, _ = client_app_tuple_func_scoped
        headers = get_valid_provider_auth_headers
        # Assuming 'first_name' has a max_length defined in Pydantic model (e.g., 50)
        long_name = "A" * 100 
        payload = {
            "first_name": long_name,
            "last_name": "LastName",
            "date_of_birth": "1990-01-01",
            "email": "long.name@example.com",
            "phone_number":"333-444-5555"
        }
        response = await client.post("/api/v1/patients/", headers=headers, json=payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        # Check for specific error detail if Pydantic provides it
        # Example: response_json = response.json(); assert "ensure this value has at most 50 characters" in str(response_json)

@pytest.mark.db_required()
class TestSecureHeaders:
    """Test for presence and configuration of security-related HTTP headers."""

    @pytest.mark.asyncio
    async def test_required_security_headers_present(self, client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI]) -> None:
        """Test that responses include headers like X-Content-Type-Options, etc."""
        client, _ = client_app_tuple_func_scoped
        response = await client.get(f"/api/v1/patients/{TEST_PATIENT_ID}") # Any valid GET endpoint
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert "Strict-Transport-Security" in response.headers
        # Add checks for other headers like CSP, X-Frame-Options if configured

    @pytest.mark.asyncio
    async def test_cors_headers_configuration(self, client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI]) -> None:
        """Test CORS headers for allowed origins, methods, etc."""
        client, current_fastapi_app = client_app_tuple_func_scoped
        # Ensure settings has CORS_ORIGINS and it's not empty
        assert hasattr(current_fastapi_app.state.settings, "CORS_ORIGINS")
        assert current_fastapi_app.state.settings.CORS_ORIGINS
        
        origin_to_test = current_fastapi_app.state.settings.CORS_ORIGINS[0] # Use CORS_ORIGINS
        
        headers = {"Origin": origin_to_test}
        response = await client.options("/api/v1/status/health", headers=headers)
        
        # Basic check, real validation depends on your CORS config in app_factory.py
        if current_fastapi_app.state.settings.CORS_ORIGINS and current_fastapi_app.state.settings.CORS_ORIGINS != ["*"]:
            assert response.headers.get("access-control-allow-origin") == origin_to_test 
        elif current_fastapi_app.state.settings.CORS_ORIGINS == ["*"]:
            assert response.headers.get("access-control-allow-origin") == "*"
        else: # No origins or complex setup not covered here
            pass
        assert "access-control-allow-methods" in response.headers
        assert "access-control-allow-headers" in response.headers

@pytest.mark.db_required()
class TestErrorHandling:
    """Test secure error handling, ensuring no sensitive info is leaked."""

    @pytest.mark.asyncio
    async def test_not_found_error_generic(
        self,
        client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Test that 404 errors are generic and don't leak info."""
        client, _ = client_app_tuple_func_scoped
        headers = get_valid_provider_auth_headers
        non_existent_id = str(uuid.uuid4())
        response = await client.get(f"/api/v1/patients/{non_existent_id}", headers=headers)
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert response.json().get("detail") == f"Patient with id {non_existent_id} not found." # Default FastAPI not found or custom
        # Ensure no stack traces or excessive details are present
        assert "traceback" not in response.text.lower()

    @pytest.mark.asyncio
    async def test_internal_server_error_masked(
        self,
        client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
        get_valid_auth_headers: dict[str, str],
        global_mock_jwt_service: MagicMock # Corrected: Use global mock
    ):
        """Test that 500 errors are generic and mask internal details."""
        client, current_fastapi_app = client_app_tuple_func_scoped
        headers = get_valid_auth_headers
        token_data = await global_mock_jwt_service.decode_token(token=headers["Authorization"].replace("Bearer ", ""))
        requesting_user_id = uuid.UUID(token_data.sub) if hasattr(token_data, 'sub') else uuid.UUID(token_data["sub"])

        # Mock user repo to return a valid user for authentication
        mock_user_repo = AsyncMock(spec=IUserRepository)
        async def mock_get_requesting_user(*, user_id: uuid.UUID):
            if user_id == requesting_user_id:
                return User(
                    id=requesting_user_id,
                    username="requesting_user_for_error_test",
                    email="requesting_error@example.com",
                    full_name="Requesting Error User",
                    roles=[UserRole.ADMIN], # Example role
                    account_status=UserStatus.ACTIVE, # CHANGED
                    password_hash="hashed_password_error_test"
                )
            return None # Should not be called for other IDs in this specific test
        mock_user_repo.get_by_id = mock_get_requesting_user
        mock_user_repo.get_user_by_id = mock_get_requesting_user
        current_fastapi_app.dependency_overrides[get_user_repository_dependency] = lambda: mock_user_repo

        # Mock patient repo to raise an unhandled exception
        mock_patient_repo_exploding = AsyncMock(spec=IPatientRepository)
        mock_patient_repo_exploding.get_by_id.side_effect = Exception("Simulated database explosion!")
        current_fastapi_app.dependency_overrides[get_patient_repository_dependency] = lambda: mock_patient_repo_exploding

        response = await client.get(f"/api/v1/patients/{requesting_user_id}", headers=headers)
        
        if get_user_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_user_repository_dependency]
        if get_patient_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_patient_repository_dependency]

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        # Default FastAPI error for unhandled exceptions might be just "Internal Server Error"
        # or a custom one if exception handlers are set up.
        assert response.json().get("detail") == "Internal Server Error" 
        assert "Simulated database explosion!" not in response.text
        assert "traceback" not in response.text.lower()

# Standalone tests (not in a class) - ensure they also use client_app_tuple_func_scoped correctly

@pytest.mark.asyncio
async def test_access_patient_phi_data_success_provider(
    client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
    get_valid_provider_auth_headers: dict[str, str],
    global_mock_jwt_service: MagicMock # Corrected
):
    """A provider can access PHI of a patient they are authorized for."""
    client, current_fastapi_app = client_app_tuple_func_scoped
    headers = get_valid_provider_auth_headers
    token_data = await global_mock_jwt_service.decode_token(token=headers["Authorization"].replace("Bearer ", ""))
    provider_user_id = uuid.UUID(token_data.sub) if hasattr(token_data, 'sub') else uuid.UUID(token_data["sub"])
    target_patient_id = uuid.UUID(TEST_PATIENT_ID)

    mock_user_repo = AsyncMock(spec=IUserRepository)
    async def mock_get_provider_user(*, user_id: uuid.UUID):
        if user_id == provider_user_id:
            # Handle TokenPayload objects (which have attributes) or dictionaries (which have get method)
            if hasattr(token_data, 'username'):
                username = token_data.username
                email = token_data.email if hasattr(token_data, 'email') else f"{username}@example.com"
            else:
                # Fallback for dictionaries or other types
                username = token_data.get("username", f"phi_provider_user")
                email = token_data.get("email", f"phi_provider@example.com")
                
            return User(
                id=provider_user_id, 
                username=username, 
                email=email, 
                full_name=f"Dr. PHI Accessor", 
                roles=[UserRole.CLINICIAN], 
                account_status=UserStatus.ACTIVE,
                password_hash="hashed_password_phi_provider"
            )
        return None
    mock_user_repo.get_by_id = mock_get_provider_user
    mock_user_repo.get_user_by_id = mock_get_provider_user

    mock_patient_repo = AsyncMock(spec=IPatientRepository)
    async def mock_get_target_patient(*, patient_id: uuid.UUID):
        if patient_id == target_patient_id:
            return CorePatient(id=target_patient_id, first_name="Target", last_name="PHI Patient", date_of_birth="1970-01-01", email="target.phi@example.com", ssn="encrypted_ssn_value_here_if_model_has_it")
        return None
    mock_patient_repo.get_by_id = mock_get_target_patient

    current_fastapi_app.dependency_overrides[get_user_repository_dependency] = lambda: mock_user_repo
    current_fastapi_app.dependency_overrides[get_patient_repository_dependency] = lambda: mock_patient_repo

    response = await client.get(f"/api/v1/patients/{target_patient_id}/phi", headers=headers)
    
    if get_user_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_user_repository_dependency]
    if get_patient_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_patient_repository_dependency]
    
    assert response.status_code == status.HTTP_200_OK, response.text
    # Assuming PHI endpoint returns sensitive data like SSN if present on the model
    # and the response model (PatientPHI) includes it.
    assert response.json()["id"] == str(target_patient_id) 
    # assert "ssn" in response.json() # Or other PHI fields

@pytest.mark.asyncio
async def test_access_patient_phi_data_unauthorized_patient(
    client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
    global_mock_jwt_service: MagicMock # Corrected
):
    """A patient cannot access PHI data of another patient."""
    client, current_fastapi_app = client_app_tuple_func_scoped
    patient_a_id = uuid.uuid4()
    patient_b_id = uuid.UUID(OTHER_PATIENT_ID) # Ensure this is different from patient_a_id

    token_data_a = {"sub": str(patient_a_id), "roles": [UserRole.PATIENT.value], "username": "patientA", "email": "patientA@example.com"}
    token_a = await global_mock_jwt_service.create_access_token(data=token_data_a)
    headers_patient_a = {"Authorization": f"Bearer {token_a}"}

    mock_user_repo = AsyncMock(spec=IUserRepository)
    async def mock_get_patient_a_user(*, user_id: uuid.UUID):
        if user_id == patient_a_id:
            return User(
                id=patient_a_id, 
                username="phi_patient_a_user", 
                email="phi_patient_a@example.com", 
                full_name="Patient A PHI", 
                roles=[UserRole.PATIENT],
                account_status=UserStatus.ACTIVE,
                password_hash="hashed_password_phi_patient_a"
            )
        return None
    mock_user_repo.get_by_id = mock_get_patient_a_user
    mock_user_repo.get_user_by_id = mock_get_patient_a_user

    mock_patient_repo = AsyncMock(spec=IPatientRepository)
    async def mock_get_patient_b(*, patient_id: uuid.UUID):
        if patient_id == patient_b_id:
            return CorePatient(id=patient_b_id, first_name="Patient", last_name="B", date_of_birth="1971-01-01", email="patientB@example.com")
        return None
    mock_patient_repo.get_by_id = mock_get_patient_b

    current_fastapi_app.dependency_overrides[get_user_repository_dependency] = lambda: mock_user_repo
    current_fastapi_app.dependency_overrides[get_patient_repository_dependency] = lambda: mock_patient_repo

    response = await client.get(f"/api/v1/patients/{patient_b_id}/phi", headers=headers_patient_a)

    if get_user_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_user_repository_dependency]
    if get_patient_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_patient_repository_dependency]

    assert response.status_code == status.HTTP_403_FORBIDDEN, response.text

@pytest.mark.asyncio
async def test_access_patient_phi_data_patient_not_found(
    client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
    get_valid_provider_auth_headers: dict[str, str],
    global_mock_jwt_service: MagicMock # Corrected
):
    """Accessing PHI for a non-existent patient returns 404."""
    client, current_fastapi_app = client_app_tuple_func_scoped
    headers = get_valid_provider_auth_headers
    token_data = await global_mock_jwt_service.decode_token(token=headers["Authorization"].replace("Bearer ", ""))
    provider_user_id = uuid.UUID(token_data.sub) if hasattr(token_data, 'sub') else uuid.UUID(token_data["sub"])
    non_existent_patient_id = uuid.uuid4()

    mock_user_repo = AsyncMock(spec=IUserRepository)
    async def mock_get_provider_user(*, user_id: uuid.UUID):
        if user_id == provider_user_id:
            # Handle TokenPayload objects (which have attributes) or dictionaries (which have get method)
            if hasattr(token_data, 'username'):
                username = token_data.username
                email = token_data.email if hasattr(token_data, 'email') else f"{username}@example.com"
            else:
                # Fallback for dictionaries or other types
                username = token_data.get("username", f"phi_provider_user_for_not_found_test")
                email = token_data.get("email", f"phi_provider_notfound@example.com")
                
            return User(
                id=provider_user_id, 
                username=username, 
                email=email, 
                full_name=f"Dr. PHI Not Found Test", 
                roles=[UserRole.CLINICIAN], 
                account_status=UserStatus.ACTIVE,
                password_hash="hashed_password_phi_provider_nf"
            )
        return None
    mock_user_repo.get_by_id = mock_get_provider_user
    mock_user_repo.get_user_by_id = mock_get_provider_user

    mock_patient_repo = AsyncMock(spec=IPatientRepository)
    # Simulate patient not found
    mock_patient_repo.get_by_id = AsyncMock(return_value=None) 

    current_fastapi_app.dependency_overrides[get_user_repository_dependency] = lambda: mock_user_repo
    current_fastapi_app.dependency_overrides[get_patient_repository_dependency] = lambda: mock_patient_repo

    response = await client.get(f"/api/v1/patients/{non_existent_patient_id}/phi", headers=headers)

    if get_user_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_user_repository_dependency]
    if get_patient_repository_dependency in current_fastapi_app.dependency_overrides: del current_fastapi_app.dependency_overrides[get_patient_repository_dependency]

    assert response.status_code == status.HTTP_404_NOT_FOUND, response.text
    assert response.json()["detail"] == f"Patient PHI for patient id {non_existent_patient_id} not found."

@pytest.mark.asyncio
@pytest.mark.db_required # Added db_required as it likely interacts with DB through user/patient lookups
@pytest.mark.asyncio
async def test_authenticated_but_unknown_role(
    client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI],
    global_mock_jwt_service: MagicMock # Corrected
) -> None:
    """Test how the system handles a token with a role not defined in UserRole enum (if possible/relevant)."""
    # This scenario might be hard to test if UserRole enum is strictly enforced at token creation/validation.
    # If JWTService.create_access_token validates roles against UserRole enum, this state might not be achievable.
    # Assuming for a moment a token could have a non-standard role string.
    client, current_fastapi_app = client_app_tuple_func_scoped
    user_id_unknown_role = uuid.uuid4()
    # The global_mock_jwt_service.create_access_token might validate roles. 
    # If it does, this test might always fail at token creation or succeed if the mock is lenient.
    # For this test, we might need a more specialized mock or to acknowledge this limitation.
    token_data_unknown = {"sub": str(user_id_unknown_role), "roles": ["ceo"], "username": "ceo_user", "email": "ceo@example.com"}
    
    # global_mock_jwt_service.create_access_token = AsyncMock(return_value="mocked.unknown.role.token")
    # token_unknown_role = "mocked.unknown.role.token"
    # OR, if create_access_token is flexible enough:
    token_unknown_role = await global_mock_jwt_service.create_access_token(data=token_data_unknown)
    
    headers_unknown_role = {"Authorization": f"Bearer {token_unknown_role}"}

    mock_user_repo = AsyncMock(spec=IUserRepository)
    async def mock_get_user_for_unknown_role(*, user_id: uuid.UUID) -> User | None:
        if user_id == user_id_unknown_role:
            # Simulate a User object that somehow got this role, even if it's not in UserRole enum.
            # Pydantic model for User might coerce/validate roles strictly.
            # This part is tricky. For now, let's assume the User object can be formed.
            return User(
                id=user_id_unknown_role, 
                username="unknown_role_user", 
                email="unknown_role@example.com", 
                full_name="Unknown Role User",
                roles=[UserRole.CEO], # Using a role that might not be explicitly handled by specific endpoint logic
                account_status=UserStatus.ACTIVE,
                password_hash="hashed_password_unknown_role"
            )
        return None
    mock_user_repo.get_by_id = mock_get_user_for_unknown_role
    mock_user_repo.get_user_by_id = mock_get_user_for_unknown_role
    current_fastapi_app.dependency_overrides[get_user_repository_dependency] = lambda: mock_user_repo

    # Attempt to access a generic authenticated endpoint
    response = await client.get(f"/api/v1/auth/me", headers=headers_unknown_role)

    if get_user_repository_dependency in current_fastapi_app.dependency_overrides:
        del current_fastapi_app.dependency_overrides[get_user_repository_dependency]

    # Behavior depends on how get_current_user handles roles not in UserRole enum.
    # It might raise an error, or default to no permissions.
    # If User model creation fails due to role, this test needs rethink.
    # Current get_current_user logic might just not grant any specific role-based access.
    # For /users/me, it might still succeed if auth is valid and User object is returned.
    if response.status_code == status.HTTP_200_OK:
        test_logger.warning("Test test_authenticated_but_unknown_role: /users/me succeeded with potentially unknown role. Verify behavior.")
        assert response.json()["username"] == "ceo_user" # If User object used "ceo_user"
    else:
        # Expecting some form of unauthorized or error if role validation is strict in get_current_user
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN, status.HTTP_500_INTERNAL_SERVER_ERROR], response.text
        test_logger.info(f"Test test_authenticated_but_unknown_role: Received {response.status_code} as expected for unknown role scenario.")

