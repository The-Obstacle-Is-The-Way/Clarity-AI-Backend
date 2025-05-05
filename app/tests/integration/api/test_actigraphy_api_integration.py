"""
Integration tests for the Actigraphy API.

This module tests the integration between the API routes and the
PAT service implementation.
"""

from collections.abc import AsyncGenerator, Callable
from datetime import datetime, timedelta
import uuid
from typing import Any, TypeVar
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import Depends, FastAPI
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# Import proper interfaces following Clean Architecture
# Core imports
from app.core.interfaces.repositories.base_repository import BaseRepositoryInterface
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface as IJwtService
from app.domain.entities.user import User
from app.domain.utils.datetime_utils import UTC

# Infrastructure imports
from app.infrastructure.persistence.sqlalchemy.models.user import UserRole  # Used for SQLAUserRole
from app.infrastructure.security.jwt_service import get_jwt_service

# Presentation/API imports
from app.presentation.api.dependencies.auth import get_current_active_user  # Used for mocking auth flow
from app.presentation.api.dependencies.database import get_db
from app.presentation.api.v1.routes.actigraphy import get_pat_service as actual_get_pat_service

# Mark all tests in this module as asyncio tests
pytestmark = pytest.mark.asyncio

from app.core.services.ml.pat.mock import MockPATService


@pytest.fixture
def mock_pat_service() -> MagicMock:
    """Fixture for mock PAT service."""
    # Create a proper mock with the required methods
    mock = MagicMock(spec=MockPATService)
    
    # Implement the analyze_actigraphy method to return a valid response
    async def mock_analyze_actigraphy(
        patient_id: str,
        readings: list[dict[str, Any]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        device_info: dict[str, Any],
        analysis_types: list[str],
        **kwargs: Any
    ) -> dict[str, Any]:
        """Mock implementation of analyze_actigraphy"""
        # Generate a realistic looking analysis result
        analysis_id = str(uuid.uuid4())
        timestamp = datetime.now(UTC).isoformat()
        
        # Return a structure that matches what the real service would return
        return {
            "analysis_id": analysis_id,
            "patient_id": patient_id,
            "timestamp": timestamp,
            "status": "completed",
            "device_info": device_info,
            "summary": {
                "activity_score": 85,
                "rest_quality": "good",
                "movement_intensity": "moderate"
            },
            "metrics": {
                "total_steps": 8500,
                "active_minutes": 120,
                "calories_burned": 450
            },
            "analysis_types": analysis_types
        }
    
    # Set up the mock method
    mock.analyze_actigraphy = mock_analyze_actigraphy
    mock.initialize = MagicMock(return_value=None)
    
    # Ensure the mock is properly initialized
    mock.initialize({})
    
    return mock

def auth_headers() -> dict[str, str]:
    """Authentication headers for API requests."""
    # Use the mock token recognized by the mocked JWT service in async_client
    return {
        "Authorization": "Bearer VALID_PATIENT_TOKEN", # Use the correct mock token string
        "Content-Type": "application/json"
    }


@pytest.fixture
def actigraphy_data() -> dict[str, Any]:
    """Sample actigraphy data for testing."""
    # Generate 1 hour of data at 50Hz
    start_time = datetime.now(UTC).replace(microsecond=0)
    readings = []

    for i in range(180):  # 3 minutes of data (simplified for testing)
        timestamp = start_time + timedelta(seconds=i)
        readings.append({
            "x": 0.1 + (i % 10) * 0.01,
            "y": 0.2 + (i % 5) * 0.01,
            "z": 0.3 + (i % 7) * 0.01,
            "timestamp": timestamp.isoformat() + "Z"
        })

    end_time = (start_time + timedelta(seconds=179)).isoformat() + "Z"
    start_time = start_time.isoformat() + "Z"

    # Use a valid UUID format for patient_id to satisfy SQLAlchemy's UUID type validation
    test_patient_uuid = "123e4567-e89b-12d3-a456-426614174000"
    
    return {
        "patient_id": test_patient_uuid,
        "readings": readings,
        "start_time": start_time,
        "end_time": end_time,
        "sampling_rate_hz": 1.0,
        # DeviceInfo fields must match schema: device_type and model are required; others optional
        "device_info": {
            "device_type": "ActiGraph GT9X",
            "model": "GT9X",
            "manufacturer": None,
            "firmware_version": "1.7.0",
            "position": None,
            "metadata": None
        },
        # Use correct analysis type values
        "analysis_types": ["activity_levels", "sleep_quality"]
    }

# Define the repository override factory function
def create_repository_override(mock_user_repo_instance: MagicMock) -> Callable:
    """Create a repository override function for the dependency injection system.
    
    This follows clean architecture by mocking the repositories at the boundary,
    allowing for proper unit testing of the API routes.
    
    Args:
        mock_user_repo_instance: A mocked user repository instance
        
    Returns:
        A function that provides the appropriate repository based on the type requested
    """
    T = TypeVar('T', bound=BaseRepositoryInterface)
    
    # Define the direct repository instance provider
    # This provides the mock regardless of session or repository type
    async def _get_mock_repo(db: AsyncSession) -> T:
        return mock_user_repo_instance
    
    return _get_mock_repo

# Fixtures to create app and client for integration tests
@pytest.fixture
async def test_app(mock_pat_service: MagicMock, actigraphy_data: dict[str, Any]) -> FastAPI:
    from app.main import create_application
    from app.core.config import settings
    from app.infrastructure.database.session import create_db_engine_and_session
    
    # Create application instance
    app_instance = create_application()

    # Setup database for tests with the correct async driver
    # Override the DATABASE_URL to use sqlite+aiosqlite (required for async operations)
    test_db_url = "sqlite+aiosqlite:///./test_db.sqlite3"
    db_engine, db_session_factory = create_db_engine_and_session(test_db_url)
    app_instance.state.db_engine = db_engine
    app_instance.state.db_session_factory = db_session_factory
    
    # Create a session dependency override
    async def get_test_db_session() -> AsyncGenerator[AsyncSession, None]:
        async with db_session_factory() as session:
            yield session
    
    # --- Mock JWT Service Setup (provides the actual user for tests) --- 
    mock_jwt_service = MagicMock(spec=IJwtService)
    
    # --- Create a proper adapter mock repository that implements both interfaces ---
    # This class addresses the architectural inconsistency between get_by_id and get_user_by_id
    class MockUserRepository(IUserRepository):
        """Mock user repository that implements both interface variants.
        
        This adapter addresses the architectural inconsistency where:
        - Core layer interface uses get_by_id
        - Auth dependencies call get_user_by_id
        """
        
        def __init__(self, mock_user):
            self.mock_user = mock_user
            
        async def get_by_id(self, user_id: str) -> User:
            """Core interface method - get user by ID"""
            return self.mock_user
            
        async def get_user_by_id(self, user_id: str) -> User:
            """Auth dependency method - get user by ID with different method name"""
            return self.mock_user
            
        async def get_by_email(self, email: str) -> User:
            """Get user by email"""
            return self.mock_user
            
        async def get_by_username(self, username: str) -> User:
            """Get user by username"""
            return self.mock_user
            
        async def create(self, user: User) -> User:
            """Create a new user"""
            return self.mock_user
            
        async def update(self, user: User) -> User:
            """Update an existing user"""
            return self.mock_user
            
        async def delete(self, user_id: str) -> bool:
            """Delete a user"""
            return True
            
        async def list_all(self, skip: int = 0, limit: int = 100) -> list[User]:
            """List all users with pagination"""
            return [self.mock_user]
            
        async def count(self) -> int:
            """Count all users"""
            return 1
    
    # Create a mock user object matching the expected structure using the SQLAlchemy User model
    from app.infrastructure.persistence.sqlalchemy.models.user import User as SQLAUser, UserRole as SQLAUserRole
    
    mock_user = SQLAUser(
        id=actigraphy_data["patient_id"],
        username=f"user_{actigraphy_data['patient_id']}",
        email=f"{actigraphy_data['patient_id']}@test.com",
        password_hash="hashed_password",  # Mocked, not used by JWT decode
        is_active=True,
        is_verified=True,
        email_verified=True,
        role=SQLAUserRole.PATIENT,
        roles=[SQLAUserRole.PATIENT.value]
    )

    # Configure the mock's methods to provide necessary functionality
    mock_jwt_service.get_user_from_token = AsyncMock(return_value=mock_user)
    mock_jwt_service.create_access_token = MagicMock(return_value="test_token")
    # Add missing decode_access_token method required by authentication flow
    mock_jwt_service.decode_access_token = MagicMock(return_value={
        "sub": actigraphy_data["patient_id"],
        "exp": (datetime.now(UTC) + timedelta(minutes=30)).timestamp(),
        "role": "patient"
    })
    
    # Create our repository adapter with the mock user
    mock_user_repo = MockUserRepository(mock_user)
    # ------------------------------

    # Override dependencies including get_repository_instance to avoid database access completely
    app_instance.dependency_overrides[get_db] = get_test_db_session
    app_instance.dependency_overrides[actual_get_pat_service] = lambda: mock_pat_service
    app_instance.dependency_overrides[get_jwt_service] = lambda: mock_jwt_service
    
    # This is the most critical part - override get_user_repository_dependency to return our mock
    # This prevents any actual database access attempts
    from app.presentation.api.dependencies.auth import get_user_repository_dependency
    app_instance.dependency_overrides[get_user_repository_dependency] = lambda: mock_user_repo
    
    # Reset and reconfigure the DI container to ensure clean test isolation
    from app.infrastructure.di.container import reset_container, get_container, DIContainer
    
    # Reset the container to start fresh
    reset_container()
    
    # Get a test container with mock=True flag
    container = get_container(use_mock=True)
    
    # Register our mock repository factory directly in the DI container
    # This is more reliable than overriding the get_repository_instance function
    def mock_user_repo_factory(session: AsyncSession) -> IUserRepository:
        """Factory function that always returns our mock user repository."""
        return mock_user_repo
    
    # Register the factory for both possible interface types to handle architectural inconsistencies
    container.register_repository_factory(IUserRepository, mock_user_repo_factory)
    
    # For interfaces defined in the domain layer (architectural inconsistency)
    from app.domain.repositories.user_repository import UserRepository as DomainUserRepository
    container.register_repository_factory(DomainUserRepository, mock_user_repo_factory)
    
    # For good measure, also override the dependency at the FastAPI level
    from app.infrastructure.di.provider import get_repository_instance
    
    # Override the repository provider function
    app_instance.dependency_overrides[get_repository_instance] = lambda repo_type, session: mock_user_repo if repo_type == IUserRepository else None
    
    yield app_instance
    
    # Cleanup
    await db_engine.dispose()

@pytest.mark.asyncio
@pytest.mark.db_required()
class TestActigraphyAPI:
    """Integration tests for the Actigraphy API."""

    async def test_analyze_actigraphy(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        actigraphy_data: dict[str, Any]
    ) -> None:
        """Test analyzing actigraphy data."""
        import logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)

        response = await test_client.post(
            "/api/v1/actigraphy/analyze",
            headers=auth_headers,
            json=actigraphy_data
        )

        # Direct print for immediate debugging visibility
        print(f"\n\nDEBUG - Response status code: {response.status_code}")
        print(f"DEBUG - Response headers: {response.headers}")
        print(f"DEBUG - Response body: {response.text}")
        
        # Modify assertion to include the response body for better debugging
        error_msg = f"\nExpected status code: 200, Actual status code: {response.status_code}\nResponse body: {response.text}"
        assert response.status_code == 200, error_msg
        
        # Debug the PAT service mock configuration and ensure it's properly set up
        try:
            print(f"\n\nDEBUG - PAT service analyze_actigraphy method: {mock_pat_service.analyze_actigraphy}")
            
            # Temporarily create a minimal response data for testing
            data = {}
            if response.status_code == 200:
                data = response.json()
            else:
                print(f"Cannot parse JSON from response with status {response.status_code}")
                data = {
                    "analysis_id": "test-analysis-id",
                    "patient_id": actigraphy_data["patient_id"],
                    "status": "completed",
                    "timestamp": datetime.now(UTC).isoformat()
                }
                print(f"Using mock data for testing: {data}")
        except Exception as e:
            print(f"Exception during debug: {e}")
            raise
        assert "analysis_id" in data
        assert "patient_id" in data
        assert data["patient_id"] == actigraphy_data["patient_id"]
        assert "timestamp" in data
        assert "results" in data
        assert "data_summary" in data
        assert data["data_summary"]["readings_count"] == len(actigraphy_data["readings"])

    async def test_get_actigraphy_embeddings(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        actigraphy_data: dict[str, Any]
    ) -> None:
        """Test generating embeddings from actigraphy data."""
        embedding_data = {
            "patient_id": actigraphy_data["patient_id"],
            "readings": actigraphy_data["readings"],
            "start_time": actigraphy_data["start_time"],
            "end_time": actigraphy_data["end_time"],
            "sampling_rate_hz": actigraphy_data["sampling_rate_hz"]
        }

        response = await test_client.post(
            "/api/v1/actigraphy/embeddings",
            headers=auth_headers,
            json=embedding_data
        )

        assert response.status_code == 201
        data = response.json()
        assert "embedding_id" in data
        assert "patient_id" in data
        assert data["patient_id"] == actigraphy_data["patient_id"]
        assert "timestamp" in data
        assert "embedding" in data
        assert "vector" in data["embedding"]
        assert "dimension" in data["embedding"]

    async def test_get_analysis_by_id(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        mock_pat_service: MagicMock
    ) -> None:
        """Test retrieving an analysis by ID."""
        analysis_data = mock_pat_service.analyze_actigraphy(
            patient_id="test-patient-123",
            readings=[{
                "x": 0.1, 
                "y": 0.2, 
                "z": 0.3,
                "timestamp": "2025-03-28T12:00:00Z"
            }],
            start_time="2025-03-28T12:00:00Z",
            end_time="2025-03-28T12:01:00Z",
            sampling_rate_hz=1.0,
            device_info={"name": "Test Device"},
            analysis_types=["activity_levels"]
        )

        analysis_id = analysis_data["analysis_id"]

        response = await test_client.get(
            f"/api/v1/actigraphy/analyses/{analysis_id}",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "analysis_id" in data
        assert data["analysis_id"] == analysis_id
        assert "patient_id" in data
        assert "timestamp" in data

    async def test_get_patient_analyses(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        mock_pat_service: MagicMock
    ) -> None:
        """Test retrieving analyses for a patient."""
        patient_id = "test-patient-123"

        for i in range(3):
            mock_pat_service.analyze_actigraphy(
                patient_id=patient_id,
                readings=[{
                    "x": 0.1, 
                    "y": 0.2, 
                    "z": 0.3,
                    "timestamp": f"2025-03-28T12:0{i}:00Z"
                }],
                start_time=f"2025-03-28T12:0{i}:00Z",
                end_time=f"2025-03-28T12:0{i + 1}:00Z",
                sampling_rate_hz=1.0,
                device_info={"name": "Test Device"},
                analysis_types=["activity_levels"]
            )

        response = await test_client.get(
            f"/api/v1/actigraphy/patient/{patient_id}/analyses",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()

        assert {
            "patient_id",
            "analyses",
            "total",
        } <= data.keys()

        assert data["patient_id"] == patient_id
        assert isinstance(data["analyses"], list)
        assert data["total"] == len(data["analyses"])

        for analysis in data["analyses"]:
            assert "analysis_id" in analysis
            assert analysis["patient_id"] == patient_id

    async def test_get_model_info(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        mock_pat_service: MagicMock
    ) -> None:
        """Test getting model information."""
        response = await test_client.get(
            "/api/v1/actigraphy/model-info",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        expected_keys = {"name", "version", "capabilities", "developer"}
        assert expected_keys <= data.keys()

    async def test_integrate_with_digital_twin(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        mock_pat_service: MagicMock,
        actigraphy_data: dict[str, Any]
    ) -> None:
        """Test integrating analysis with digital twin."""
        analysis_data = mock_pat_service.analyze_actigraphy(
            patient_id="test-patient-123",
            readings=[{
                "x": 0.1, 
                "y": 0.2, 
                "z": 0.3,
                "timestamp": "2025-03-28T12:00:00Z"
            }],
            start_time="2025-03-28T12:00:00Z",
            end_time="2025-03-28T12:01:00Z",
            sampling_rate_hz=1.0,
            device_info={"name": "Test Device"},
            analysis_types=["activity_levels"]
        )

        analysis_id = analysis_data["analysis_id"]

        payload = {
            "analysis_id": analysis_id,
            "patient_id": "test-patient-123",
            "integration_options": {
                "update_symptom_tracking": True,
                "update_sleep_pattern": True,
                "include_raw_data": False
            }
        }

        response = await test_client.post(
            "/api/v1/actigraphy/integrate-with-digital-twin",
            headers=auth_headers,
            json=payload
        )

        assert response.status_code == 200
        data = response.json()

        expected_keys = {"patient_id", "profile_id", "timestamp", "integrated_profile"}
        assert expected_keys <= data.keys()

    async def test_unauthorized_access(
        self,
        test_client: AsyncClient,
        actigraphy_data: dict[str, Any]
    ) -> None:
        """Test unauthorized access to API."""
        response = await test_client.post(
            "/api/v1/actigraphy/analyze",
            json=actigraphy_data
        )
        assert response.status_code == 401
        assert "detail" in response.json()

    async def test_get_analysis_types(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        mock_pat_service: MagicMock
    ) -> None:
        """Test retrieving analysis types via the API."""

        expected = [
            "sleep_quality",
            "activity_levels",
            "gait_analysis",
            "tremor_analysis",
        ]

        mock_pat_service.get_analysis_types = lambda: expected

        response = await test_client.get(
            "/api/v1/actigraphy/analysis_types",
            headers=auth_headers,
        )

        assert response.status_code == 200
        assert response.json() == expected
