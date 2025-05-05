"""
Integration tests for the Actigraphy API.

This module tests the integration between the API routes and the
PAT service implementation.
"""

from collections.abc import AsyncGenerator, Callable
from datetime import datetime, timedelta
from typing import Any, TypeVar
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import Depends, FastAPI
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

# Import proper interfaces following Clean Architecture
from app.application.security.interfaces.jwt_service import IJwtService
from app.core.interfaces.repositories.base_repository import BaseRepositoryInterface
from app.core.interfaces.repositories.user_repository import IUserRepository
from app.domain.utils.datetime_utils import UTC
from app.infrastructure.persistence.sqlalchemy.models.user import UserRole
from app.presentation.api.dependencies.database import get_db
from app.presentation.api.dependencies.repositories import get_repository
from app.presentation.api.dependencies.security import get_jwt_service
from app.presentation.api.v1.routes.actigraphy import get_pat_service as actual_get_pat_service

# Mark all tests in this module as asyncio tests
pytestmark = pytest.mark.asyncio

from app.core.services.ml.pat.mock import MockPATService


@pytest.fixture
def mock_pat_service() -> MagicMock:
    """Fixture for mock PAT service."""
    service = MockPATService()
    service.initialize({})
    return service

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

    return {
        "patient_id": "test-patient-123",
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

# Reintroduce the repository override factory function
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
    
    # Define the override provider function
    def repository_override_provider(repo_type: type[T]) -> Callable[[AsyncSession], T]:
        # When we need a user repository, return our mock
        if repo_type == IUserRepository:
            # Return a function that ignores the session and returns the mock
            async def _get_mock_repo(db: AsyncSession = Depends(get_db)) -> T:
                return mock_user_repo_instance
            return _get_mock_repo
        else:
            # Raise an error if any other repository type is unexpectedly requested in these tests
            raise NotImplementedError(
                f"Dependency override not configured for repository type: {repo_type.__name__}"
            )
    
    return repository_override_provider

# Fixtures to create app and client for integration tests
@pytest.fixture
async def test_app(mock_pat_service: MagicMock, actigraphy_data: dict[str, Any]) -> FastAPI:
    from app.main import create_application
    from app.core.config import settings
    from app.infrastructure.database.session import create_db_engine_and_session
    from app.presentation.api.dependencies.database import get_db_session
    from app.presentation.api.v1.routes.actigraphy import get_pat_service as actual_get_pat_service

    # Create application instance
    app_instance = create_application()

    # Setup database for tests
    db_engine, db_session_factory = create_db_engine_and_session(str(settings.DATABASE_URL))
    app_instance.state.db_engine = db_engine
    app_instance.state.db_session_factory = db_session_factory
    
    # Create a session dependency override
    async def get_test_db_session() -> AsyncGenerator[AsyncSession, None]:
        async with db_session_factory() as session:
            yield session
    
    # --- Mock User Repository (needed for get_jwt_service signature analysis) ---
    mock_user_repo = MagicMock(spec=IUserRepository)
    
    # --- Mock JWT Service Setup (provides the actual user for tests) --- 
    mock_jwt_service = MagicMock(spec=IJwtService)

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

    # Configure the mock's async method to return the mock user
    mock_jwt_service.get_user_from_token = AsyncMock(return_value=mock_user)
    mock_jwt_service.create_access_token = MagicMock(return_value="test_token")
    # ------------------------------

    # Override dependencies
    app_instance.dependency_overrides[get_db] = get_test_db_session
    app_instance.dependency_overrides[actual_get_pat_service] = lambda: mock_pat_service
    app_instance.dependency_overrides[get_jwt_service] = lambda: mock_jwt_service
    app_instance.dependency_overrides[get_repository] = create_repository_override(mock_user_repo)
    
    yield app_instance
    
    # Cleanup
    await db_engine.dispose()

    return app_instance

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
        response = await test_client.post(
            "/api/v1/actigraphy/analyze",
            headers=auth_headers,
            json=actigraphy_data
        )

        # Debug response details
        print(f"Response status code: {response.status_code}")
        print(f"Response headers: {response.headers}")
        print(f"Response body: {response.text}")

        assert response.status_code == 200
        data = response.json()
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
