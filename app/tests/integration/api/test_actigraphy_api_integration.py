"""
Integration tests for the Actigraphy API, ensuring that the API endpoints
interact correctly with the underlying services and database.
"""

from collections.abc import AsyncGenerator, Callable
from datetime import datetime, timedelta, timezone
import json
import os
import uuid
from copy import deepcopy
from typing import Any, AsyncGenerator, Callable, Dict, Generator, List, Optional, Type, TypeVar, Union
from unittest.mock import MagicMock, AsyncMock
from zoneinfo import ZoneInfo
from sqlalchemy.ext.asyncio import AsyncSession

import fastapi
import pytest
from fastapi import Depends, FastAPI, HTTPException, status
from httpx import AsyncClient
from pytest_mock import MockerFixture

from app.core.services.ml.pat.mock import MockPATService
from app.domain.entities.user import User
from app.infrastructure.persistence.sqlalchemy.models.user import UserRole
from app.presentation.api.dependencies.auth import get_current_active_user
from app.core.interfaces.repositories.base_repository import BaseRepositoryInterface
from app.core.interfaces.repositories.user_repository_interface import IUserRepository
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface as IJwtService
from app.core.config import Settings
from app.domain.utils.datetime_utils import UTC
from app.core.errors.security_exceptions import TokenValidationError

# Infrastructure imports
from app.infrastructure.persistence.sqlalchemy.models.user import UserRole  # Used for SQLAUserRole
from app.infrastructure.security.jwt_service import get_jwt_service
from app.infrastructure.persistence.sqlalchemy.models.base import Base

# Presentation/API imports
from app.presentation.api.dependencies.auth import get_current_active_user  # Used for mocking auth flow
from app.presentation.api.dependencies.database import get_db
from app.presentation.api.dependencies.repositories import get_user_repository # ADDED IMPORT
from app.presentation.api.v1.routes.actigraphy import get_pat_service as actual_get_pat_service

# Mark all tests in this module as asyncio tests
pytestmark = pytest.mark.asyncio

from app.core.services.ml.pat.mock import MockPATService

# Import TEST_USER_ID for consistency
from app.tests.integration.utils.test_db_initializer import TEST_USER_ID


@pytest.fixture
def mock_pat_service() -> MagicMock:
    """Fixture for mock PAT service."""
    # Create a proper mock with the required methods
    mock = MagicMock(spec=MockPATService)
    
    # Create all necessary methods first
    mock.analyze_actigraphy = AsyncMock()
    mock.get_embeddings = AsyncMock()
    mock.get_analysis_by_id = AsyncMock()
    mock.get_patient_analyses = AsyncMock()
    mock.get_model_info = AsyncMock()
    mock.get_analysis_types = AsyncMock()
    mock.integrate_with_digital_twin = AsyncMock()
    mock.initialize = AsyncMock()
    
    # Implement the analyze_actigraphy method with flexible parameter handling
    async def mock_analyze_actigraphy(*args, **kwargs) -> dict[str, Any]:
        """Mock implementation of analyze_actigraphy that handles different parameter styles"""
        # Handle both calling styles (single dict or keyword arguments)
        data: dict[str, Any] = {}
        
        # If called with a dictionary as first arg after self
        if len(args) > 0 and isinstance(args[0], dict):
            data = args[0]
        # If called with keyword arguments
        elif kwargs:
            data = kwargs
        
        # Extract parameters - handle both styles of access
        patient_id = data.get("patient_id", kwargs.get("patient_id", ""))
        readings = data.get("readings", kwargs.get("readings", []))
        device_info = data.get("device_info", kwargs.get("device_info", {}))
        analysis_types = data.get("analysis_types", kwargs.get("analysis_types", []))
        
        # Generate a realistic looking analysis result
        analysis_id = kwargs.get("analysis_id", str(uuid.uuid4()))
        timestamp = datetime.now(UTC).isoformat()
        
        # Return a structure that matches the ActigraphyResponse model
        return {
            "analysis_id": analysis_id,
            "patient_id": patient_id,
            "timestamp": timestamp,
            "results": {
                "status": "completed",
                "activity_score": 85,
                "rest_quality": "good",
                "movement_intensity": "moderate"
            },
            "data_summary": {
                "total_readings": len(readings) if isinstance(readings, list) else 0,
            }
        }
    
    # Set the side_effect of the mock method to the async implementation
    mock.analyze_actigraphy.side_effect = mock_analyze_actigraphy
    
    # Implement the get_embeddings method
    async def mock_get_embeddings(*args, **kwargs) -> dict[str, Any]:
        """Mock implementation of get_embeddings with flexible parameter handling"""
        # Handle both calling styles like analyze_actigraphy
        data: dict[str, Any] = {}
        if len(args) > 0 and isinstance(args[0], dict):
            data = args[0]
        elif kwargs:
            data = kwargs
            
        patient_id = data.get("patient_id", kwargs.get("patient_id", ""))
        
        # Match the EmbeddingsResponse schema from the API routes
        return {
            "embeddings": [0.1, 0.2, 0.3, 0.4, 0.5],
            "patient_id": patient_id,
            "timestamp": datetime.now(UTC).isoformat()
        }
    
    # Set the side_effect of the mock method to the async implementation
    mock.get_embeddings.side_effect = mock_get_embeddings
    
    # Implement get_analysis_by_id method
    async def mock_get_analysis_by_id(analysis_id: str, **kwargs) -> dict[str, Any]:
        """Mock implementation for getting a specific analysis"""
        # Create a result directly rather than awaiting another coroutine
        return {
            "analysis_id": analysis_id,
            "patient_id": kwargs.get("patient_id", ""),
            "timestamp": datetime.now(UTC).isoformat(),
            "results": {
                "status": "completed",
                "activity_score": 85
            },
            "data_summary": {
                "total_readings": 180,
                "sampling_rate": 1.0
            }
        }
        
    # Set the side_effect of the mock method
    mock.get_analysis_by_id.side_effect = mock_get_analysis_by_id
    
    # Implement get_patient_analyses method
    async def mock_get_patient_analyses(patient_id: str, **kwargs) -> dict[str, Any]:
        """Mock implementation for getting a patient's analyses"""
        # Create a result matching the expected response format in test_get_patient_analyses
        analyses = [{
            "analysis_id": str(uuid.uuid4()),
            "patient_id": patient_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "results": {
                "status": "completed",
                "activity_score": 85
            },
            "data_summary": {
                "total_readings": 180,
                "sampling_rate": 1.0
            }
        } for _ in range(3)]
        
        return {
            "patient_id": patient_id,
            "analyses": analyses,
            "total": len(analyses)
        }
        
    # Set the side_effect of the mock method
    mock.get_patient_analyses.side_effect = mock_get_patient_analyses
    
    # Implement get_model_info method
    async def mock_get_model_info() -> dict[str, Any]:
        """Mock implementation for getting model info"""
        return {
            "name": "MockPATModel",
            "version": "1.0.0",
            "capabilities": ["activity_analysis", "sleep_analysis"],
            "developer": "Clarity AI Team",
            "description": "Mock model for testing"
        }
        
    # Set the side_effect of the mock method
    mock.get_model_info.side_effect = mock_get_model_info
    
    # Implement get_analysis_types method
    async def mock_get_analysis_types() -> list[str]:
        """Mock implementation for getting analysis types"""
        return [
            "sleep_quality",
            "activity_levels",
            "gait_analysis",
            "tremor_analysis",
        ]
        
    # Set the side_effect of the mock method
    mock.get_analysis_types.side_effect = mock_get_analysis_types
    
    # Implement integrate_with_digital_twin method
    async def mock_integrate_with_digital_twin(integration_data: dict[str, Any]) -> dict[str, Any]:
        """Mock implementation for integrating with digital twin"""
        return {
            "patient_id": integration_data.get("patient_id", ""),
            "profile_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "integrated_profile": {
                "sleep_pattern": {
                    "updated": integration_data.get("integration_options", {}).get("update_sleep_pattern", False),
                    "quality": "Good"
                },
                "activity_level": "Moderate",
                "symptom_tracking": {
                    "updated": integration_data.get("integration_options", {}).get("update_symptom_tracking", False)
                }
            }
        }
        
    # Set the side_effect of the mock method
    mock.integrate_with_digital_twin.side_effect = mock_integrate_with_digital_twin
    
    # Implement initialize method
    async def mock_initialize() -> None:
        """Mock implementation for initialize"""
        return None
        
    # Set the side_effect of the mock method
    mock.initialize.side_effect = mock_initialize
    
    return mock

@pytest.fixture
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
        
        # For successful responses, verify the response content matches expectations
        if response.status_code == 200:
            data = response.json()
            
            # Verify required fields are present
            assert "analysis_id" in data, "Response missing analysis_id field"
            assert "patient_id" in data, "Response missing patient_id field"
            assert "timestamp" in data, "Response missing timestamp field"
            assert "results" in data, "Response missing results field"
            assert "data_summary" in data, "Response missing data_summary field"
            
            # Verify patient_id matches the request
            assert data["patient_id"] == actigraphy_data["patient_id"], "Patient ID mismatch in response"

            # Also verify the readings count if present in data_summary
            if "readings_count" in data["data_summary"]:
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

        # The API response should match the EmbeddingsResponse model with a 200 status code
        response = await test_client.post(
            "/api/v1/actigraphy/embeddings",
            headers=auth_headers,
            json=embedding_data
        )
        
        assert response.status_code == 200  # API defines status_code=200 not 201
        data = response.json()
        assert "embeddings" in data
        assert isinstance(data["embeddings"], list)
        assert "patient_id" in data
        assert data["patient_id"] == actigraphy_data["patient_id"]
        assert "timestamp" in data

    async def test_analyze_again(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        mock_pat_service: MagicMock,
        actigraphy_data: dict[str, Any]
    ) -> None:
        """Test analyzing actigraphy data a second time."""
        # We test the analyze endpoint again with different expectations
        response = await test_client.post(
            "/api/v1/actigraphy/analyze",
            headers=auth_headers,
            json=actigraphy_data
        )

        assert response.status_code == 200
        data = response.json()
        
        # Verify the analysis data structure is correct
        assert set(["analysis_id", "patient_id", "timestamp", "results", "data_summary"]) <= set(data.keys())
        assert data["patient_id"] == actigraphy_data["patient_id"]
        assert "status" in data["results"]
        
        # Verify the data_summary exists and contains fields
        # The mock implementation might use different field names
        assert isinstance(data["data_summary"], dict)
        assert len(data["data_summary"]) > 0

    async def test_embeddings_endpoint(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        mock_pat_service: MagicMock,
        actigraphy_data: dict[str, Any]
    ) -> None:
        """Test the embeddings endpoint for generating embeddings from actigraphy data."""
        response = await test_client.post(
            "/api/v1/actigraphy/embeddings",
            headers=auth_headers,
            json=actigraphy_data
        )

        assert response.status_code == 200
        data = response.json()

        # Verify the embeddings response structure is correct
        assert set(["embeddings", "patient_id", "timestamp"]) <= set(data.keys())
        assert isinstance(data["embeddings"], list)
        assert data["patient_id"] == actigraphy_data["patient_id"]
        assert "timestamp" in data

    async def test_placeholder_endpoint(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        mock_pat_service: MagicMock
    ) -> None:
        """Test the placeholder endpoint which is documented in the API."""
        response = await test_client.get(
            "/api/v1/actigraphy/placeholder",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert data["message"] == "Placeholder endpoint for actigraphy data"

    async def test_analyze_with_different_data(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        mock_pat_service: MagicMock
    ) -> None:
        """Test analyzing actigraphy data with a different data structure."""
        # Create a different actigraphy dataset
        different_data = {
            "patient_id": "test-patient-456",
            "readings": [
                {
                    "x": 0.5,
                    "y": 0.7,
                    "z": 0.9,
                    "timestamp": "2025-05-28T15:00:00Z"
                },
                {
                    "x": 0.4,
                    "y": 0.6,
                    "z": 0.8,
                    "timestamp": "2025-05-28T15:00:01Z"
                }
            ],
            "device_info": {
                "device_type": "Advanced Wearable",
                "model": "Pro 5000"
            },
            "sampling_rate_hz": 1.0
        }
        
        response = await test_client.post(
            "/api/v1/actigraphy/analyze",
            headers=auth_headers,
            json=different_data
        )

        assert response.status_code == 200
        data = response.json()
        
        # Verify the analysis data structure is correct
        assert "analysis_id" in data
        assert data["patient_id"] == different_data["patient_id"]
        assert "results" in data
        assert "data_summary" in data
        assert "timestamp" in data

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

    async def test_reanalyze_actigraphy(
        self,
        test_client: AsyncClient,
        auth_headers: dict[str, str],
        mock_pat_service: MagicMock,
        actigraphy_data: dict[str, Any]
    ) -> None:
        """Test re-analyzing actigraphy data with different analysis types."""
        # Modify the actigraphy data to specify different analysis types
        modified_data = actigraphy_data.copy()
        modified_data["analysis_types"] = ["sleep_quality", "activity_levels"]
        
        response = await test_client.post(
            "/api/v1/actigraphy/analyze",
            headers=auth_headers,
            json=modified_data
        )

        assert response.status_code == 200
        data = response.json()
        
        # Verify the results structure contains all necessary fields
        assert "analysis_id" in data
        assert "patient_id" in data 
        assert "timestamp" in data
        assert "results" in data
        assert "data_summary" in data
