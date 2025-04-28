# -*- coding: utf-8 -*-
"""
Unit tests for Analytics API endpoints.

This module contains unit tests for the analytics endpoints,
ensuring that they correctly handle events, validate data,
and process in a HIPAA-compliant manner.
"""

import json
import pytest
from datetime import datetime, timedelta, timezone # Corrected import
from unittest.mock import AsyncMock, MagicMock, patch, call # Added call
from uuid import UUID, uuid4
from typing import List, Dict, Any, Optional

from fastapi import BackgroundTasks, FastAPI, status, Request, Response, Depends
from fastapi.testclient import TestClient

# Defer service import
# from app.domain.services.analytics_service import AnalyticsService
from app.infrastructure.cache.redis_cache import RedisCache # Assuming RedisCache is used
# Correctly import router and endpoint functions/models we need to test or mock
# Avoid importing the dependency provider (get_analytics_service) itself if possible
from app.domain.entities.analytics import AnalyticsEvent
from app.presentation.api.v1.endpoints.analytics_endpoints import (
    router,
    # get_analytics_service, # Don't import the dependency provider
    # AnalyticsEvent # Import the Pydantic model
)

# Import the *actual* service for type hints where necessary
from app.domain.services.analytics_service import AnalyticsService

# Assuming get_cache_service exists or is defined elsewhere for dependency override
try:
    from app.presentation.api.dependencies.services import get_cache_service
except ImportError:
    # Define a dummy function if the actual dependency isn't available
    async def get_cache_service():
        print("Warning: Using dummy get_cache_service")
        mock_cache = AsyncMock(spec=RedisCache)
        mock_cache.get = AsyncMock(return_value=None)
        mock_cache.set = AsyncMock(return_value=True)
        return mock_cache

# Define UTC if not imported elsewhere (Python 3.11+)
try:
    from app.domain.utils.datetime_utils import UTC
except ImportError:
    UTC = timezone.utc # Fallback for older Python versions


@pytest.fixture
def mock_analytics_service():
    """Create a mock AnalyticsService for testing."""
    # Import service locally if needed for spec, or use string
    mock = AsyncMock(spec=AnalyticsService)
    # Setup mock responses for various methods used by endpoints
    mock.record_event_batch = AsyncMock(return_value=["evt1", "evt2"]) # Example return
    mock.get_dashboard_data = AsyncMock(return_value={ # Example return for dashboard
        "event_count": 1500, "unique_users": 150,
        "top_events": [
             {"event_type": "page_view", "count": 800},
             {"event_type": "button_click", "count": 350},
        ],
        "hourly_breakdown": [{"hour": h, "count": h*10} for h in range(24)] # Example data
    })
    # Add mocks for other service methods if endpoints call them directly
    return mock

@pytest.fixture
def mock_cache_service():
    """Create a mock RedisCache for testing."""
    mock = AsyncMock(spec=RedisCache)
    mock.get = AsyncMock(return_value=None)  # Default to cache miss
    mock.set = AsyncMock(return_value=True)
    mock.increment = AsyncMock(return_value=1)
    mock.expire = AsyncMock(return_value=True)
    return mock

@pytest.fixture
def mock_background_tasks():
    """Create a mock background tasks object."""
    mock = MagicMock(spec=BackgroundTasks)
    mock.add_task = MagicMock()
    return mock

@pytest.fixture
def mock_user():
    """Create a mock user object for testing dependencies."""
    user = MagicMock()
    user.id = "test-user-123"
    user.email = "test@example.com"
    user.role = "provider"
    return user

@pytest.fixture
def app(mock_analytics_service, mock_cache_service, mock_user): # Removed mock_background_tasks from fixture args
    """Create a FastAPI app with the analytics router and overridden dependencies."""
    app_instance = FastAPI()

    # Override dependencies used by the router/endpoints
    # Use string path for the dependency key if get_analytics_service isn't imported
    # Or use the imported AnalyticsService type if DI container handles it.
    # For consistency with previous fix, assume string path is needed for the key.
    # BUT we need the actual service for the value lambda.
    # Let's try overriding the specific dependency provider from the *endpoints* module
    # if it's defined there (it wasn't based on previous reads). Assuming DI.
    
    # If using DI container's get_service approach:
    try:
        from app.infrastructure.di.container import get_service
        from app.domain.services.analytics_service import AnalyticsService
        app_instance.dependency_overrides[get_service(AnalyticsService)] = lambda: mock_analytics_service
    except ImportError:
        print("Warning: DI container or AnalyticsService not found for override.")
        # Fallback or raise error depending on test requirements

    if get_cache_service: # Check if import was successful
        app_instance.dependency_overrides[get_cache_service] = lambda: mock_cache_service

    # Override auth dependency (assuming get_current_user is the correct name)
    try:
        from app.presentation.api.dependencies.auth import get_current_user as auth_get_user
        app_instance.dependency_overrides[auth_get_user] = lambda: mock_user
    except ImportError:
        print("Warning: get_current_user dependency not found for override.")
        async def dummy_get_user(): return mock_user
        # app_instance.dependency_overrides[Depends(lambda: None)] = dummy_get_user # Placeholder

    # Override rate limiter if needed (example)
    try:
        from app.presentation.api.dependencies.rate_limiter import RateLimitDependency
        app_instance.dependency_overrides[RateLimitDependency] = lambda *args, **kwargs: (lambda: None)
    except ImportError:
        pass

    app_instance.include_router(router)
    return app_instance

@pytest.fixture
def client(app):
    """Create a TestClient for the app."""
    return TestClient(app)


# Removed misplaced decorator @pytest.mark.db_required()
class TestAnalyticsEndpoints:
    """Tests for analytics endpoints."""

    @pytest.mark.asyncio
    async def test_record_analytics_event(
        self,
        client: TestClient,
        mock_analytics_service: AsyncMock,
        mock_background_tasks: MagicMock, # Inject mock BG tasks
        mock_user: MagicMock # User comes from dependency override
    ):
        """Test the record_analytics_event endpoint."""
        event_data = {
            "event_type": "page_view",
            "timestamp": datetime.now(UTC).isoformat(),
            "session_id": "test-session",
            # user_id is removed as it should be populated by the endpoint
            "client_info": {"browser": "Chrome", "os": "Windows"},
            "data": {"page": "/dashboard", "referrer": "/login"}
        }

        # Patch BackgroundTasks where it's used in the endpoint function
        with patch('app.presentation.api.v1.endpoints.analytics_endpoints.BackgroundTasks', return_value=mock_background_tasks):
             # Mock PHI detection within the scope of this test if needed
             with patch('app.infrastructure.ml.phi_detection.PHIDetectionService') as mock_phi_detector:
                mock_instance = mock_phi_detector.return_value
                mock_instance.ensure_initialized = AsyncMock(return_value=None) # Make async
                mock_instance.contains_phi_async = AsyncMock(return_value=False) # Make async
                mock_instance.redact_phi_async = AsyncMock(return_value=json.dumps(event_data["data"])) # Make async

                response = client.post("/analytics/events", json=event_data)

        assert response.status_code == status.HTTP_202_ACCEPTED
        response_data = response.json()
        assert response_data["status"] == "success"
        assert "event_id" in response_data["data"] # Check if event_id is returned

        # Verify the background task was added correctly
        mock_background_tasks.add_task.assert_called_once()
        args, kwargs = mock_background_tasks.add_task.call_args
        # Check the function called and its arguments
        # Assuming the first arg is the service method, second is the event list, third is user_id
        assert args[0] == mock_analytics_service.record_event_batch
        assert isinstance(args[1], list)
        assert len(args[1]) == 1
        event_arg = args[1][0]
        assert isinstance(event_arg, AnalyticsEvent)
        assert event_arg.event_type == "page_view"
        assert event_arg.user_id == mock_user.id # Verify user ID was added
        assert event_arg.data == {"page": "/dashboard", "referrer": "/login"}
        assert args[2] == mock_user.id # Verify user_id passed separately


    @pytest.mark.asyncio
    async def test_record_analytics_batch(
        self,
        client: TestClient,
        mock_analytics_service: AsyncMock,
        mock_background_tasks: MagicMock, # Inject mock BG tasks
        mock_user: MagicMock # User comes from dependency override
    ):
        """Test the record_analytics_batch endpoint."""
        batch_data = {
            "events": [
                {
                    "event_type": "page_view",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "session_id": "test-session-batch",
                    "client_info": {"browser": "Firefox"},
                    "data": {"page": "/settings"}
                },
                {
                    "event_type": "button_click",
                    "timestamp": datetime.now(UTC).isoformat(),
                    "session_id": "test-session-batch",
                    "client_info": {"browser": "Firefox"},
                    "data": {"button_id": "save"}
                }
            ]
        }

        with patch('app.presentation.api.v1.endpoints.analytics_endpoints.BackgroundTasks', return_value=mock_background_tasks):
             # Mock PHI detection within the scope of this test if needed
             with patch('app.infrastructure.ml.phi_detection.PHIDetectionService') as mock_phi_detector:
                mock_instance = mock_phi_detector.return_value
                mock_instance.ensure_initialized = AsyncMock(return_value=None)
                mock_instance.contains_phi_async = AsyncMock(return_value=False)
                # Mock redact to return original data as string since no PHI detected
                mock_instance.redact_phi_async = AsyncMock(side_effect=lambda d: json.dumps(d))

                response = client.post("/analytics/events/batch", json=batch_data)

        assert response.status_code == status.HTTP_202_ACCEPTED
        response_data = response.json()
        assert response_data["status"] == "success"
        assert response_data["data"]["batch_size"] == 2

        # Verify background task was called with the batch
        mock_background_tasks.add_task.assert_called_once()
        args, kwargs = mock_background_tasks.add_task.call_args
        assert args[0] == mock_analytics_service.record_event_batch
        assert isinstance(args[1], list)
        assert len(args[1]) == 2
        # Verify events were enhanced with user info
        for event in args[1]:
            assert isinstance(event, AnalyticsEvent)
            assert event.user_id == mock_user.id
        assert args[2] == mock_user.id


    @pytest.mark.asyncio
    async def test_phi_detection_in_analytics_event(
        self,
        client: TestClient,
        mock_analytics_service: AsyncMock,
        mock_background_tasks: MagicMock,
        mock_user: MagicMock
    ):
        """Test PHI detection and redaction in analytics events."""
        event_data_with_phi = {
            "event_type": "form_submit",
            "timestamp": datetime.now(UTC).isoformat(),
            "session_id": "phi-session",
            "data": {
                "form_id": "patient_details",
                "fields": {
                    "name": "John Doe",  # This should be detected as PHI
                    "age": 45,
                    "ssn": "123-45-6789" # More PHI
                }
            }
        }
        original_data_str = json.dumps(event_data_with_phi["data"])
        redacted_data_str = json.dumps({
             "form_id": "patient_details",
             "fields": {"name": "[REDACTED]", "age": 45, "ssn": "[REDACTED]"}
        })

        # Mock phi detector to simulate PHI detection
        with patch('app.infrastructure.ml.phi_detection.PHIDetectionService') as mock_phi_detector:
            mock_instance = mock_phi_detector.return_value
            mock_instance.ensure_initialized = AsyncMock(return_value=None)
            mock_instance.contains_phi_async = AsyncMock(return_value=True) # Detect PHI
            mock_instance.redact_phi_async = AsyncMock(return_value=redacted_data_str) # Return redacted string

            # Act
            with patch('app.presentation.api.v1.endpoints.analytics_endpoints.BackgroundTasks', return_value=mock_background_tasks):
                response = client.post("/analytics/events", json=event_data_with_phi)

            # Assert
            assert response.status_code == status.HTTP_202_ACCEPTED

            # Verify PHI detection was called with the original data string
            mock_instance.contains_phi_async.assert_called_once_with(original_data_str)

            # Verify redaction was called because PHI was detected
            mock_instance.redact_phi_async.assert_called_once_with(event_data_with_phi["data"])

            # Check that the background task received the redacted data string
            mock_background_tasks.add_task.assert_called_once()
            args, _ = mock_background_tasks.add_task.call_args
            _, event, _ = args
            assert isinstance(event.data, str) # Data should be the redacted JSON string
