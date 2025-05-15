"""
Tests for biometric alerts endpoints.

This module contains tests for the biometric alerts API endpoints,
ensuring HIPAA compliance and correct data handling.
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncGenerator, Dict, List, Tuple, TypeVar, Union
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch
from enum import Enum

import asyncio
import pytest
import pytest_asyncio
from app.tests.utils.asyncio_helpers import run_with_timeout
import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout_asyncio
from asgi_lifespan import LifespanManager
from faker import Faker
from fastapi import FastAPI, status
from httpx import ASGITransport, AsyncClient

from app.factory import create_application
from app.core.config.settings import Settings as AppSettings
from app.domain.models.user import UserRole, User

# Define UserStatus locally for testing
class UserStatus(str, Enum):
    """User status enum for tests."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"

# Create a DomainUser class for testing
class DomainUser:
    """Domain user model for tests."""
    def __init__(self, id, email, username, full_name, hashed_password, roles, status):
        self.id = id
        self.email = email
        self.username = username
        self.full_name = full_name
        self.hashed_password = hashed_password
        self.roles = roles
        self.status = status

from app.core.domain.entities.alert import AlertPriority, AlertStatus
from app.core.interfaces.services.auth_service_interface import AuthServiceInterface
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface
from app.core.interfaces.services.alert_service_interface import AlertServiceInterface

from app.domain.repositories.biometric_alert_repository import BiometricAlertRepository
from app.domain.repositories.biometric_alert_rule_repository import BiometricAlertRuleRepository
from app.domain.repositories.biometric_alert_template_repository import (
    BiometricAlertTemplateRepository,
)
from app.domain.services.biometric_event_processor import (
    BiometricEventProcessor,
    # ClinicalRuleEngine, # Already imported below
)
from app.domain.services.clinical_rule_engine import ClinicalRuleEngine # type: ignore
from app.presentation.api.dependencies.biometric_alert import (
    get_alert_repository,
    get_event_processor,
    get_rule_repository,
    get_template_repository,
)
from app.presentation.api.dependencies.auth import get_current_user, get_jwt_service as get_jwt_service_dependency, get_auth_service as get_auth_service_dependency
from app.presentation.api.v1.dependencies.biometric import get_alert_service as get_alert_service_dependency, get_biometric_rule_repository
from app.infrastructure.di.container import get_container, reset_container

# Attempt to import infrastructure implementations for more realistic mocking specs
# Fallback to basic AsyncMock if infrastructure layer is not available
try:
    from app.infrastructure.repositories.biometric_alert_repository import (
        BiometricAlertRepository as InfraAlertRepo,
    )
    from app.infrastructure.repositories.biometric_alert_rule_repository import (
        BiometricAlertRuleRepository as InfraRuleRepo,
    )
    from app.infrastructure.repositories.biometric_alert_template_repository import (
        BiometricAlertTemplateRepository as InfraTemplateRepo,
    )
    from app.infrastructure.services.biometric_event_processor import (
        BiometricEventProcessor as InfraEventProcessor,
    )
except ImportError:
    InfraAlertRepo = AsyncMock(spec=BiometricAlertRepository)
    InfraRuleRepo = AsyncMock(spec=BiometricAlertRuleRepository)
    InfraTemplateRepo = AsyncMock(spec=BiometricAlertTemplateRepository)
    InfraEventProcessor = AsyncMock(spec=BiometricEventProcessor)

# ADDED: Import enums for filter values
from app.core.domain.entities.alert import AlertStatus, AlertPriority

T = TypeVar("T")

# ADDED logger definition
logger = logging.getLogger(__name__)

@pytest.fixture
def mock_biometric_event_processor() -> AsyncMock:
    processor = AsyncMock(spec=BiometricEventProcessor)
    processor.add_rule = AsyncMock()
    processor.remove_rule = AsyncMock()
    processor.register_observer = AsyncMock()
    processor.unregister_observer = AsyncMock()
    processor.process_data_point = AsyncMock()
    return processor

@pytest.fixture
def mock_clinical_rule_engine() -> AsyncMock:
    engine = AsyncMock(spec=ClinicalRuleEngine)
    engine.register_rule_template = AsyncMock()
    engine.register_custom_condition = AsyncMock()

    mock_rule_template_output = {
        "rule_id": uuid.uuid4(),
        "name": "High Heart Rate Mock Rule",
        "description": "Mock rule from template",
        "priority": "warning",
        "patient_id": None,
        "conditions": [
            {
                "metric_name": "heart_rate",
                "comparator_operator": "greater_than",
                "threshold_value": 100.0,
                "duration_minutes": 5
            }
        ],
        "logical_operator": "and",
        "is_active": True,
    }

    async def create_rule_side_effect(
        template_id: uuid.UUID,
        patient_id: uuid.UUID,
        customization: dict[str, Any]
    ) -> dict[str, Any]:
        output = mock_rule_template_output.copy()
        output["patient_id"] = patient_id
        output["priority"] = customization.get("priority", output["priority"])
        output["conditions"] = customization.get("conditions", output["conditions"])
        output["is_active"] = customization.get("is_active", output["is_active"])
        return output

    engine.create_rule_from_template = AsyncMock(side_effect=create_rule_side_effect)

    template_list = [
        {
            "template_id": "high_heart_rate",
            "name": "High Heart Rate Template",
            "description": "Alert when heart rate exceeds {threshold_value}",
            "category": "cardiac",
            "conditions": [
                {
                    "metric_name": "heart_rate",
                    "comparator_operator": ">",
                    "threshold_value": 100
                }
            ],
            "logical_operator": "AND",
            "default_priority": "warning",
            "customizable_fields": ["threshold_value", "priority"]
        },
    ]
    engine.get_rule_templates = AsyncMock(return_value=template_list)
    return engine

@pytest.fixture
def mock_biometric_alert_repository() -> AsyncMock:
    repository = AsyncMock(spec=BiometricAlertRepository)
    repository.get_alert_by_id = AsyncMock(return_value=None)
    repository.get_alerts_for_patient = AsyncMock(return_value=([], 0))
    repository.get_patient_alert_summary = AsyncMock(return_value=None)
    repository.update_alert_status = AsyncMock()
    repository.get_all_alerts = AsyncMock(return_value=([], 0))
    return repository

@pytest.fixture
def mock_biometric_rule_repository() -> AsyncMock:
    return AsyncMock(spec=BiometricAlertRuleRepository)

@pytest.fixture
def mock_template_repository() -> AsyncMock:
    repo = AsyncMock(spec=BiometricAlertTemplateRepository)
    repo.get_template_by_id = AsyncMock(return_value=None) 
    repo.get_all_templates = AsyncMock(return_value=[]) 
    return repo

@pytest.fixture
def mock_alert_service() -> MagicMock:
    """Provides a mock alert service for tests."""
    service = MagicMock(spec=AlertServiceInterface)
    service.get_alerts = AsyncMock(return_value=([], 0))
    service.get_alert_by_id = AsyncMock(return_value=None)
    service.update_alert_status = AsyncMock()
    service.get_patient_alert_summary = AsyncMock(return_value=None)
    service.trigger_alert_manually = AsyncMock()
    return service

@pytest.fixture
def mock_current_user() -> User:
    """Returns a mock user for current_user dependency."""
    # Use a valid UUID string instead of a UUID object
    return User(
        id="123e4567-e89b-42d3-a456-426614174000",  # Use a valid UUIDv4 string
        email="test@example.com", 
        hashed_password="fake_hash",
        roles=[UserRole.ADMIN],
        is_active=True,
        first_name="Test",
        last_name="Admin User"
    )

@pytest.fixture
def sample_patient_id() -> uuid.UUID:
    return uuid.UUID("abcdef12-e89b-12d3-a456-426614174abc")

@pytest.fixture
def test_settings() -> AppSettings:
    """Provides test settings for the API endpoints."""
    return AppSettings(
        PROJECT_NAME="Test Biometric Alerts API",
        API_V1_STR="/api/v1",
        JWT_SECRET="test_secret_key_for_biometric_alerts_tests_only",
        JWT_ALGORITHM="HS256",
        JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30,
        JWT_REFRESH_TOKEN_EXPIRE_MINUTES=60,
    )

@pytest.fixture
def global_mock_jwt_service() -> MagicMock:
    """Provides a mock JWT service for tests."""
    mock = MagicMock(spec=JWTServiceInterface)
    
    # Mock create_access_token to return a test token
    async def create_access_token_mock(*args, **kwargs):
        return "test.provider.token"
        
    # Set up the mock
    mock.create_access_token = AsyncMock(side_effect=create_access_token_mock)
    
    return mock

@pytest.fixture
def mock_auth_service() -> MagicMock:
    """Provides a mock auth service for tests."""
    return MagicMock(spec=AuthServiceInterface)

@pytest.fixture
def authenticated_provider_user() -> DomainUser:
    """Returns a provider user for authentication tests."""
    return DomainUser(
        id="123e4567-e89b-42d3-a456-426614174001",  # Use a valid UUIDv4 string
        email="provider@example.com",
        username="testprovider",
        full_name="Test Provider",
        hashed_password="fake_hash",
        roles=[UserRole.PROVIDER],
        status=UserStatus.ACTIVE
    )

@pytest.fixture
def get_valid_provider_auth_headers(global_mock_jwt_service) -> dict[str, str]:
    """Generate valid auth headers for a provider user."""
    return {"Authorization": f"Bearer test.provider.token"}

@pytest.fixture
def mock_redis_service() -> MagicMock:
    """Provides a mock Redis service for tests."""
    redis_service = MagicMock()
    redis_service.ping = AsyncMock(return_value=True)
    redis_service.close = AsyncMock(return_value=None)
    redis_service.get = AsyncMock(return_value=None)
    redis_service.set = AsyncMock(return_value=True)
    redis_service.delete = AsyncMock(return_value=True)
    redis_service.exists = AsyncMock(return_value=False)
    redis_service.incr = AsyncMock(return_value=1)
    redis_service.expire = AsyncMock(return_value=True)
    return redis_service

@pytest_asyncio.fixture(scope="function")
@pytest.mark.asyncio
async def test_app(
    test_settings: AppSettings,
    global_mock_jwt_service: MagicMock,
    mock_auth_service: MagicMock,
    mock_alert_service: MagicMock,
    mock_biometric_alert_repository: AsyncMock,
    mock_biometric_rule_repository: AsyncMock,
    mock_template_repository: AsyncMock,
    mock_biometric_event_processor: AsyncMock,
    mock_current_user: User,
    authenticated_provider_user: DomainUser,
    mock_redis_service: MagicMock,
) -> AsyncGenerator[Tuple[FastAPI, AsyncClient], None]:
    """
    Creates a test application with specific dependency overrides:
    
    1. JWT Service: Provides a mock that returns pre-configured tokens
    2. Auth Service: Handles user authentication and permissions
    3. Alert Service: Manages alert operations
    4. Alert Repository: Handles alert persistence
    5. Rule Repository: Manages alert rules
    6. Template Repository: Provides alert templates
    7. Event Processor: Processes biometric events against rules
    8. Current User: Provides the authenticated user
    9. Redis Service: Mocks the Redis connection
    
    Returns:
        A tuple containing (FastAPI app, AsyncClient)
    """
    # Create the FastAPI app with test settings
    # Skip auth middleware for test isolation
    app = create_application(
        settings_override=test_settings,
        skip_auth_middleware=True,
        skip_redis_middleware=True  # Skip the Redis rate limiting middleware
    )
    
    # Make sure app.state.skip_auth_middleware is explicitly set
    app.state.skip_auth_middleware = True
    
    # Set Redis service override before lifespan starts
    app.state.redis_service_override = mock_redis_service
    
    # Add dependency overrides
    app.dependency_overrides[get_jwt_service_dependency] = lambda: global_mock_jwt_service
    app.dependency_overrides[get_auth_service_dependency] = lambda: mock_auth_service
    app.dependency_overrides[get_alert_service_dependency] = lambda: mock_alert_service
    app.dependency_overrides[get_alert_repository] = lambda: mock_biometric_alert_repository
    app.dependency_overrides[get_rule_repository] = lambda: mock_biometric_rule_repository
    # Add dependency override for BiometricRuleRepoDep
    app.dependency_overrides[get_biometric_rule_repository] = lambda: mock_biometric_rule_repository
    app.dependency_overrides[get_template_repository] = lambda: mock_template_repository
    app.dependency_overrides[get_event_processor] = lambda: mock_biometric_event_processor
    app.dependency_overrides[get_current_user] = lambda: mock_current_user
    
    # Create test client with ASGI app
    async with AsyncClient(app=app, base_url="http://test") as client:
        # This uses the lifespan manager to properly initialize the app context
        async with LifespanManager(app):
            # Return both app and client as a tuple
            yield app, client

@pytest.fixture
async def client(test_app: Tuple[FastAPI, AsyncClient]) -> AsyncClient:
    app, client_instance = test_app # Renamed to avoid conflict with client module
    return client_instance
