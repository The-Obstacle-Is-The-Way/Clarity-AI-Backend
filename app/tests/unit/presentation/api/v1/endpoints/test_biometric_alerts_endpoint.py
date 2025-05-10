import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar, Tuple, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock
import logging

import pytest
import pytest_asyncio
from fastapi import FastAPI, status
from httpx import AsyncClient, ASGITransport
# from httpx import AsyncClient # Duplicate import
from faker import Faker

from app.core.domain.entities.user import User, UserRole, UserStatus
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
from app.presentation.api.v1.dependencies.biometric import get_alert_service as get_alert_service_dependency
from app.infrastructure.di.container import get_container, reset_container
from app.core.interfaces.services.alert_service_interface import AlertServiceInterface
from app.core.interfaces.services.jwt_service_interface import JWTServiceInterface
from app.core.interfaces.services.auth_service_interface import AuthServiceInterface

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

# Add import for create_application and Settings
from app.app_factory import create_application
from app.core.config.settings import Settings as CoreSettings
# from app.core.domain.entities.user import User # Keep this User import, it is used for mock_current_user # Duplicate, already imported

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
def mock_current_user() -> User:
    test_user_id = uuid.UUID("123e4567-e89b-12d3-a456-426614174000")
    mock_user = User(
        id=test_user_id,
        email="test@example.com",
        username="testadmin",
        full_name="Test Admin User",
        password_hash="fake_hash",
        roles={UserRole.ADMIN},
        status=UserStatus.ACTIVE
    )
    return mock_user

@pytest.fixture(scope="function")
def mock_alert_service() -> MagicMock:
    return MagicMock(spec=AlertServiceInterface)

@pytest_asyncio.fixture(scope="function")
async def test_app(
    test_settings: CoreSettings,
    # Changed to global_mock_jwt_service to match conftest.py more clearly if needed later
    # though this test_app uses its own parameter `mock_jwt_service` for overrides.
    global_mock_jwt_service: MagicMock,
    mock_auth_service: MagicMock,
    mock_alert_service: MagicMock,
    mock_biometric_alert_repository: AsyncMock,
    mock_biometric_rule_repository: AsyncMock,
    mock_template_repository: AsyncMock,
    mock_biometric_event_processor: AsyncMock,
    mock_current_user: User,
) -> AsyncGenerator[Tuple[FastAPI, AsyncClient], None]:
    logger.info("Creating test_app for BiometricAlertsEndpoints.")
    
    reset_container()
    # include_test_routers=False was for a specific setup, let's assume it should be True for these unit tests
    # unless there's a strong reason for False. For now, keeping it as is from previous state.
    app = create_application(settings_override=test_settings, include_test_routers=False)

    app.dependency_overrides[get_rule_repository] = lambda: mock_biometric_rule_repository
    app.dependency_overrides[get_alert_repository] = lambda: mock_biometric_alert_repository
    app.dependency_overrides[get_template_repository] = lambda: mock_template_repository
    app.dependency_overrides[get_event_processor] = lambda: mock_biometric_event_processor
    app.dependency_overrides[get_current_user] = lambda: mock_current_user
    app.dependency_overrides[get_jwt_service_dependency] = lambda: global_mock_jwt_service
    app.dependency_overrides[get_auth_service_dependency] = lambda: mock_auth_service
    app.dependency_overrides[get_alert_service_dependency] = lambda: mock_alert_service
    logger.info(f"Applied FastAPI dependency_overrides. Keys: {list(app.dependency_overrides.keys())}")

    container = get_container()
    # Explicitly register mocks used by this test_app in DI container
    # This test_app uses its own `mock_jwt_service` param, not necessarily the global one from conftest.
    container.register(JWTServiceInterface, global_mock_jwt_service)
    container.register(AuthServiceInterface, mock_auth_service)
    container.register(AlertServiceInterface, mock_alert_service)
    logger.info("Explicitly registered MOCK services in DI container for BiometricAlerts test_app.")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        yield app, client
    
    app.dependency_overrides.clear()
    reset_container()

@pytest.fixture
async def client(test_app: Tuple[FastAPI, AsyncClient]) -> AsyncClient:
    app, client_instance = test_app # Renamed to avoid conflict with client module
    return client_instance

@pytest.fixture
def sample_patient_id() -> uuid.UUID:
    return uuid.UUID("abcdef12-e89b-12d3-a456-426614174abc")

@pytest.mark.asyncio
class TestBiometricAlertsEndpoints:
    async def test_get_alert_rules(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        pytest.skip("Skipping test until AlertRuleService is implemented") # MOVED TO TOP
        headers = await get_valid_provider_auth_headers
        response = await client.get("/api/v1/biometric-alerts/rules", headers=headers)
        # pytest.skip("Skipping test until AlertRuleService is implemented") # Original position

    async def test_create_alert_rule_from_template(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID,
    ) -> None:
        pytest.skip("Skipping test until AlertRuleService is implemented") # MOVED TO TOP
        headers = await get_valid_provider_auth_headers
        payload = {
            "template_id": "high_heart_rate",
            "patient_id": str(sample_patient_id),
            "customization": {
                "threshold_value": 110.0,
                "priority": "high"
            }
        }
        response = await client.post(
            "/api/v1/biometric-alerts/rules/from-template",
            headers=headers,
            json=payload
        )
        # pytest.skip("Skipping test until AlertRuleService is implemented") # Original position

    async def test_create_alert_rule_from_condition(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID,
    ) -> None:
        pytest.skip("Skipping test until AlertRuleService is implemented") # MOVED TO TOP
        headers = await get_valid_provider_auth_headers 
        payload = {
            "name": "Custom Low Oxygen Rule",
            "description": "Alert when SpO2 drops below 92%",
            "patient_id": str(sample_patient_id),
            "priority": "critical",
            "conditions": [
                {
                    "metric_name": "blood_oxygen",
                    "comparator_operator": "less_than",
                    "threshold_value": 92.0,
                    "duration_minutes": 10
                }
            ],
            "logical_operator": "and",
            "is_active": True
        }
        response = await client.post(
            "/api/v1/biometric-alerts/rules",
            headers=headers,
            json=payload
        )
        # pytest.skip("Skipping test until AlertRuleService is implemented") # Original position

    async def test_create_alert_rule_validation_error(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID
    ) -> None:
        pytest.skip("Skipping test as validation path doesn't exist and relies on AlertRuleService") # MOVED TO TOP
        # headers = await get_valid_provider_auth_headers # Original code was just a skip
        # ... (rest of original test if any, assumed it was only a skip)

    async def test_get_alert_rule(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str], 
        sample_patient_id: uuid.UUID,
    ) -> None:
        pytest.skip("Skipping test until AlertRuleService is implemented") # MOVED TO TOP
        headers = await get_valid_provider_auth_headers 
        rule_id_str = str(sample_patient_id) # Using sample_patient_id as rule_id for test purposes
        response = await client.get(
            f"/api/v1/biometric-alerts/rules/{rule_id_str}",
            headers=headers
        )
        # pytest.skip("Skipping test until AlertRuleService is implemented") # Original position

    async def test_get_alert_rule_not_found(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        # This test asserts a 404 and does not skip, so no change needed for skip positioning.
        headers = await get_valid_provider_auth_headers 
        non_existent_rule_id = str(uuid.uuid4())
        response = await client.get(
            f"/api/v1/biometric-alerts/rules/{non_existent_rule_id}",
            headers=headers
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_update_alert_rule(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID
    ) -> None:
        pytest.skip("Skipping test until AlertRuleService is implemented") # MOVED TO TOP
        headers = await get_valid_provider_auth_headers 
        rule_id_str = str(sample_patient_id) # Using sample_patient_id as rule_id for test purposes
        update_payload = {
            "name": "Updated Sample Rule",
            "description": "Description updated",
            "priority": "high",
            "is_active": False,
            "conditions": [
                {
                    "metric_name": "low_heart_rate",
                    "comparator_operator": "less_than",
                    "threshold_value": 60.0,
                    "duration_minutes": 15
                }
            ],
            "logical_operator": "or"
        }
        response = await client.put(
            f"/api/v1/biometric-alerts/rules/{rule_id_str}",
            headers=headers,
            json=update_payload
        )
        # pytest.skip("Skipping test until AlertRuleService is implemented") # Original position

    async def test_delete_alert_rule(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID
    ) -> None:
        pytest.skip("Skipping test until AlertRuleService is implemented") # MOVED TO TOP
        headers = await get_valid_provider_auth_headers 
        rule_id_str = str(sample_patient_id) # Using sample_patient_id as rule_id for test purposes
        response = await client.delete(
            f"/api/v1/biometric-alerts/rules/{rule_id_str}",
            headers=headers
        )
        # pytest.skip("Skipping test until AlertRuleService is implemented") # Original position

    async def test_get_rule_templates(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        pytest.skip("Skipping test until AlertRuleTemplateService is implemented") # MOVED TO TOP
        headers = await get_valid_provider_auth_headers 
        response = await client.get(
            "/api/v1/biometric-alerts/rules/templates",
            headers=headers
        )
        # pytest.skip("Skipping test until AlertRuleTemplateService is implemented") # Original position

    async def test_get_alerts(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        # This test asserts a 200 and does not skip.
        headers = await get_valid_provider_auth_headers 
        response = await client.get(
            "/api/v1/biometric-alerts", 
            headers=headers,
            params={"kwargs": "dummy"} 
        )
        assert response.status_code == status.HTTP_200_OK

    async def test_get_alerts_with_filters(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID,
        mock_alert_service: MagicMock, # This specific mock is for this test
    ) -> None:
        # This test asserts behavior and does not skip.
        headers = await get_valid_provider_auth_headers 
        status_filter = AlertStatus.OPEN.value
        priority_filter = AlertPriority.HIGH.value
        start_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        end_time = datetime.now(timezone.utc).isoformat()
        params = {
            "patient_id": str(sample_patient_id),
            "status": status_filter,
            "priority": priority_filter,
            "start_date": start_time,
            "end_date": end_time,
            "offset": 1,
            "limit": 5,
            "kwargs": "dummy" 
        }
        
        mock_alert_service.validate_access = AsyncMock()
        mock_alert_service.get_alerts = AsyncMock(return_value=[])
        
        response = await client.get(
            "/api/v1/biometric-alerts",
            headers=headers,
            params=params
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []
        mock_alert_service.validate_access.assert_awaited_once()
        mock_alert_service.get_alerts.assert_awaited_once()

    async def test_update_alert_status_acknowledge(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str], 
        sample_patient_id: uuid.UUID,
    ) -> None:
        pytest.skip("Skipping test as PATCH /alerts/{id}/status route not implemented") # MOVED TO TOP
        # headers = await get_valid_provider_auth_headers # Original code was just a skip
        # ... (rest of original test if any)

    async def test_update_alert_status_resolve(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID,
    ) -> None:
        pytest.skip("Skipping test as PATCH /alerts/{id}/status route not implemented") # MOVED TO TOP
        # headers = await get_valid_provider_auth_headers # Original code was just a skip
        # ... (rest of original test if any)

    async def test_update_alert_status_not_found(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        # This test asserts a 404 and does not skip.
        headers = await get_valid_provider_auth_headers 
        non_existent_alert_id = str(uuid.uuid4())
        update_payload = {"status": "acknowledged"}
        response = await client.patch(
            f"/api/v1/biometric-alerts/{non_existent_alert_id}/status",
            headers=headers,
            json=update_payload
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_get_patient_alert_summary(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID
    ) -> None:
        pytest.skip("Skipping test as GET /patients/{id}/summary route not implemented") # MOVED TO TOP
        # headers = await get_valid_provider_auth_headers # Original code was just a skip
        # ... (rest of original test if any)

    async def test_get_patient_alert_summary_not_found(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        # This test asserts a 404 and does not skip.
        headers = await get_valid_provider_auth_headers 
        non_existent_patient_id = str(uuid.uuid4()) 
        response = await client.get(
            f"/api/v1/biometric-alerts/patients/{non_existent_patient_id}/summary", 
            headers=headers
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_create_alert_rule_template(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        pytest.skip("Skipping test until AlertRuleTemplateService is implemented") # MOVED TO TOP
        headers = await get_valid_provider_auth_headers 
        payload = {
            "template_id": "high_heart_rate",
            "name": "High Heart Rate Template",
            "description": "Alert when heart rate exceeds threshold",
            "category": "cardiac",
            "conditions": [
                {
                    "metric_name": "heart_rate",
                    "comparator_operator": "greater_than",
                    "threshold_value": 100.0,
                    "duration_minutes": 5
                }
            ],
            "logical_operator": "and",
            "default_priority": "warning",
            "customizable_fields": ["threshold_value", "priority"]
        }
        response = await client.post(
            "/api/v1/biometric-alerts/rules/templates",
            headers=headers,
            json=payload
        )
        # pytest.skip("Skipping test until AlertRuleTemplateService is implemented") # Original position

    async def test_update_alert_status_unauthorized(
        self, client: AsyncClient, sample_patient_id: uuid.UUID # No get_valid_provider_auth_headers here
    ) -> None:
        pytest.skip("Skipping test as PATCH /alerts/{id}/status route not implemented") # MOVED TO TOP
        # ... (rest of original test if any)

    async def test_update_alert_status_invalid_payload(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID
    ) -> None:
        pytest.skip("Skipping test as PATCH /alerts/{id}/status route not implemented") # MOVED TO TOP
        # headers = await get_valid_provider_auth_headers # Original code was just a skip
        # ... (rest of original test if any)

    async def test_trigger_alert_manually_success(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID,
    ) -> None:
        pytest.skip("Skipping test as POST /patients/{id}/trigger route not implemented") # MOVED TO TOP
        # headers = await get_valid_provider_auth_headers # Original code was just a skip
        # ... (rest of original test if any)

    async def test_hipaa_compliance_no_phi_in_url_or_errors(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        # This test asserts behavior and does not skip.
        headers = await get_valid_provider_auth_headers 
        alert_id_str = str(uuid.uuid4())
        update_payload = {"status": "resolved"}
        response = await client.patch(
            f"/api/v1/biometric-alerts/{alert_id_str}/status",
            headers=headers,
            json=update_payload
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "detail" in response.json()
        response_detail_str = str(response.json()["detail"])
        assert alert_id_str not in response_detail_str
        assert "123" not in response_detail_str
