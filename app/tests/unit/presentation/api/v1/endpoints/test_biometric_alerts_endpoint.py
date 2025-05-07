import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, status
from httpx import AsyncClient

from app.domain.entities.user import User
from app.domain.repositories.biometric_alert_repository import BiometricAlertRepository
from app.domain.repositories.biometric_alert_rule_repository import BiometricAlertRuleRepository
from app.domain.repositories.biometric_alert_template_repository import (
    BiometricAlertTemplateRepository,
)
from app.domain.services.biometric_event_processor import (
    BiometricEventProcessor,
    ClinicalRuleEngine,
)
from app.domain.services.clinical_rule_engine import ClinicalRuleEngine # type: ignore
from app.presentation.api.dependencies.biometric_alert import (
    get_alert_repository,
    get_event_processor,
    get_rule_repository,
    get_template_repository,
)
from app.presentation.api.dependencies.auth import get_current_user

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
from app.core.config.settings import Settings as AppSettings # Use alias to avoid conflict if any

T = TypeVar("T")

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
        role="admin",
        email="test@example.com",
        username="testadmin"
    )
    return mock_user

@pytest.fixture
def test_app(
    mock_biometric_alert_repository: AsyncMock,
    mock_biometric_rule_repository: AsyncMock,
    mock_template_repository: AsyncMock,
    mock_biometric_event_processor: AsyncMock,
    mock_current_user: User,
    test_settings: AppSettings # Add test_settings fixture
) -> FastAPI:
    # Create a new app instance for this test scope
    app_instance = create_application(settings_override=test_settings)
    
    app_instance.dependency_overrides[get_rule_repository] = lambda: mock_biometric_rule_repository
    app_instance.dependency_overrides[get_alert_repository] = lambda: mock_biometric_alert_repository
    app_instance.dependency_overrides[get_template_repository] = lambda: mock_template_repository
    app_instance.dependency_overrides[get_event_processor] = lambda: mock_biometric_event_processor
    app_instance.dependency_overrides[get_current_user] = lambda: mock_current_user

    yield app_instance # Yield the new instance

    app_instance.dependency_overrides.clear() # Clear overrides on the new instance

@pytest.fixture
async def client(test_app: FastAPI) -> AsyncClient: # Add client fixture that uses test_app
    async with AsyncClient(app=test_app, base_url="http://testserver") as async_client:
        yield async_client

@pytest.fixture
def sample_patient_id() -> uuid.UUID:
    return uuid.UUID("abcdef12-e89b-12d3-a456-426614174abc")

@pytest.fixture
def get_valid_provider_auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer fake-provider-token"}

@pytest.mark.asyncio
class TestBiometricAlertsEndpoints:
    async def test_get_alert_rules(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        headers = get_valid_provider_auth_headers
        response = await client.get("/api/v1/biometric-alerts/rules", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        assert "rules" in response.json()
        assert "total" in response.json()

    async def test_create_alert_rule_from_template(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID,
    ) -> None:
        headers = get_valid_provider_auth_headers
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
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["name"] == "High Heart Rate Mock Rule"
        assert response.json()["patient_id"] == str(sample_patient_id)
        assert response.json()["priority"] == "high"

    async def test_create_alert_rule_from_condition(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID,
    ) -> None:
        headers = get_valid_provider_auth_headers
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
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["name"] == "Custom Low Oxygen Rule"
        assert response.json()["patient_id"] == str(sample_patient_id)
        assert response.json()["priority"] == "critical"
        assert len(response.json()["conditions"]) == 1
        assert response.json()["conditions"][0]["metric_name"] == "blood_oxygen"

    async def test_create_alert_rule_validation_error(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID
    ) -> None:
        headers = get_valid_provider_auth_headers
        invalid_payload = {
            "name": "Incomplete Rule",
        }
        response = await client.post(
            "/api/v1/biometric-alerts/rules/force-validation-error",
            headers=headers,
            json=invalid_payload
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_get_alert_rule(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str], 
        sample_patient_id: uuid.UUID,
    ) -> None:
        headers = get_valid_provider_auth_headers 
        rule_id_str = str(sample_patient_id)
        response = await client.get(
            f"/api/v1/biometric-alerts/rules/{rule_id_str}",
            headers=headers
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["rule_id"] == rule_id_str

    async def test_get_alert_rule_not_found(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        headers = get_valid_provider_auth_headers
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
        headers = get_valid_provider_auth_headers
        rule_id_str = str(sample_patient_id)
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
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["rule_id"] == rule_id_str
        assert response.json()["name"] == update_payload["name"]
        assert response.json()["is_active"] == update_payload["is_active"]

    async def test_delete_alert_rule(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID
    ) -> None:
        headers = get_valid_provider_auth_headers
        rule_id_str = str(sample_patient_id)
        response = await client.delete(
            f"/api/v1/biometric-alerts/rules/{rule_id_str}",
            headers=headers
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT

    async def test_get_rule_templates(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        headers = get_valid_provider_auth_headers
        response = await client.get(
            "/api/v1/biometric-alerts/rules/templates",
            headers=headers
        )
        assert response.status_code == status.HTTP_200_OK
        assert "templates" in response.json()
        assert "total" in response.json()

    async def test_get_alerts(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        headers = get_valid_provider_auth_headers
        response = await client.get("/api/v1/biometric-alerts/", headers=headers)
        assert response.status_code == status.HTTP_200_OK

    async def test_get_alerts_with_filters(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID
    ) -> None:
        headers = get_valid_provider_auth_headers
        patient_id_str = str(sample_patient_id)
        status_filter = "triggered"
        priority_filter = "warning"
        start_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        end_time = datetime.now(timezone.utc).isoformat()
        params = {
            "patient_id": patient_id_str,
            "status": status_filter,
            "priority": priority_filter,
            "start_time": start_time,
            "end_time": end_time,
            "page": 2,
            "page_size": 5
        }
        response = await client.get(
            "/api/v1/biometric-alerts/",
            headers=headers,
            params=params
        )
        assert response.status_code == status.HTTP_200_OK

    async def test_update_alert_status_acknowledge(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str], 
        sample_patient_id: uuid.UUID,
    ) -> None:
        headers = get_valid_provider_auth_headers 
        alert_id_str = str(sample_patient_id)
        update_payload = {
            "status": "acknowledged",
            "resolution_notes": None
        }
        response = await client.patch(
            f"/api/v1/biometric-alerts/{alert_id_str}/status",
            headers=headers,
            json=update_payload
        )
        assert response.status_code == status.HTTP_200_OK

    async def test_update_alert_status_resolve(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID,
    ) -> None:
        headers = get_valid_provider_auth_headers
        alert_id_str = str(sample_patient_id)
        resolution_notes = "Patient condition stabilized after intervention."
        update_payload = {
            "status": "resolved",
            "resolution_notes": resolution_notes
        }
        response = await client.patch(
            f"/api/v1/biometric-alerts/{alert_id_str}/status",
            headers=headers,
            json=update_payload
        )
        assert response.status_code == status.HTTP_200_OK

    async def test_update_alert_status_not_found(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        headers = get_valid_provider_auth_headers
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
        headers = get_valid_provider_auth_headers
        patient_id_str = str(sample_patient_id)
        response = await client.get(
            f"/api/v1/biometric-alerts/patients/{patient_id_str}/summary",
            headers=headers
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["patient_id"] == patient_id_str
        assert "total_alerts" in response.json()
        assert "active_alerts" in response.json()

    async def test_get_patient_alert_summary_not_found(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        headers = get_valid_provider_auth_headers
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
        headers = get_valid_provider_auth_headers
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
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["template_id"] == payload["template_id"]
        assert response.json()["name"] == payload["name"]
        assert response.json()["description"] == payload["description"]

    async def test_update_alert_status_unauthorized(
        self, client: AsyncClient, sample_patient_id: uuid.UUID
    ) -> None:
        alert_id_str = str(sample_patient_id)
        update_payload = {"new_status": "acknowledged", "comment": "Test comment"}
        response = await client.patch(
            f"/api/v1/biometric-alerts/{alert_id_str}/status",
            headers={},
            json=update_payload,
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_update_alert_status_invalid_payload(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID
    ) -> None:
        headers = get_valid_provider_auth_headers
        alert_id_str = str(sample_patient_id)
        invalid_payload = {"status": "invalid_status_value"}
        response = await client.patch(
            f"/api/v1/biometric-alerts/{alert_id_str}/status",
            headers=headers,
            json=invalid_payload
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    async def test_trigger_alert_manually_success(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: uuid.UUID,
    ) -> None:
        headers = get_valid_provider_auth_headers
        patient_id_str = str(sample_patient_id)
        payload = {
            "metric_name": "heart_rate",
            "value": 120.0,
            "unit": "bpm"
        }
        response = await client.post(
            f"/api/v1/biometric-alerts/patients/{patient_id_str}/trigger",
            headers=headers,
            json=payload
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["alert_id"] is not None
        assert response.json()["patient_id"] == patient_id_str
        assert response.json()["metric_name"] == payload["metric_name"]
        assert response.json()["value"] == payload["value"]
        assert response.json()["unit"] == payload["unit"]

    async def test_hipaa_compliance_no_phi_in_url_or_errors(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        headers = get_valid_provider_auth_headers
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
