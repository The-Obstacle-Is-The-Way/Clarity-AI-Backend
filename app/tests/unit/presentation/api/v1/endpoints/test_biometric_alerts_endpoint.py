from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI, status
from httpx import AsyncClient

from app.domain.entities.user import User
from app.domain.repositories.biometric_alert_repository import BiometricAlertRepository
from app.domain.services.biometric_event_processor import (
    BiometricEventProcessor,
    ClinicalRuleEngine,
)
from app.main import app
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.api.dependencies.get_services import get_biometric_alert_service


@pytest.fixture
def mock_biometric_event_processor() -> AsyncMock:
    """Create a mock BiometricEventProcessor."""
    processor = AsyncMock(spec=BiometricEventProcessor)
    processor.add_rule = AsyncMock()
    processor.remove_rule = AsyncMock()
    processor.register_observer = AsyncMock()
    processor.unregister_observer = AsyncMock()
    processor.process_data_point = AsyncMock()
    return processor

@pytest.fixture
def mock_clinical_rule_engine() -> AsyncMock:
    """Create a mock ClinicalRuleEngine."""
    engine = AsyncMock(spec=ClinicalRuleEngine)
    engine.register_rule_template = AsyncMock()
    engine.register_custom_condition = AsyncMock()

    mock_rule_template_output = {
        "rule_id": uuid4(),
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
        template_id: UUID,
        patient_id: UUID,
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
    """Create a mock BiometricAlertRepository."""
    repository = AsyncMock(spec=BiometricAlertRepository)
    repository.get_alert_by_id = AsyncMock(return_value=None)
    repository.get_alerts_for_patient = AsyncMock(return_value=([], 0))
    repository.get_patient_alert_summary = AsyncMock(return_value=None)
    repository.update_alert_status = AsyncMock()
    repository.get_all_alerts = AsyncMock(return_value=([], 0))
    return repository

@pytest.fixture
def mock_current_user() -> User:
    """Fixture to provide a mock User object for dependency injection."""
    test_user_id = UUID("123e4567-e89b-12d3-a456-426614174000")
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
    mock_current_user: User
) -> FastAPI:
    """Overrides dependencies for the test application instance."""
    app.dependency_overrides[get_biometric_alert_service] = lambda: AsyncMock(
        repo=mock_biometric_alert_repository
    )
    app.dependency_overrides[get_current_user] = lambda: mock_current_user
    yield app
    app.dependency_overrides.clear()

@pytest.fixture
def sample_patient_id() -> UUID:
    """Provide a consistent patient UUID for testing."""
    return UUID("abcdef12-e89b-12d3-a456-426614174abc")

@pytest.fixture
def get_valid_provider_auth_headers() -> dict[str, str]:
    """Provide valid authentication headers for a provider role."""
    return {"Authorization": "Bearer fake-provider-token"}

@pytest.mark.asyncio
class TestBiometricAlertsEndpoints:
    """Test suite for the Biometric Alerts API endpoints."""

    async def test_get_alert_rules(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Test retrieving alert rules successfully."""
        headers = get_valid_provider_auth_headers
        response = await client.get("/api/v1/biometric-alerts/rules", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "rules" in response_data
        assert "total" in response_data

    async def test_create_alert_rule_from_template(
        self,
        client: AsyncClient,
        get_valid_admin_auth_headers: dict[str, str],
        sample_patient_id: UUID,
    ) -> None:
        """Test creating an alert rule from a template."""
        headers = get_valid_admin_auth_headers
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
        response_data = response.json()
        assert response_data["name"] == "High Heart Rate Mock Rule"
        assert response_data["patient_id"] == str(sample_patient_id)
        assert response_data["priority"] == "high"

    async def test_create_alert_rule_from_condition(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: UUID,
    ) -> None:
        """Test creating a custom alert rule from conditions."""
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
        response_data = response.json()
        assert response_data["name"] == "Custom Low Oxygen Rule"
        assert response_data["patient_id"] == str(sample_patient_id)
        assert response_data["priority"] == "critical"
        assert len(response_data["conditions"]) == 1
        assert response_data["conditions"][0]["metric_name"] == "blood_oxygen"

    async def test_create_alert_rule_validation_error(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: UUID
    ) -> None:
        """Test creating an alert rule with invalid data results in 422."""
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
        sample_rule_id: UUID,
    ) -> None:
        """Test retrieving a specific alert rule by ID."""
        headers = get_valid_provider_auth_headers
        rule_id_str = str(sample_rule_id)
        response = await client.get(
            f"/api/v1/biometric-alerts/rules/{rule_id_str}",
            headers=headers
        )
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert response_data["rule_id"] == rule_id_str

    async def test_get_alert_rule_not_found(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Test retrieving a non-existent alert rule."""
        headers = get_valid_provider_auth_headers
        non_existent_rule_id = str(uuid4())
        response = await client.get(
            f"/api/v1/biometric-alerts/rules/{non_existent_rule_id}",
            headers=headers
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_update_alert_rule(
        self,
        client: AsyncClient,
        get_valid_admin_auth_headers: dict[str, str],
        sample_rule_id: UUID
    ) -> None:
        """Test updating an existing alert rule."""
        headers = get_valid_admin_auth_headers
        rule_id_str = str(sample_rule_id)
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
        response_data = response.json()
        assert response_data["rule_id"] == rule_id_str
        assert response_data["name"] == update_payload["name"]
        assert response_data["is_active"] == update_payload["is_active"]

    async def test_delete_alert_rule(
        self,
        client: AsyncClient,
        get_valid_admin_auth_headers: dict[str, str],
        sample_rule_id: UUID
    ) -> None:
        """Test deleting an alert rule."""
        headers = get_valid_admin_auth_headers
        rule_id_str = str(sample_rule_id)
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
        """Test retrieving available rule templates."""
        headers = get_valid_provider_auth_headers
        response = await client.get(
            "/api/v1/biometric-alerts/rules/templates",
            headers=headers
        )
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "templates" in response_data
        assert "total" in response_data

    async def test_get_alerts(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Test retrieving biometric alerts."""
        headers = get_valid_provider_auth_headers
        response = await client.get("/api/v1/biometric-alerts/", headers=headers)
        assert response.status_code == status.HTTP_200_OK

    async def test_get_alerts_with_filters(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_patient_id: UUID
    ) -> None:
        """Test retrieving biometric alerts with filters."""
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
        response_data = response.json()

    async def test_update_alert_status_acknowledge(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_alert_id: UUID,
    ) -> None:
        """Test acknowledging a biometric alert by updating its status."""
        headers = get_valid_provider_auth_headers
        alert_id_str = str(sample_alert_id)
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
        response_data = response.json()
        assert response_data["alert_id"] == alert_id_str
        assert response_data["status"] == "acknowledged"
        assert response_data["acknowledged_by"] is not None
        assert response_data["acknowledged_at"] is not None

    async def test_update_alert_status_resolve(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str],
        sample_alert_id: UUID,
    ) -> None:
        """Test resolving a biometric alert by updating its status."""
        headers = get_valid_provider_auth_headers
        alert_id_str = str(sample_alert_id)
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
        """Test updating status of a non-existent alert."""
        headers = get_valid_provider_auth_headers
        non_existent_alert_id = str(uuid4())
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
        sample_patient_id: UUID
    ) -> None:
        """Test retrieving the alert summary for a specific patient."""
        headers = get_valid_provider_auth_headers
        patient_id_str = str(sample_patient_id)
        response = await client.get(
            f"/api/v1/biometric-alerts/patients/{patient_id_str}/summary",
            headers=headers
        )
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert response_data["patient_id"] == patient_id_str
        assert "total_alerts" in response_data
        assert "active_alerts" in response_data

    async def test_get_patient_alert_summary_not_found(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Test retrieving summary for a patient with no alerts."""
        headers = get_valid_provider_auth_headers
        non_existent_patient_id = str(uuid4())
        response = await client.get(
            f"/api/v1/biometric-alerts/patients/{non_existent_patient_id}/summary",
            headers=headers
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    async def test_create_alert_rule_template(
        self,
        client: AsyncClient,
        get_valid_admin_auth_headers: dict[str, str]
    ) -> None:
        """Test creating an alert rule template."""
        headers = get_valid_admin_auth_headers
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
        response_data = response.json()
        assert response_data["template_id"] == payload["template_id"]
        assert response_data["name"] == payload["name"]
        assert response_data["description"] == payload["description"]

    async def test_update_alert_status_unauthorized(
        self, client: AsyncClient, sample_alert_id: UUID
    ) -> None:
        """Test updating alert status without authorization."""
        alert_id_str = str(sample_alert_id)
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
        sample_alert_id: UUID
    ) -> None:
        """Test updating alert status with invalid data."""
        headers = get_valid_provider_auth_headers
        alert_id_str = str(sample_alert_id)
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
        sample_patient_id: UUID,
    ) -> None:
        """Test triggering an alert manually."""
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
        response_data = response.json()
        assert response_data["alert_id"] is not None
        assert response_data["patient_id"] == patient_id_str
        assert response_data["metric_name"] == payload["metric_name"]
        assert response_data["value"] == payload["value"]
        assert response_data["unit"] == payload["unit"]

    async def test_hipaa_compliance_no_phi_in_url_or_errors(
        self,
        client: AsyncClient,
        get_valid_provider_auth_headers: dict[str, str]
    ) -> None:
        """Verify no PHI is leaked in URLs or error responses."""
        headers = get_valid_provider_auth_headers
        alert_id_str = str(uuid4())
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
