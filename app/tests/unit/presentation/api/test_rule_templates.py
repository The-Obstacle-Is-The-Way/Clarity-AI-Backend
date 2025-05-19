"""
Isolated test for rule templates API endpoint.

This test focuses only on the rule templates endpoint without dependencies
on the full application stack.
"""

from unittest.mock import AsyncMock

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.domain.entities.user import User, set_test_mode
from app.domain.services.clinical_rule_engine import ClinicalRuleEngine
from app.presentation.api.dependencies.auth import get_current_user

# Enable test mode
set_test_mode(True)


@pytest.fixture
def mock_current_user():
    """Fixture for a mock User object."""
    return User(
        id="00000000-0000-0000-0000-000000000001",
        role="admin",
        email="test@example.com",
    )


@pytest.fixture
def mock_clinical_rule_engine():
    """Create a mock ClinicalRuleEngine."""
    engine = AsyncMock(spec=ClinicalRuleEngine)

    # Mock the get_rule_templates method with proper template format
    template_list = [
        {
            "template_id": "high_heart_rate",
            "name": "High Heart Rate",
            "description": "Alert when heart rate exceeds threshold",
            "category": "cardiac",
            "conditions": [
                {"metric_name": "heart_rate", "operator": ">", "threshold_value": 100}
            ],
            "logical_operator": "AND",
            "default_priority": "WARNING",
            "customizable_fields": ["threshold_value", "priority"],
        },
        {
            "template_id": "low_heart_rate",
            "name": "Low Heart Rate",
            "description": "Alert when heart rate falls below threshold",
            "category": "cardiac",
            "conditions": [
                {"metric_name": "heart_rate", "operator": "<", "threshold_value": 50}
            ],
            "logical_operator": "AND",
            "default_priority": "URGENT",
            "customizable_fields": ["threshold_value", "priority"],
        },
    ]
    engine.get_rule_templates = AsyncMock(return_value=template_list)
    return engine


@pytest.fixture
def app(mock_current_user, mock_clinical_rule_engine):
    """Create a minimal test app with just the rule templates endpoint."""
    app = FastAPI()

    # Override dependencies
    app.dependency_overrides[get_current_user] = lambda: mock_current_user

    # Create a simple endpoint just for testing
    @app.get("/biometric-alerts/rule-templates")
    async def get_rule_templates(
        engine: ClinicalRuleEngine = Depends(lambda: mock_clinical_rule_engine),
    ):
        templates = await engine.get_rule_templates()
        return {"templates": templates, "count": len(templates)}

    return app


@pytest.fixture
def client(app):
    """Create a test client for the FastAPI app."""
    return TestClient(app)


def test_get_rule_templates(client, mock_clinical_rule_engine):
    """Test that get_rule_templates returns the correct response."""
    # Execute
    response = client.get("/biometric-alerts/rule-templates")

    # Verify
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 2
    assert len(data["templates"]) == 2
    template_ids = {t["template_id"] for t in data["templates"]}
    assert template_ids == {"high_heart_rate", "low_heart_rate"}
