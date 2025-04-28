# -*- coding: utf-8 -*-
"""
Unit tests for Biometric Alerts API endpoints.

These tests verify that the Biometric Alerts API endpoints correctly handle
requests and responses, maintain HIPAA compliance, and integrate properly
with the biometric event processor.
"""

import json
from datetime import datetime, timedelta, timezone
from app.domain.utils.datetime_utils import UTC
from typing import Dict, List, Any, Optional, Union  
from unittest.mock import AsyncMock, MagicMock, patch
import uuid # Import the uuid module
from uuid import UUID, uuid4

from enum import Enum  

import pytest
from fastapi import FastAPI, Depends, status  
from fastapi.testclient import TestClient
from pydantic import parse_obj_as

from app.domain.exceptions import (
    ValidationError,
    EntityNotFoundError,
    RepositoryError,
)  
# Import from the correct module path
from app.domain.entities.biometric_alert import BiometricAlert, AlertStatusEnum as DomainAlertStatusEnum # <-- Corrected Source
from app.domain.services.biometric_event_processor import ( 
     AlertStatus as EventProcessorAlertStatus,
     BiometricEventProcessor,
     AlertObserver,
     EmailAlertObserver,
     SMSAlertObserver,
     InAppAlertObserver,
     ClinicalRuleEngine,  
) 
# Import AlertPriority from the correct location
from app.domain.entities.biometric_rule import AlertPriority

from app.domain.entities.biometric_twin import BiometricDataPoint
from app.domain.entities.biometric_alert import BiometricAlert, AlertStatusEnum as AlertStatus # Import from domain
from app.domain.entities.biometric_alert import AlertStatusEnum
from app.domain.repositories.biometric_alert_repository import BiometricAlertRepository
from app.domain.repositories.biometric_rule_repository import BiometricRuleRepository
from app.presentation.api.v1.endpoints.biometric_alerts import (
    router as alerts_router,
    get_alert_repository
) 

# Mock the rule endpoints instead of importing them directly
from fastapi import APIRouter

# Create a mock rules router
rules_router = APIRouter()

# Mock rule templates endpoint to avoid database dependencies
@rules_router.get("/rule-templates")
async def mock_get_rule_templates():
    """Mock implementation of the rule templates endpoint."""
    return {
        "templates": [
            {
                "template_id": "high_heart_rate",
                "name": "High Heart Rate",
                "description": "Alert when heart rate exceeds threshold",
                "category": "cardiac",
                "conditions": [],
                "customizable_fields": []
            },
            {
                "template_id": "low_heart_rate",
                "name": "Low Heart Rate",
                "description": "Alert when heart rate falls below threshold",
                "category": "cardiac",
                "conditions": [],
                "customizable_fields": []
            }
        ],
        "count": 2
    }

# Mock rule repository dependency
def get_rule_repository():
    """Mock rule repository dependency."""
    return AsyncMock()

# Mock rule engine dependency
def get_rule_engine():
    """Mock rule engine dependency."""
    return AsyncMock()

# Import the actual schema classes from our implementation
from app.presentation.api.schemas.biometric_alert import (
    AlertRuleCreateSchema,
    AlertRuleResponseSchema,
    AlertRuleUpdateSchema, 
    AlertRuleListResponseSchema,
    BiometricAlertResponseSchema,
    AlertListResponseSchema,
    AlertRuleTemplateResponseSchema,
    AlertStatusUpdateSchema,
    AlertPriorityEnum,  
    ComparatorOperatorEnum,
    LogicalOperatorEnum
    # AlertStatusEnum
)


# Corrected imports based on likely structure - adjust if actual paths differ
# Remove incorrect AlertStatus import from enums
# from app.domain.enums import AlertStatus
from app.presentation.api.dependencies.auth import get_current_user 
 
# ... existing imports ...

# Import the User domain entity
from app.domain.entities.user import User 
from app.domain.entities.user import set_test_mode # Import set_test_mode
from app.domain.entities.patient import Patient
from app.domain.entities.biometric_alert import BiometricAlert
from app.domain.entities.biometric_alert import AlertStatusEnum
# Removed faulty import
# from app.domain.repositories import BaseRepository 

@pytest.fixture
def mock_biometric_event_processor():
    """Create a mock BiometricEventProcessor."""
    processor = AsyncMock(spec=BiometricEventProcessor)
    processor.add_rule = MagicMock()
    processor.remove_rule = MagicMock()
    processor.register_observer = MagicMock()
    processor.unregister_observer = MagicMock()
    processor.process_data_point = MagicMock()
    return processor 

@pytest.fixture
def mock_clinical_rule_engine():
    """Create a mock ClinicalRuleEngine."""
    engine = AsyncMock(spec=ClinicalRuleEngine)
    engine.register_rule_template = MagicMock()
    engine.register_custom_condition = MagicMock()
    
    # Critical: For test_create_alert_rule_from_template, return the input rule by default
    engine.create_rule_from_template = AsyncMock(side_effect=lambda template_id, patient_id, customization: {
        "rule_id": "test-rule-1",
        "name": "High Heart Rate",
        "description": "Alert when heart rate exceeds 100 bpm",
        "priority": AlertPriority.WARNING, 
        "patient_id": patient_id,
        "conditions": [
            {"metric_name": "heart_rate", "operator": ">", "threshold_value": 100}
        ],
        "is_active": True
    })
    
    # Mock the get_rule_templates method with proper template format - NOT async in the test
    template_list = [
        {
            "template_id": "high_heart_rate",
            "name": "High Heart Rate",
            "description": "Alert when heart rate exceeds {threshold}",
            "category": "cardiac",
            "conditions": [
                {
                    "metric_name": "heart_rate",
                    "operator": ">",
                    "threshold_value": 100
                }
            ],
            "logical_operator": "AND",
            "default_priority": "WARNING",
            "customizable_fields": ["threshold_value", "priority"]
        },
        {
            "template_id": "low_heart_rate",
            "name": "Low Heart Rate",
            "description": "Alert when heart rate falls below {threshold}",
            "category": "cardiac",
            "conditions": [
                {
                    "metric_name": "heart_rate",
                    "operator": "<",
                    "threshold_value": 50
                }
            ],
            "logical_operator": "AND",
            "default_priority": "URGENT",
            "customizable_fields": ["threshold_value", "priority"]
        }
    ]
    # Critical: For test_get_rule_templates test, NOT async in the test fixture
    engine.get_rule_templates = MagicMock(return_value=template_list)
    
    # For validation error test
    engine.create_rule_from_template.side_effect = None  
    
    # Rule templates dictionary used in tests
    engine.rule_templates = {
        "high_heart_rate": {
            "name": "High Heart Rate",
            "description": "Alert when heart rate exceeds {threshold}",
            "required_parameters": ["threshold"],
            "condition_template": {
                "data_type": "heart_rate",
                "operator": ">",
                "threshold_value": "{threshold}",  
            },
        },
        "low_heart_rate": {
            "name": "Low Heart Rate",
            "description": "Alert when heart rate falls below {threshold}",
            "required_parameters": ["threshold"],
            "condition_template": {
                "data_type": "heart_rate",
                "operator": "<",
                "threshold_value": "{threshold}",
            },
        },
    }
    return engine


@pytest.fixture
def mock_alert_repository():
    """Create a mock alert repository."""
    repository = AsyncMock(spec=BiometricAlertRepository)  
    repository.get_alerts = AsyncMock()
    repository.get_alert_by_id = AsyncMock()
    repository.create_alert = AsyncMock()
    repository.update_alert = AsyncMock()
    repository.delete_alert = AsyncMock()
    return repository 

@pytest.fixture
def mock_current_user(): 
    """Fixture for a mock User object."""
    # Enable test mode for more permissive validation
    set_test_mode(True)
    # Create a mock User object with necessary attributes (e.g., id, role)
    mock_user = User(id=UUID("00000000-0000-0000-0000-000000000001"), role="admin", email="test@example.com") 
    return mock_user

# Define the target path for patching based on search results
REPOSITORY_PATH = "app.infrastructure.persistence.sqlalchemy.repositories.biometric_rule_repository.SQLAlchemyBiometricRuleRepository"

@pytest.mark.db_required()
class TestBiometricAlertsEndpoints:
    """Tests for the Biometric Alerts API endpoints."""

    @pytest.mark.asyncio
    @patch(f"{REPOSITORY_PATH}.get_rules", new_callable=AsyncMock)
    async def test_get_alert_rules(self, mock_get_rules, client, sample_rule):
        """Test retrieving all alert rules."""
        # Arrange
        mock_rule_data = [sample_rule.copy() for _ in range(3)]
        # Ensure patient_id is a UUID
        for rule in mock_rule_data:
            rule["patient_id"] = UUID(str(rule["patient_id"]))  # Convert string to UUID
            rule["rule_id"] = UUID(str(rule["rule_id"]))
        
        mock_get_rules.return_value = mock_rule_data

        # Act
        response = await client.get("/biometric-rules/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert len(response_data["rules"]) == 3
        assert response_data["count"] == 3
        
        # Verify structure matches AlertRuleResponseSchema
        for rule_resp in response_data["rules"]:
            assert "rule_id" in rule_resp
            assert "name" in rule_resp
            assert "description" in rule_resp
            assert "priority" in rule_resp
            assert "patient_id" in rule_resp
            assert "conditions" in rule_resp
            assert "is_active" in rule_resp
            # Convert expected priority to the enum value for comparison if needed
            assert rule_resp["priority"] == sample_rule["priority"] 
            
        mock_get_rules.assert_called_once_with(
            page=1, 
            page_size=10, 
            patient_id=None, 
            is_active=None
        ) 

    @pytest.mark.asyncio
    @patch(f"{REPOSITORY_PATH}.create_rule", new_callable=AsyncMock)
    @patch("app.presentation.api.v1.endpoints.biometric_alerts.get_event_processor") # Patch event processor dep
    async def test_create_alert_rule_from_template(self, mock_get_event_processor, mock_create_rule, client, mock_clinical_rule_engine, sample_patient_id, sample_rule):
        """Test creating an alert rule from a template."""
        # Arrange
        mock_event_processor = AsyncMock()
        mock_get_event_processor.return_value = mock_event_processor
        
        template_id = "high_heart_rate"
        customization = {
            "threshold_value": 150, # Example customization
            "priority": "URGENT" # Customize priority as well
        }
        
        # Mock the rule engine's template creation
        # Use the correct AlertPriority enum value
        expected_rule_data = {
            **sample_rule,  # Start with the base sample rule
            "rule_id": uuid.uuid4(), # Generate a new UUID for the response
            "patient_id": sample_patient_id,
            "name": "High Heart Rate Rule", # Example name based on template
            "description": "Alert for high heart rate > 150", # Example description
            "priority": AlertPriorityEnum.URGENT, # Match the customization
            "conditions": [
                {
                    "metric_name": "heart_rate",
                    "comparator_operator": ComparatorOperatorEnum.GREATER_THAN,
                    "threshold_value": 150.0,  # Match customization
                    "duration_minutes": 5 
                }
            ],
            "logical_operator": LogicalOperatorEnum.AND,
            "is_active": True
        }
        mock_clinical_rule_engine.create_rule_from_template.return_value = expected_rule_data
        mock_create_rule.return_value = expected_rule_data # Mock repository create

        # Act
        response = await client.post(
            f"/biometric-rules/from-template/{template_id}",
            json={
                "patient_id": str(sample_patient_id),
                "customization": customization
            }
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        
        # Compare relevant fields
        assert response_data["name"] == expected_rule_data["name"]
        assert response_data["patient_id"] == str(sample_patient_id)
        assert response_data["priority"] == AlertPriorityEnum.URGENT.value # Check the value
        assert response_data["conditions"][0]["threshold_value"] == 150.0
        assert response_data["is_active"] == True
        
        # Verify rule engine and repository calls
        mock_clinical_rule_engine.create_rule_from_template.assert_called_once_with(
            template_id, str(sample_patient_id), customization
        )
        mock_create_rule.assert_called_once()
        # Check that the event processor was called to add the rule
        mock_event_processor.add_rule.assert_called_once() 


    @pytest.mark.asyncio
    @patch(f"{REPOSITORY_PATH}.create_rule", new_callable=AsyncMock)
    @patch("app.presentation.api.v1.endpoints.biometric_alerts.get_event_processor")
    async def test_create_alert_rule_from_condition(self, mock_get_event_processor, mock_create_rule, client, sample_patient_id, sample_rule):
        """Test creating an alert rule directly from conditions."""
        # Arrange
        mock_event_processor = AsyncMock()
        mock_get_event_processor.return_value = mock_event_processor
        
        rule_create_data = {
            "name": "Custom Low SpO2 Rule",
            "description": "Alert when SpO2 drops below 92% for 10 mins",
            "priority": "CRITICAL", # Use AlertPriorityEnum.CRITICAL.value
            "patient_id": str(sample_patient_id),
            "conditions": [
                {
                    "metric_name": "spo2",
                    "comparator_operator": "<", # Use ComparatorOperatorEnum.LESS_THAN.value
                    "threshold_value": 92.0,
                    "duration_minutes": 10
                }
            ],
            "logical_operator": "AND", # Use LogicalOperatorEnum.AND.value
            "is_active": True
        }
        
        # Mock the repository's create_rule method to return a rule based on input
        # Use the correct Enum values for the returned object
        expected_rule_data = {
            **rule_create_data, 
            "rule_id": uuid.uuid4(), # Generate a new ID
            "patient_id": sample_patient_id, # Keep as UUID
            "priority": AlertPriorityEnum.CRITICAL,
            "conditions": [
                {
                    "metric_name": "spo2",
                    "comparator_operator": ComparatorOperatorEnum.LESS_THAN,
                    "threshold_value": 92.0,
                    "duration_minutes": 10
                }
            ],
            "logical_operator": LogicalOperatorEnum.AND,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
            "created_by": "test_user" # Assuming created_by is set somewhere
        }
        mock_create_rule.return_value = expected_rule_data

        # Act
        response = await client.post(
            "/biometric-rules/from-condition", 
            json=rule_create_data
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        
        # Check key fields
        assert response_data["name"] == rule_create_data["name"]
        assert response_data["patient_id"] == str(sample_patient_id)
        assert response_data["priority"] == AlertPriorityEnum.CRITICAL.value
        assert response_data["conditions"][0]["metric_name"] == "spo2"
        assert response_data["conditions"][0]["threshold_value"] == 92.0
        
        mock_create_rule.assert_called_once()
        # Check that the event processor was called to add the rule
        mock_event_processor.add_rule.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_alert_rule_validation_error(self, client, mock_clinical_rule_engine, sample_patient_id):
        """Test validation error when creating an alert rule with invalid data."""
        # Arrange - Invalid data (e.g., missing required fields)
        invalid_rule_data = {
            "name": "Incomplete Rule",
            # Missing patient_id, priority, conditions etc.
        }

        # Act
        response = await client.post(
            "/biometric-rules/from-condition", 
            json=invalid_rule_data
        )

        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        # Optionally check the detail in the response
        # error_details = response.json()["detail"]
        # assert any("patient_id" in err["loc"] for err in error_details)

    @pytest.mark.asyncio
    @patch(f"{REPOSITORY_PATH}.get_by_id", new_callable=AsyncMock)
    async def test_get_alert_rule(self, mock_get_by_id, client, sample_rule):
        """Test retrieving a specific alert rule by ID."""
        # Arrange
        rule_id = sample_rule["rule_id"]
        # Ensure patient_id is UUID in the mock return value
        mock_rule_data = sample_rule.copy()
        mock_rule_data["patient_id"] = UUID(str(mock_rule_data["patient_id"]))
        mock_rule_data["rule_id"] = UUID(str(mock_rule_data["rule_id"]))
        mock_get_by_id.return_value = mock_rule_data

        # Act
        response = await client.get(f"/biometric-rules/{rule_id}")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert response_data["rule_id"] == str(rule_id)
        assert response_data["name"] == sample_rule["name"]
        assert response_data["patient_id"] == str(sample_rule["patient_id"]) # Compare string representations
        mock_get_by_id.assert_called_once_with(rule_id)

    @pytest.mark.asyncio
    @patch(f"{REPOSITORY_PATH}.get_by_id", new_callable=AsyncMock)
    async def test_get_alert_rule_not_found(self, mock_get_by_id, client):
        """Test retrieving a non-existent alert rule."""
        # Arrange
        non_existent_rule_id = uuid.uuid4()
        mock_get_by_id.return_value = None # Simulate rule not found

        # Act
        response = await client.get(f"/biometric-rules/{non_existent_rule_id}")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND
        mock_get_by_id.assert_called_once_with(non_existent_rule_id)

    @pytest.mark.asyncio
    @patch(f"{REPOSITORY_PATH}.get_by_id", new_callable=AsyncMock)
    @patch(f"{REPOSITORY_PATH}.update_rule", new_callable=AsyncMock)
    @patch("app.presentation.api.v1.endpoints.biometric_alerts.get_event_processor")
    async def test_update_alert_rule(self, mock_get_event_processor, mock_update_rule, mock_get_by_id, client, sample_rule, sample_patient_id):
        """Test updating an existing alert rule."""
        # Arrange
        mock_event_processor = AsyncMock()
        mock_get_event_processor.return_value = mock_event_processor
        
        rule_id = sample_rule["rule_id"]
        update_data = {
            "name": "Updated High HR Rule",
            "description": "Updated description for high HR",
            "priority": "HIGH", # Use AlertPriorityEnum.HIGH.value
            "is_active": False,
            "conditions": [
                {
                    "metric_name": "heart_rate",
                    "comparator_operator": ">", # Use ComparatorOperatorEnum.GREATER_THAN.value
                    "threshold_value": 130.0, # Updated threshold
                    "duration_minutes": 3 # Updated duration
                }
            ],
            "logical_operator": "OR" # Use LogicalOperatorEnum.OR.value
        }
        
        # Mock repository get_by_id to return the original rule
        # Ensure patient_id and rule_id are UUIDs
        original_rule_data = sample_rule.copy()
        original_rule_data["patient_id"] = UUID(str(original_rule_data["patient_id"]))
        original_rule_data["rule_id"] = UUID(str(original_rule_data["rule_id"]))
        mock_get_by_id.return_value = original_rule_data
        
        # Mock repository update_rule to return the updated rule data
        # Ensure enums and UUIDs are correctly typed
        updated_rule_data_from_repo = {
            **original_rule_data, # Start with original
            **update_data, # Apply updates
            "rule_id": UUID(str(rule_id)), # Keep original ID as UUID
            "patient_id": UUID(str(sample_patient_id)), # Keep original patient ID as UUID
            "priority": AlertPriorityEnum.HIGH, # Use Enum
            "conditions": [
                {
                    "metric_name": "heart_rate",
                    "comparator_operator": ComparatorOperatorEnum.GREATER_THAN, # Use Enum
                    "threshold_value": 130.0,
                    "duration_minutes": 3
                }
            ],
            "logical_operator": LogicalOperatorEnum.OR, # Use Enum
            "updated_at": datetime.now(UTC) # Update timestamp
        }
        mock_update_rule.return_value = updated_rule_data_from_repo

        # Act
        response = await client.put(f"/biometric-rules/{rule_id}", json=update_data)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        
        # Check updated fields
        assert response_data["rule_id"] == str(rule_id)
        assert response_data["name"] == update_data["name"]
        assert response_data["priority"] == AlertPriorityEnum.HIGH.value
        assert response_data["is_active"] == update_data["is_active"]
        assert response_data["conditions"][0]["threshold_value"] == 130.0
        assert response_data["conditions"][0]["duration_minutes"] == 3
        assert response_data["logical_operator"] == LogicalOperatorEnum.OR.value
        
        mock_get_by_id.assert_called_once_with(rule_id)
        mock_update_rule.assert_called_once()
        # Verify event processor was called to update/remove/add the rule
        mock_event_processor.remove_rule.assert_called_once()
        mock_event_processor.add_rule.assert_called_once()

    @pytest.mark.asyncio
    @patch(f"{REPOSITORY_PATH}.get_by_id", new_callable=AsyncMock)
    @patch(f"{REPOSITORY_PATH}.delete_rule", new_callable=AsyncMock)
    @patch("app.presentation.api.v1.endpoints.biometric_alerts.get_event_processor")
    async def test_delete_alert_rule(self, mock_get_event_processor, mock_delete_rule, mock_get_by_id, client, sample_rule):
        """Test deleting an alert rule."""
        # Arrange
        mock_event_processor = AsyncMock()
        mock_get_event_processor.return_value = mock_event_processor
        
        rule_id = sample_rule["rule_id"]
        
        # Mock get_by_id to return the rule initially
        mock_rule_data = sample_rule.copy()
        mock_rule_data["patient_id"] = UUID(str(mock_rule_data["patient_id"]))
        mock_rule_data["rule_id"] = UUID(str(mock_rule_data["rule_id"]))
        mock_get_by_id.return_value = mock_rule_data
        
        mock_delete_rule.return_value = True # Simulate successful deletion

        # Act
        response = await client.delete(f"/biometric-rules/{rule_id}")

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT
        
        mock_get_by_id.assert_called_once_with(rule_id)
        mock_delete_rule.assert_called_once_with(rule_id)
        # Verify the event processor was called to remove the rule
        mock_event_processor.remove_rule.assert_called_once_with(str(rule_id))

    @pytest.mark.asyncio
    async def test_get_rule_templates(self, client, mock_clinical_rule_engine):
        """Test retrieving available rule templates."""
        # Arrange (Mock is already set up in the fixture)
        expected_templates = mock_clinical_rule_engine.get_rule_templates()

        # Act
        response = await client.get("/biometric-rules/templates")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "templates" in response_data
        assert len(response_data["templates"]) == len(expected_templates)
        assert response_data["count"] == len(expected_templates)
        # Optionally, compare structure or specific template details
        assert response_data["templates"][0]["template_id"] == expected_templates[0]["template_id"]

    @pytest.mark.asyncio
    async def test_get_alerts(self, client, mock_alert_repository, sample_alert):
        """Test retrieving biometric alerts."""
        # Arrange
        mock_alert_list = [sample_alert]
        mock_alert_repository.get_alerts.return_value = (mock_alert_list, 1) # Return (items, total_count)

        # Act
        response = await client.get("/biometric-alerts/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert len(response_data["alerts"]) == 1
        assert response_data["total_count"] == 1
        assert response_data["alerts"][0]["alert_id"] == str(sample_alert.alert_id)
        assert response_data["alerts"][0]["patient_id"] == str(sample_alert.patient_id)
        assert response_data["alerts"][0]["status"] == sample_alert.status.value

        mock_alert_repository.get_alerts.assert_called_once_with(
            page=1,
            page_size=10,
            patient_id=None,
            status=None,
            priority=None,
            start_time=None,
            end_time=None
        )

    @pytest.mark.asyncio
    async def test_get_alerts_with_filters(self, client, mock_alert_repository, sample_alert, sample_patient_id):
        """Test retrieving biometric alerts with filters."""
        # Arrange
        patient_id_str = str(sample_patient_id)
        status_filter = AlertStatusEnum.TRIGGERED.value
        priority_filter = AlertPriorityEnum.WARNING.value
        start_time_iso = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        end_time_iso = datetime.now(UTC).isoformat()

        mock_alert_list = [sample_alert] # Assume sample_alert matches filters
        mock_alert_repository.get_alerts.return_value = (mock_alert_list, 1)

        # Act
        response = await client.get(
            "/biometric-alerts/",
            params={
                "patient_id": patient_id_str,
                "status": status_filter,
                "priority": priority_filter,
                "start_time": start_time_iso,
                "end_time": end_time_iso,
                "page": 1,
                "page_size": 5
            }
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert len(response_data["alerts"]) == 1
        assert response_data["total_count"] == 1

        # Parse string dates back to datetime for comparison if necessary
        start_time_dt = datetime.fromisoformat(start_time_iso.replace("Z", "+00:00"))
        end_time_dt = datetime.fromisoformat(end_time_iso.replace("Z", "+00:00"))

        mock_alert_repository.get_alerts.assert_called_once_with(
            page=1,
            page_size=5,
            patient_id=sample_patient_id, # Should be UUID
            status=AlertStatusEnum.TRIGGERED, # Should be Enum
            priority=AlertPriorityEnum.WARNING, # Should be Enum
            start_time=start_time_dt,
            end_time=end_time_dt
        )


    @pytest.mark.asyncio
    async def test_acknowledge_alert(self, client, mock_alert_repository, mock_current_user, sample_alert):
        """Test acknowledging a biometric alert."""
        # Arrange
        alert_id = sample_alert.alert_id
        # Mock get_alert_by_id to return the sample alert
        mock_alert_repository.get_alert_by_id.return_value = sample_alert

        # Mock update_alert to simulate successful update
        updated_alert_data = sample_alert.copy(deep=True)
        updated_alert_data.status = AlertStatusEnum.ACKNOWLEDGED
        updated_alert_data.acknowledged_by = mock_current_user.id
        updated_alert_data.acknowledged_at = datetime.now(UTC)
        mock_alert_repository.update_alert.return_value = updated_alert_data

        # Construct the update payload
        update_payload = {
            "status": AlertStatusEnum.ACKNOWLEDGED.value,
            # Acknowledged_by and acknowledged_at should be set by the endpoint
            # based on the current user and time.
        }

        # Act
        # Need to override the dependency to inject the mock user
        app.dependency_overrides[get_current_user] = lambda: mock_current_user
        response = await client.patch(
            f"/biometric-alerts/{alert_id}/status",
            json=update_payload
        )
        app.dependency_overrides = {} # Clear overrides after test

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        
        assert response_data["alert_id"] == str(alert_id)
        assert response_data["status"] == AlertStatusEnum.ACKNOWLEDGED.value
        assert response_data["acknowledged_by"] == str(mock_current_user.id)
        assert "acknowledged_at" in response_data and response_data["acknowledged_at"] is not None

        # Verify mocks
        mock_alert_repository.get_alert_by_id.assert_called_once_with(alert_id)
        mock_alert_repository.update_alert.assert_called_once()
        
        # Check the arguments passed to update_alert (it receives the BiometricAlert object)
        call_args, _ = mock_alert_repository.update_alert.call_args
        updated_alert_object = call_args[0]
        assert isinstance(updated_alert_object, BiometricAlert)
        assert updated_alert_object.alert_id == alert_id
        assert updated_alert_object.status == AlertStatusEnum.ACKNOWLEDGED
        assert updated_alert_object.acknowledged_by == mock_current_user.id
        assert updated_alert_object.acknowledged_at is not None


    @pytest.mark.asyncio
    async def test_resolve_alert(self, client, mock_alert_repository, mock_current_user, sample_alert):
        """Test resolving a biometric alert."""
        # Arrange
        alert_id = sample_alert.alert_id
        sample_alert.status = AlertStatusEnum.ACKNOWLEDGED # Assume it's acknowledged first
        mock_alert_repository.get_alert_by_id.return_value = sample_alert

        updated_alert_data = sample_alert.copy(deep=True)
        updated_alert_data.status = AlertStatusEnum.RESOLVED
        updated_alert_data.resolved_by = mock_current_user.id
        updated_alert_data.resolved_at = datetime.now(UTC)
        updated_alert_data.resolution_notes = "Patient condition stabilized."
        mock_alert_repository.update_alert.return_value = updated_alert_data

        update_payload = {
            "status": AlertStatusEnum.RESOLVED.value,
            "resolution_notes": "Patient condition stabilized."
        }

        # Act
        app.dependency_overrides[get_current_user] = lambda: mock_current_user
        response = await client.patch(
            f"/biometric-alerts/{alert_id}/status",
            json=update_payload
        )
        app.dependency_overrides = {} # Clear overrides

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()

        assert response_data["status"] == AlertStatusEnum.RESOLVED.value
        assert response_data["resolved_by"] == str(mock_current_user.id)
        assert response_data["resolution_notes"] == update_payload["resolution_notes"]
        assert "resolved_at" in response_data and response_data["resolved_at"] is not None

        mock_alert_repository.get_alert_by_id.assert_called_once_with(alert_id)
        mock_alert_repository.update_alert.assert_called_once()
        
        call_args, _ = mock_alert_repository.update_alert.call_args
        updated_alert_object = call_args[0]
        assert updated_alert_object.status == AlertStatusEnum.RESOLVED
        assert updated_alert_object.resolved_by == mock_current_user.id
        assert updated_alert_object.resolution_notes == update_payload["resolution_notes"]

    @pytest.mark.asyncio
    async def test_get_patient_alert_summary(self, client, mock_alert_repository, sample_patient_id):
        """Test retrieving the alert summary for a specific patient."""
        # Arrange
        patient_id_str = str(sample_patient_id)
        # Mock the repository call (assuming it returns a summary dict)
        expected_summary = {
            "patient_id": patient_id_str,
            "total_alerts": 5,
            "active_alerts": 2,
            "highest_priority": AlertPriorityEnum.CRITICAL.value,
            "last_alert_time": datetime.now(UTC).isoformat()
        }
        mock_alert_repository.get_patient_alert_summary = AsyncMock(return_value=expected_summary)

        # Act
        response = await client.get(f"/biometric-alerts/summary/patient/{patient_id_str}")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert response_data["patient_id"] == patient_id_str
        assert response_data["total_alerts"] == expected_summary["total_alerts"]
        assert response_data["active_alerts"] == expected_summary["active_alerts"]
        assert response_data["highest_priority"] == expected_summary["highest_priority"]
        assert response_data["last_alert_time"] is not None

        mock_alert_repository.get_patient_alert_summary.assert_called_once_with(sample_patient_id)
