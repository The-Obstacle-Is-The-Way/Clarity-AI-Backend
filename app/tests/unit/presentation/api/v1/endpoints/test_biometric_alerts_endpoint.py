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
from app.domain.repositories.user_repository import UserRepository
from app.presentation.api.v1.endpoints.biometric_alerts import (
    router as alerts_router,
    get_alert_repository,
    get_rule_repository as get_rule_repo_from_endpoint, # Alias to avoid conflict
    get_event_processor,
    get_rule_engine
) 

# Mock the rule endpoints instead of importing them directly
# from fastapi import APIRouter

# Create a mock rules router
# rules_router = APIRouter()

# Mock rule templates endpoint to avoid database dependencies
# @rules_router.get("/rule-templates")
# async def mock_get_rule_templates():
#     """Mock implementation of the rule templates endpoint."""
#     return {
#         "templates": [
#             {
#                 "template_id": "high_heart_rate",
#                 "name": "High Heart Rate",
#                 "description": "Alert when heart rate exceeds threshold",
#                 "category": "cardiac",
#                 "conditions": [],
#                 "customizable_fields": []
#             },
#             {
#                 "template_id": "low_heart_rate",
#                 "name": "Low Heart Rate",
#                 "description": "Alert when heart rate falls below threshold",
#                 "category": "cardiac",
#                 "conditions": [],
#                 "customizable_fields": []
#             }
#         ],
#         "count": 2
#     }

# Mock rule repository dependency
# def get_rule_repository():
#     """Mock rule repository dependency."""
#     return AsyncMock()

# Mock rule engine dependency
# def get_rule_engine():
#     """Mock rule engine dependency."""
#     return AsyncMock()

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
from app.domain.entities.user import User, set_test_mode # Import set_test_mode
from app.domain.entities.patient import Patient
from app.domain.entities.biometric_alert import BiometricAlert
from app.domain.entities.biometric_alert import AlertStatusEnum
# Removed faulty import
# from app.domain.repositories import BaseRepository 

# Import the main FastAPI app instance
from app.main import app

@pytest.fixture
def mock_biometric_event_processor() -> AsyncMock:
    """Create a mock BiometricEventProcessor."""
    processor = AsyncMock(spec=BiometricEventProcessor)
    processor.add_rule = AsyncMock()
    processor.remove_rule = AsyncMock()
    processor.register_observer = MagicMock()
    processor.unregister_observer = MagicMock()
    processor.process_data_point = MagicMock()
    return processor 

@pytest.fixture
def mock_clinical_rule_engine() -> AsyncMock:
    """Create a mock ClinicalRuleEngine."""
    engine = AsyncMock(spec=ClinicalRuleEngine)
    engine.register_rule_template = AsyncMock()
    engine.register_custom_condition = AsyncMock()
    
    # Define mock return value for create_rule_from_template
    # Use Schema Enums for priority, comparator, logical operator if the schema is the direct input
    # Use Domain Enums if the domain object is expected
    mock_rule_template_output = {
        "rule_id": uuid4(), # Generate dynamically
        "name": "High Heart Rate Mock Rule",
        "description": "Mock rule from template",
        "priority": AlertPriorityEnum.WARNING.value, # Use Schema Enum value for JSON compatibility
        "patient_id": None, # Will be set by caller context
        "conditions": [
            {
                "metric_name": "heart_rate", 
                "comparator_operator": ComparatorOperatorEnum.GREATER_THAN.value, # Schema Enum value
                "threshold_value": 100.0,
                "duration_minutes": 5 # Assuming duration is part of the condition now
            }
        ],
        "logical_operator": LogicalOperatorEnum.AND.value, # Schema Enum value
        "is_active": True,
        # Add created_at, updated_at etc. if the engine returns them
    }
    # Using side_effect to modify the return value based on input
    async def create_rule_side_effect(template_id, patient_id, customization):
        output = mock_rule_template_output.copy()
        output["patient_id"] = UUID(str(patient_id)) # Ensure UUID type if needed internally
        output["priority"] = customization.get("priority", output["priority"]) # Update from customization
        # Potentially update conditions based on customization too
        if "threshold_value" in customization:
             output["conditions"][0]["threshold_value"] = float(customization["threshold_value"])
        return output # Return the dictionary

    engine.create_rule_from_template = AsyncMock(side_effect=create_rule_side_effect)
    
    # Define mock return value for get_rule_templates - should be sync list of dicts
    template_list = [
        {
            "template_id": "high_heart_rate",
            "name": "High Heart Rate Template",
            "description": "Alert when heart rate exceeds {threshold_value}",
            "category": "cardiac",
            "conditions": [ # Example condition structure in template
                 {
                    "metric_name": "heart_rate",
                    "comparator_operator": ">", # Raw operator string might be here
                    "threshold_value": 100 # Default threshold
                 }
            ],
            "logical_operator": "AND", # Raw operator string
            "default_priority": AlertPriorityEnum.WARNING.value, # Use Enum value
            "customizable_fields": ["threshold_value", "priority"]
        },
        # ... other templates
    ]
    engine.get_rule_templates = MagicMock(return_value=template_list) # Sync mock
    
    # Removed old rule_templates dictionary if not used by the actual engine logic being mocked
    # engine.rule_templates = { ... }
    return engine


@pytest.fixture
def mock_alert_repository() -> AsyncMock:
    """Create a mock alert repository."""
    repository = AsyncMock(spec=BiometricAlertRepository)  
    repository.get_alerts = AsyncMock(return_value=([], 0)) # Default: empty list, zero count
    repository.get_alert_by_id = AsyncMock(return_value=None) # Default: Not found
    repository.create_alert = AsyncMock() # Returns the created alert object
    repository.update_alert = AsyncMock() # Returns the updated alert object
    repository.delete_alert = AsyncMock(return_value=True) # Simulate success
    repository.get_patient_alert_summary = AsyncMock() # Returns summary dict
    return repository 

@pytest.fixture
def mock_current_user() -> User:
    """Fixture for a mock User object."""
    set_test_mode(True) # Ensure test mode is active for validation
    # Use a consistent test user ID
    test_user_id = UUID("123e4567-e89b-12d3-a456-426614174000") 
    mock_user = User(id=test_user_id, role="admin", email="test@example.com", username="testadmin") # Added username
    return mock_user

# Define the target path for patching rule repository - Use the actual dependency path
# This should point to where get_rule_repository is *used* in the alerts endpoint file, 
# or be handled by dependency overrides. Let's rely on overrides.
# REPOSITORY_PATH = "app.presentation.api.v1.endpoints.biometric_alerts.get_rule_repository" 
# Let's use dependency overrides instead of patching the getter function directly.

# Define sample data fixtures (use pytest fixtures for better reuse)
@pytest.fixture
def sample_patient_id() -> UUID:
    return uuid4()

@pytest.fixture
def sample_rule_id() -> UUID:
    return uuid4()

@pytest.fixture
def sample_alert_id() -> UUID:
    return uuid4()

@pytest.fixture
def sample_rule_data(sample_patient_id: UUID, sample_rule_id: UUID) -> Dict[str, Any]:
    """Provides sample rule data as a dictionary, matching expected structure."""
    return {
        "rule_id": sample_rule_id,
        "name": "Sample High HR Rule",
        "description": "Alert when HR > 100",
        "patient_id": sample_patient_id,
        "priority": AlertPriorityEnum.WARNING.value, # Use Schema Enum value
        "conditions": [
            {
                "metric_name": "heart_rate",
                "comparator_operator": ComparatorOperatorEnum.GREATER_THAN.value, # Use Schema Enum value
                "threshold_value": 100.0,
                "duration_minutes": 5
            }
        ],
        "logical_operator": LogicalOperatorEnum.AND.value, # Use Schema Enum value
        "is_active": True,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
        "created_by": "system", # Example value
        "updated_by": "system"  # Example value
    }
    
@pytest.fixture
def sample_alert_domain(sample_patient_id: UUID, sample_rule_id: UUID, sample_alert_id: UUID) -> BiometricAlert:
    """Provides a sample BiometricAlert domain entity."""
    # Use Domain Enums here
    return BiometricAlert(
        alert_id=sample_alert_id,
        patient_id=sample_patient_id,
        rule_id=sample_rule_id,
        triggered_at=datetime.now(UTC),
        status=DomainAlertStatusEnum.TRIGGERED, # Domain Enum
        priority=AlertPriority.WARNING, # Domain Enum (assuming it exists)
        message="HR exceeded threshold",
        metric_name="heart_rate",
        metric_value=110.0,
        threshold_value=100.0,
        # Add other necessary fields like acknowledged_by, resolved_by etc. initialized to None
        acknowledged_by=None,
        acknowledged_at=None,
        resolved_by=None,
        resolved_at=None,
        resolution_notes=None,
        created_by="system", # Example value
        updated_by="system"  # Example value
    )

# Removed the @pytest.mark.db_required() - unit tests shouldn't need a real DB
class TestBiometricAlertsEndpoints:
    """Tests for the Biometric Alerts API endpoints."""

    # Use pytest-asyncio decorator for async tests
    @pytest.mark.asyncio 
    async def test_get_alert_rules(self, client: TestClient, mock_rule_repository: AsyncMock, sample_rule_data: Dict[str, Any]):
        """Test retrieving all alert rules."""
        # Arrange
        # Use the injected mock repository via dependency override
        app.dependency_overrides[get_rule_repo_from_endpoint] = lambda: mock_rule_repository
        
        mock_rules_list = [sample_rule_data.copy() for _ in range(3)]
        for i, rule in enumerate(mock_rules_list):
             rule["rule_id"] = uuid4() # Ensure unique IDs if repo returns distinct objects
             # Ensure patient_id is UUID if repo returns domain objects, but here it's dict
             rule["patient_id"] = str(rule["patient_id"]) # Keep as string for comparison with JSON
             rule["created_at"] = rule["created_at"].isoformat() # Convert datetime to string for mock return
             rule["updated_at"] = rule["updated_at"].isoformat()

        # Configure the mock repo to return the list of dictionaries
        mock_rule_repository.get_rules.return_value = mock_rules_list 

        # Act
        response = client.get("/api/v1/biometric-rules/") # Use full path from client base URL

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "rules" in response_data
        assert "count" in response_data
        assert len(response_data["rules"]) == 3
        assert response_data["count"] == 3
        
        # Verify structure and content matches AlertRuleResponseSchema
        for rule_resp, expected_rule in zip(response_data["rules"], mock_rules_list):
            assert rule_resp["rule_id"] == str(expected_rule["rule_id"]) # Compare string UUIDs
            assert rule_resp["name"] == expected_rule["name"]
            assert rule_resp["patient_id"] == expected_rule["patient_id"] # Compare string UUIDs
            assert rule_resp["priority"] == expected_rule["priority"] # Already enum value string
            assert rule_resp["is_active"] == expected_rule["is_active"]
            # Compare condition structure carefully
            assert len(rule_resp["conditions"]) == len(expected_rule["conditions"])
            assert rule_resp["conditions"][0]["metric_name"] == expected_rule["conditions"][0]["metric_name"]
            # Ensure datetimes are compared correctly (e.g., parse back or compare ISO strings)
            # assert rule_resp["created_at"] == expected_rule["created_at"] 
            
        mock_rule_repository.get_rules.assert_called_once_with(
            page=1, 
            page_size=10, # Default page size
            patient_id=None, 
            is_active=None
            # Add other default args if the repo method expects them
        ) 
        
        # Clean up overrides
        app.dependency_overrides = {}

    @pytest.mark.asyncio
    async def test_create_alert_rule_from_template(
        self, 
        client: TestClient, 
        mock_rule_repository: AsyncMock, 
        mock_clinical_rule_engine: AsyncMock,
        mock_biometric_event_processor: AsyncMock,
        sample_patient_id: UUID
    ):
        """Test creating an alert rule from a template."""
        # Arrange
        app.dependency_overrides[get_rule_repo_from_endpoint] = lambda: mock_rule_repository
        app.dependency_overrides[get_rule_engine] = lambda: mock_clinical_rule_engine
        app.dependency_overrides[get_event_processor] = lambda: mock_biometric_event_processor
        
        template_id = "high_heart_rate"
        patient_id_str = str(sample_patient_id)
        customization = {
            "threshold_value": 150, 
            "priority": AlertPriorityEnum.URGENT.value # Use Schema Enum value
        }
        
        # Mock Rule Engine: create_rule_from_template is already mocked in fixture
        # It will return a dict based on template + customization
        
        # Define what the repository's create_rule mock should return (usually the created rule dict/object)
        # Let's assume repo returns a dict matching the data passed to it, plus generated ID/timestamps
        async def create_rule_repo_side_effect(rule_create_schema):
             # Simulate DB creation - return a dict resembling the created resource
             created_rule_dict = rule_create_schema.dict() # If input is schema object
             created_rule_dict["rule_id"] = uuid4() # Assign new ID
             created_rule_dict["patient_id"] = UUID(created_rule_dict["patient_id"]) # Convert to UUID if needed internally
             created_rule_dict["created_at"] = datetime.now(UTC)
             created_rule_dict["updated_at"] = datetime.now(UTC)
             # Convert enums back to values for the final return dict if needed
             created_rule_dict["priority"] = created_rule_dict["priority"].value
             created_rule_dict["conditions"][0]["comparator_operator"] = created_rule_dict["conditions"][0]["comparator_operator"].value
             created_rule_dict["logical_operator"] = created_rule_dict["logical_operator"].value
             return created_rule_dict
             
        mock_rule_repository.create_rule = AsyncMock(side_effect=create_rule_repo_side_effect)

        # Act
        response = client.post(
            f"/api/v1/biometric-rules/from-template/{template_id}",
            json={
                "patient_id": patient_id_str,
                "customization": customization
            }
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        
        # Check response structure and values against customization/template
        assert "rule_id" in response_data
        assert response_data["patient_id"] == patient_id_str
        # Name might come from template or be generic - check fixture mock
        # assert response_data["name"] == "High Heart Rate Mock Rule" # Based on fixture mock
        assert response_data["priority"] == AlertPriorityEnum.URGENT.value
        assert response_data["conditions"][0]["threshold_value"] == 150.0
        assert response_data["conditions"][0]["comparator_operator"] == ComparatorOperatorEnum.GREATER_THAN.value
        assert response_data["is_active"] == True
        
        # Verify mocks were called
        mock_clinical_rule_engine.create_rule_from_template.assert_called_once_with(
            template_id, patient_id_str, customization # Engine likely gets string patient_id from API
        )
        # The repository create_rule should be called with data derived from the engine's output
        mock_rule_repository.create_rule.assert_called_once() 
        # Check event processor was called with the *created* rule data/ID
        mock_biometric_event_processor.add_rule.assert_called_once() 
        # args, _ = mock_biometric_event_processor.add_rule.call_args
        # created_rule_arg = args[0] # Check the argument passed
        # assert created_rule_arg['rule_id'] == response_data['rule_id'] # Or however the rule is passed

        # Clean up overrides
        app.dependency_overrides = {}


    @pytest.mark.asyncio
    async def test_create_alert_rule_from_condition(
        self, 
        client: TestClient, 
        mock_rule_repository: AsyncMock,
        mock_biometric_event_processor: AsyncMock,
        sample_patient_id: UUID
    ):
        """Test creating an alert rule directly from conditions."""
        # Arrange
        app.dependency_overrides[get_rule_repo_from_endpoint] = lambda: mock_rule_repository
        app.dependency_overrides[get_event_processor] = lambda: mock_biometric_event_processor
        
        patient_id_str = str(sample_patient_id)
        rule_create_payload = { # This matches AlertRuleCreateSchema structure
            "name": "Custom Low SpO2 Rule",
            "description": "Alert when SpO2 drops below 92%",
            "priority": AlertPriorityEnum.CRITICAL.value, 
            "patient_id": patient_id_str,
            "conditions": [
                {
                    "metric_name": "spo2",
                    "comparator_operator": ComparatorOperatorEnum.LESS_THAN.value, 
                    "threshold_value": 92.0,
                    "duration_minutes": 10 # Duration included
                }
            ],
            "logical_operator": LogicalOperatorEnum.AND.value, 
            "is_active": True
        }
        
        # Mock repository's create_rule method
        # Assume it returns a dict reflecting the created rule, including generated ID/timestamps
        async def create_rule_repo_side_effect(rule_create_obj): # Input might be schema obj or dict
             created_rule_dict = rule_create_obj.dict() if hasattr(rule_create_obj, 'dict') else rule_create_obj
             created_rule_dict["rule_id"] = uuid4() # Assign new ID
             # Ensure internal consistency (e.g., patient_id as UUID) if needed by other parts
             # created_rule_dict["patient_id"] = UUID(created_rule_dict["patient_id"]) 
             created_rule_dict["created_at"] = datetime.now(UTC).isoformat() # Return ISO string
             created_rule_dict["updated_at"] = datetime.now(UTC).isoformat() # Return ISO string
             # Keep enums as values as per schema response
             return created_rule_dict
             
        mock_rule_repository.create_rule = AsyncMock(side_effect=create_rule_repo_side_effect)

        # Act
        response = client.post(
            "/api/v1/biometric-rules/from-condition", 
            json=rule_create_payload
        )

        # Assert
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        
        # Check key fields against the payload
        assert "rule_id" in response_data
        assert response_data["name"] == rule_create_payload["name"]
        assert response_data["patient_id"] == patient_id_str
        assert response_data["priority"] == AlertPriorityEnum.CRITICAL.value
        assert response_data["conditions"][0]["metric_name"] == "spo2"
        assert response_data["conditions"][0]["threshold_value"] == 92.0
        assert response_data["conditions"][0]["comparator_operator"] == ComparatorOperatorEnum.LESS_THAN.value
        assert response_data["logical_operator"] == LogicalOperatorEnum.AND.value
        assert response_data["is_active"] == True
        assert "created_at" in response_data
        
        mock_rule_repository.create_rule.assert_called_once()
        # Verify event processor add_rule call
        mock_biometric_event_processor.add_rule.assert_called_once()
        # args, _ = mock_biometric_event_processor.add_rule.call_args
        # created_rule_arg = args[0] 
        # assert created_rule_arg['rule_id'] == response_data['rule_id']

        # Clean up overrides
        app.dependency_overrides = {}

    @pytest.mark.asyncio
    async def test_create_alert_rule_validation_error(self, client: TestClient, sample_patient_id: UUID):
        """Test validation error when creating an alert rule with invalid data."""
        # Arrange - Invalid data (missing required fields like patient_id, priority, conditions)
        invalid_rule_data = {
            "name": "Incomplete Rule",
            "description": "This rule is missing critical fields."
            # Missing patient_id, priority, conditions etc.
        }

        # Act
        response = client.post(
            "/api/v1/biometric-rules/from-condition", 
            json=invalid_rule_data
        )

        # Assert
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        error_details = response.json()["detail"]
        # Check that specific fields are mentioned in the validation errors
        assert any("patient_id" in err["loc"] for err in error_details), "patient_id missing validation error"
        assert any("priority" in err["loc"] for err in error_details), "priority missing validation error"
        assert any("conditions" in err["loc"] for err in error_details), "conditions missing validation error"
        
        # No overrides to clean

    @pytest.mark.asyncio
    async def test_get_alert_rule(self, client: TestClient, mock_rule_repository: AsyncMock, sample_rule_data: Dict[str, Any], sample_rule_id: UUID):
        """Test retrieving a specific alert rule by ID."""
        # Arrange
        app.dependency_overrides[get_rule_repo_from_endpoint] = lambda: mock_rule_repository
        
        rule_id_str = str(sample_rule_id)
        # Prepare the mock return data (dictionary format, as repo might return dict or domain obj)
        mock_return_data = sample_rule_data.copy()
        # Ensure datetimes are ISO strings if repo returns dict
        mock_return_data["created_at"] = mock_return_data["created_at"].isoformat()
        mock_return_data["updated_at"] = mock_return_data["updated_at"].isoformat()
        # Ensure IDs are UUIDs if repo returns domain obj, or strings if dict
        # Here, sample_rule_data already has UUIDs, but we'll convert to string for comparison
        mock_return_data["rule_id"] = str(sample_rule_id) 
        mock_return_data["patient_id"] = str(mock_return_data["patient_id"])

        mock_rule_repository.get_by_id.return_value = mock_return_data # Return the dict

        # Act
        response = client.get(f"/api/v1/biometric-rules/{rule_id_str}")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert response_data["rule_id"] == rule_id_str
        assert response_data["name"] == mock_return_data["name"]
        assert response_data["patient_id"] == mock_return_data["patient_id"]
        # Compare other relevant fields...
        
        mock_rule_repository.get_by_id.assert_called_once_with(sample_rule_id) # Repo gets UUID

        # Clean up overrides
        app.dependency_overrides = {}

    @pytest.mark.asyncio
    async def test_get_alert_rule_not_found(self, client: TestClient, mock_rule_repository: AsyncMock):
        """Test retrieving a non-existent alert rule."""
        # Arrange
        app.dependency_overrides[get_rule_repo_from_endpoint] = lambda: mock_rule_repository
        
        non_existent_rule_id = uuid4()
        mock_rule_repository.get_by_id.return_value = None # Simulate rule not found

        # Act
        response = client.get(f"/api/v1/biometric-rules/{non_existent_rule_id}")

        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND
        mock_rule_repository.get_by_id.assert_called_once_with(non_existent_rule_id)
        
        # Clean up overrides
        app.dependency_overrides = {}

    @pytest.mark.asyncio
    async def test_update_alert_rule(
        self, 
        client: TestClient, 
        mock_rule_repository: AsyncMock, 
        mock_biometric_event_processor: AsyncMock,
        sample_rule_data: Dict[str, Any],
        sample_rule_id: UUID,
        sample_patient_id: UUID
    ):
        """Test updating an existing alert rule."""
        # Arrange
        app.dependency_overrides[get_rule_repo_from_endpoint] = lambda: mock_rule_repository
        app.dependency_overrides[get_event_processor] = lambda: mock_biometric_event_processor
        
        rule_id_str = str(sample_rule_id)
        # Use AlertRuleUpdateSchema structure for payload
        update_payload = { 
            "name": "Updated Rule Name",
            "description": "Updated description",
            "priority": AlertPriorityEnum.HIGH.value, # Use Schema Enum value
            "is_active": False,
            "conditions": [
                {
                    "metric_name": "heart_rate",
                    "comparator_operator": ComparatorOperatorEnum.GREATER_THAN.value,
                    "threshold_value": 130.0, # Updated threshold
                    "duration_minutes": 3 # Updated duration
                }
            ],
            "logical_operator": LogicalOperatorEnum.OR.value # Use Schema Enum value
        }
        
        # Mock repository get_by_id to return the *original* rule data (as dict)
        original_rule_dict = sample_rule_data.copy()
        # Ensure datetime strings if repo returns dict
        original_rule_dict["created_at"] = original_rule_dict["created_at"].isoformat()
        original_rule_dict["updated_at"] = original_rule_dict["updated_at"].isoformat()
        mock_rule_repository.get_by_id.return_value = original_rule_dict
        
        # Mock repository update_rule to return the *updated* rule data (as dict)
        async def update_rule_repo_side_effect(rule_id, update_data_obj): # update_data_obj might be schema or dict
             updated_rule_dict = original_rule_dict.copy() # Start with original
             update_data_dict = update_data_obj.dict(exclude_unset=True) if hasattr(update_data_obj, 'dict') else update_data_obj
             updated_rule_dict.update(update_data_dict) # Apply changes from payload
             updated_rule_dict["rule_id"] = str(rule_id) # Ensure ID is string
             updated_rule_dict["patient_id"] = str(original_rule_dict["patient_id"]) # Keep original patient ID as string
             updated_rule_dict["updated_at"] = datetime.now(UTC).isoformat() # Update timestamp string
             # Ensure enums are string values in the returned dict
             updated_rule_dict["priority"] = AlertPriorityEnum(updated_rule_dict["priority"]).value
             updated_rule_dict["conditions"][0]["comparator_operator"] = ComparatorOperatorEnum(updated_rule_dict["conditions"][0]["comparator_operator"]).value
             updated_rule_dict["logical_operator"] = LogicalOperatorEnum(updated_rule_dict["logical_operator"]).value
             return updated_rule_dict
             
        mock_rule_repository.update_rule = AsyncMock(side_effect=update_rule_repo_side_effect)

        # Act
        response = client.put(f"/api/v1/biometric-rules/{rule_id_str}", json=update_payload)

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        
        # Check updated fields against payload
        assert response_data["rule_id"] == rule_id_str
        assert response_data["name"] == update_payload["name"]
        assert response_data["priority"] == update_payload["priority"]
        assert response_data["is_active"] == update_payload["is_active"]
        assert response_data["conditions"][0]["threshold_value"] == 130.0
        assert response_data["conditions"][0]["duration_minutes"] == 3
        assert response_data["logical_operator"] == update_payload["logical_operator"]
        assert response_data["updated_at"] > original_rule_dict["updated_at"] # Check timestamp updated

        mock_rule_repository.get_by_id.assert_called_once_with(sample_rule_id) # Called with UUID
        mock_rule_repository.update_rule.assert_called_once()
        # Check args passed to update_rule if needed
        
        # Verify event processor remove/add calls
        # If inactive, only remove should be called. If active, remove then add.
        if update_payload["is_active"]:
             mock_biometric_event_processor.remove_rule.assert_called_once_with(rule_id_str)
             mock_biometric_event_processor.add_rule.assert_called_once()
        else:
             mock_biometric_event_processor.remove_rule.assert_called_once_with(rule_id_str)
             mock_biometric_event_processor.add_rule.assert_not_called()

        # Clean up overrides
        app.dependency_overrides = {}

    @pytest.mark.asyncio
    async def test_delete_alert_rule(
        self, 
        client: TestClient, 
        mock_rule_repository: AsyncMock, 
        mock_biometric_event_processor: AsyncMock,
        sample_rule_data: Dict[str, Any],
        sample_rule_id: UUID
    ):
        """Test deleting an alert rule."""
        # Arrange
        app.dependency_overrides[get_rule_repo_from_endpoint] = lambda: mock_rule_repository
        app.dependency_overrides[get_event_processor] = lambda: mock_biometric_event_processor
        
        rule_id_str = str(sample_rule_id)
        
        # Mock get_by_id to return the rule initially (as dict)
        mock_rule_dict = sample_rule_data.copy()
        mock_rule_dict["created_at"] = mock_rule_dict["created_at"].isoformat()
        mock_rule_dict["updated_at"] = mock_rule_dict["updated_at"].isoformat()
        mock_rule_repository.get_by_id.return_value = mock_rule_dict
        
        mock_rule_repository.delete_rule.return_value = True # Simulate successful deletion in repo

        # Act
        response = client.delete(f"/api/v1/biometric-rules/{rule_id_str}")

        # Assert
        assert response.status_code == status.HTTP_204_NO_CONTENT
        
        mock_rule_repository.get_by_id.assert_called_once_with(sample_rule_id) # Called with UUID
        mock_rule_repository.delete_rule.assert_called_once_with(sample_rule_id) # Called with UUID
        # Verify the event processor was called to remove the rule
        mock_biometric_event_processor.remove_rule.assert_called_once_with(rule_id_str) # Called with string ID

        # Clean up overrides
        app.dependency_overrides = {}

    @pytest.mark.asyncio
    async def test_get_rule_templates(self, client: TestClient, mock_clinical_rule_engine: AsyncMock):
        """Test retrieving available rule templates."""
        # Arrange
        app.dependency_overrides[get_rule_engine] = lambda: mock_clinical_rule_engine
        # Mock engine is already configured in the fixture to return templates
        expected_templates = mock_clinical_rule_engine.get_rule_templates()

        # Act
        response = client.get("/api/v1/biometric-rules/templates")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "templates" in response_data
        assert "count" in response_data
        assert len(response_data["templates"]) == len(expected_templates)
        assert response_data["count"] == len(expected_templates)
        # Compare structure or specific template details
        assert response_data["templates"][0]["template_id"] == expected_templates[0]["template_id"]
        assert response_data["templates"][0]["name"] == expected_templates[0]["name"]
        
        mock_clinical_rule_engine.get_rule_templates.assert_called_once() # Verify mock was called
        
        # Clean up overrides
        app.dependency_overrides = {}

    # === Alert Endpoint Tests ===

    @pytest.mark.asyncio
    async def test_get_alerts(self, client: TestClient, mock_alert_repository: AsyncMock, sample_alert_domain: BiometricAlert):
        """Test retrieving biometric alerts."""
        # Arrange
        app.dependency_overrides[get_alert_repository] = lambda: mock_alert_repository
        
        # Mock repo returns a list of domain objects and count
        mock_alert_list = [sample_alert_domain.copy(deep=True) for _ in range(2)] 
        mock_total_count = len(mock_alert_list)
        mock_alert_repository.get_alerts.return_value = (mock_alert_list, mock_total_count) 

        # Act
        response = client.get("/api/v1/biometric-alerts/")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "alerts" in response_data
        assert "total_count" in response_data
        assert len(response_data["alerts"]) == mock_total_count
        assert response_data["total_count"] == mock_total_count
        
        # Verify response structure matches BiometricAlertResponseSchema
        # Compare against the *first* mock alert for structure/content
        first_resp_alert = response_data["alerts"][0]
        first_domain_alert = mock_alert_list[0]
        assert first_resp_alert["alert_id"] == str(first_domain_alert.alert_id)
        assert first_resp_alert["patient_id"] == str(first_domain_alert.patient_id)
        assert first_resp_alert["rule_id"] == str(first_domain_alert.rule_id)
        assert first_resp_alert["status"] == first_domain_alert.status.value # Compare enum value
        assert first_resp_alert["priority"] == first_domain_alert.priority.value # Compare enum value
        assert "triggered_at" in first_resp_alert # Check datetime presence

        mock_alert_repository.get_alerts.assert_called_once_with(
            page=1,
            page_size=10, # Default page size
            patient_id=None,
            status=None,
            priority=None,
            start_time=None,
            end_time=None
            # Add other default args if repo expects them
        )
        
        # Clean up overrides
        app.dependency_overrides = {}

    @pytest.mark.asyncio
    async def test_get_alerts_with_filters(
        self, 
        client: TestClient, 
        mock_alert_repository: AsyncMock, 
        sample_alert_domain: BiometricAlert, 
        sample_patient_id: UUID
    ):
        """Test retrieving biometric alerts with filters."""
        # Arrange
        app.dependency_overrides[get_alert_repository] = lambda: mock_alert_repository
        
        patient_id_str = str(sample_patient_id)
        status_filter = AlertStatusEnum.TRIGGERED # Use Domain Enum for repo call
        priority_filter = AlertPriority.WARNING # Use Domain Enum for repo call
        start_time = datetime.now(UTC) - timedelta(hours=1)
        end_time = datetime.now(UTC)
        
        # Mock repo returns alerts matching filters
        mock_alert_list = [sample_alert_domain] 
        mock_total_count = 1
        mock_alert_repository.get_alerts.return_value = (mock_alert_list, mock_total_count)

        # Act
        response = client.get(
            "/api/v1/biometric-alerts/",
            params={
                "patient_id": patient_id_str,
                "status": status_filter.value, # Send enum *value* as param
                "priority": priority_filter.value, # Send enum *value* as param
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "page": 2,
                "page_size": 5
            }
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert len(response_data["alerts"]) == 1
        assert response_data["total_count"] == 1
        # Check if the returned alert matches the sample
        assert response_data["alerts"][0]["alert_id"] == str(sample_alert_domain.alert_id)

        # Verify repo call with correct types (UUID, Enums, datetimes)
        mock_alert_repository.get_alerts.assert_called_once()
        call_args, call_kwargs = mock_alert_repository.get_alerts.call_args
        
        assert call_kwargs.get("page") == 2
        assert call_kwargs.get("page_size") == 5
        assert call_kwargs.get("patient_id") == sample_patient_id # Expect UUID
        assert call_kwargs.get("status") == status_filter # Expect Domain Enum
        assert call_kwargs.get("priority") == priority_filter # Expect Domain Enum
        # Allow for minor differences in microseconds for datetime comparison
        assert abs(call_kwargs.get("start_time") - start_time) < timedelta(seconds=1)
        assert abs(call_kwargs.get("end_time") - end_time) < timedelta(seconds=1)

        # Clean up overrides
        app.dependency_overrides = {}


    @pytest.mark.asyncio
    async def test_update_alert_status_acknowledge(
        self, 
        client: TestClient, 
        mock_alert_repository: AsyncMock, 
        mock_current_user: User, 
        sample_alert_domain: BiometricAlert,
        sample_alert_id: UUID
    ):
        """Test acknowledging a biometric alert by updating its status."""
        # Arrange
        app.dependency_overrides[get_alert_repository] = lambda: mock_alert_repository
        app.dependency_overrides[get_current_user] = lambda: mock_current_user # Inject mock user

        alert_id_str = str(sample_alert_id)
        # Ensure the sample alert starts as TRIGGERED
        sample_alert_domain.status = DomainAlertStatusEnum.TRIGGERED
        sample_alert_domain.acknowledged_by = None
        sample_alert_domain.acknowledged_at = None
        
        # Mock get_alert_by_id to return the sample alert domain object
        mock_alert_repository.get_alert_by_id.return_value = sample_alert_domain

        # Mock update_alert to return the modified alert domain object
        async def update_alert_side_effect(alert_obj: BiometricAlert):
            # Simulate the update operation
            assert alert_obj.alert_id == sample_alert_id
            assert alert_obj.status == DomainAlertStatusEnum.ACKNOWLEDGED # Check status being set
            assert alert_obj.acknowledged_by == mock_current_user.id # Check user ID being set
            assert alert_obj.acknowledged_at is not None # Check timestamp being set
            # Return the modified object
            return alert_obj 
        mock_alert_repository.update_alert.side_effect = update_alert_side_effect

        # Payload matches AlertStatusUpdateSchema
        update_payload = {
            "status": AlertStatusEnum.ACKNOWLEDGED.value, # Use Schema Enum value for payload
            "resolution_notes": None # Not needed for acknowledge
        }

        # Act
        response = client.patch(
            f"/api/v1/biometric-alerts/{alert_id_str}/status",
            json=update_payload
        )
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json() # Should match BiometricAlertResponseSchema
        
        assert response_data["alert_id"] == alert_id_str
        assert response_data["status"] == AlertStatusEnum.ACKNOWLEDGED.value
        assert response_data["acknowledged_by"] == str(mock_current_user.id) # Check user ID in response
        assert "acknowledged_at" in response_data and response_data["acknowledged_at"] is not None
        # Ensure resolved fields are still null
        assert response_data["resolved_by"] is None
        assert response_data["resolved_at"] is None
        assert response_data["resolution_notes"] is None

        # Verify mocks
        mock_alert_repository.get_alert_by_id.assert_called_once_with(sample_alert_id) # Called with UUID
        mock_alert_repository.update_alert.assert_called_once()
        # Side effect already checked args internally
        
        # Clean up overrides
        app.dependency_overrides = {}


    @pytest.mark.asyncio
    async def test_update_alert_status_resolve(
        self, 
        client: TestClient, 
        mock_alert_repository: AsyncMock, 
        mock_current_user: User, 
        sample_alert_domain: BiometricAlert,
        sample_alert_id: UUID
    ):
        """Test resolving a biometric alert by updating its status."""
        # Arrange
        app.dependency_overrides[get_alert_repository] = lambda: mock_alert_repository
        app.dependency_overrides[get_current_user] = lambda: mock_current_user

        alert_id_str = str(sample_alert_id)
        resolution_notes = "Patient condition stabilized after intervention."
        
        # Assume alert is already acknowledged for resolution
        sample_alert_domain.status = DomainAlertStatusEnum.ACKNOWLEDGED
        sample_alert_domain.acknowledged_by = mock_current_user.id # Some user acknowledged
        sample_alert_domain.acknowledged_at = datetime.now(UTC) - timedelta(minutes=5)
        sample_alert_domain.resolved_by = None
        sample_alert_domain.resolved_at = None
        sample_alert_domain.resolution_notes = None
        
        mock_alert_repository.get_alert_by_id.return_value = sample_alert_domain

        # Mock update_alert
        async def update_alert_side_effect(alert_obj: BiometricAlert):
            assert alert_obj.alert_id == sample_alert_id
            assert alert_obj.status == DomainAlertStatusEnum.RESOLVED # Check status
            assert alert_obj.resolved_by == mock_current_user.id # Check resolver ID
            assert alert_obj.resolution_notes == resolution_notes # Check notes
            assert alert_obj.resolved_at is not None # Check timestamp
            # Acknowledged fields should remain
            assert alert_obj.acknowledged_by is not None 
            assert alert_obj.acknowledged_at is not None
            return alert_obj
        mock_alert_repository.update_alert.side_effect = update_alert_side_effect

        # Payload for resolving
        update_payload = {
            "status": AlertStatusEnum.RESOLVED.value, # Schema Enum value
            "resolution_notes": resolution_notes
        }

        # Act
        response = client.patch(
            f"/api/v1/biometric-alerts/{alert_id_str}/status",
            json=update_payload
        )

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()

        assert response_data["alert_id"] == alert_id_str
        assert response_data["status"] == AlertStatusEnum.RESOLVED.value
        assert response_data["resolved_by"] == str(mock_current_user.id)
        assert response_data["resolution_notes"] == resolution_notes
        assert "resolved_at" in response_data and response_data["resolved_at"] is not None
        # Ensure acknowledged fields are still present in response
        assert "acknowledged_by" in response_data and response_data["acknowledged_by"] is not None
        assert "acknowledged_at" in response_data and response_data["acknowledged_at"] is not None

        # Verify mocks
        mock_alert_repository.get_alert_by_id.assert_called_once_with(sample_alert_id)
        mock_alert_repository.update_alert.assert_called_once()
        
        # Clean up overrides
        app.dependency_overrides = {}

    @pytest.mark.asyncio
    async def test_update_alert_status_not_found(self, client: TestClient, mock_alert_repository: AsyncMock, mock_current_user: User):
        """Test updating status of a non-existent alert."""
         # Arrange
        app.dependency_overrides[get_alert_repository] = lambda: mock_alert_repository
        app.dependency_overrides[get_current_user] = lambda: mock_current_user

        non_existent_alert_id = uuid4()
        alert_id_str = str(non_existent_alert_id)
        
        # Mock get_alert_by_id to return None
        mock_alert_repository.get_alert_by_id.return_value = None

        update_payload = { "status": AlertStatusEnum.ACKNOWLEDGED.value }

        # Act
        response = client.patch(
            f"/api/v1/biometric-alerts/{alert_id_str}/status",
            json=update_payload
        )
        
        # Assert
        assert response.status_code == status.HTTP_404_NOT_FOUND
        mock_alert_repository.get_alert_by_id.assert_called_once_with(non_existent_alert_id)
        mock_alert_repository.update_alert.assert_not_called() # Update should not be called

        # Clean up overrides
        app.dependency_overrides = {}

    @pytest.mark.asyncio
    async def test_get_patient_alert_summary(self, client: TestClient, mock_alert_repository: AsyncMock, sample_patient_id: UUID):
        """Test retrieving the alert summary for a specific patient."""
        # Arrange
        app.dependency_overrides[get_alert_repository] = lambda: mock_alert_repository
        
        patient_id_str = str(sample_patient_id)
        # Mock the repository call to return a summary dictionary
        # Use Domain Enum values if the repo summary uses them internally
        expected_summary_from_repo = {
            "patient_id": sample_patient_id, # Repo might return UUID
            "total_alerts": 5,
            "active_alerts": 2,
            "triggered_count": 1,
            "acknowledged_count": 1,
            "resolved_count": 3,
            "highest_priority_active": AlertPriority.CRITICAL, # Domain Enum
            "last_alert_time": datetime.now(UTC)
        }
        # Ensure the mock returns the dictionary structure expected by the endpoint logic
        mock_alert_repository.get_patient_alert_summary = AsyncMock(return_value=expected_summary_from_repo)

        # Act
        response = client.get(f"/api/v1/biometric-alerts/summary/patient/{patient_id_str}")

        # Assert
        assert response.status_code == status.HTTP_200_OK
        response_data = response.json() # Should match PatientAlertSummarySchema
        
        # Compare response data with the *expected* schema format
        assert response_data["patient_id"] == patient_id_str
        assert response_data["total_alerts"] == expected_summary_from_repo["total_alerts"]
        assert response_data["active_alerts"] == expected_summary_from_repo["active_alerts"]
        assert response_data["triggered_count"] == expected_summary_from_repo["triggered_count"]
        assert response_data["acknowledged_count"] == expected_summary_from_repo["acknowledged_count"]
        assert response_data["resolved_count"] == expected_summary_from_repo["resolved_count"]
        # Compare enum *value* for priority in response
        assert response_data["highest_priority_active"] == AlertPriorityEnum.CRITICAL.value 
        assert "last_alert_time" in response_data 
        # Compare datetimes appropriately (parse response string)
        assert abs(datetime.fromisoformat(response_data["last_alert_time"]) - expected_summary_from_repo["last_alert_time"]) < timedelta(seconds=1)

        mock_alert_repository.get_patient_alert_summary.assert_called_once_with(sample_patient_id) # Called with UUID

        # Clean up overrides
        app.dependency_overrides = {}

    @pytest.mark.asyncio
    async def test_get_patient_alert_summary_not_found(self, client: TestClient, mock_alert_repository: AsyncMock):
        """Test retrieving summary for a patient with no alerts (or patient not found scenario handled by repo)."""
        # Arrange
        app.dependency_overrides[get_alert_repository] = lambda: mock_alert_repository
        
        non_existent_patient_id = uuid4()
        patient_id_str = str(non_existent_patient_id)
        
        # Simulate repo raising EntityNotFoundError or returning a specific indicator
        # Option 1: Raise Not Found
        # mock_alert_repository.get_patient_alert_summary = AsyncMock(side_effect=EntityNotFoundError(f"Patient {patient_id_str} not found or has no alerts"))
        
        # Option 2: Return None or empty dict (Endpoint needs to handle this)
        # Let's assume the endpoint expects a 404 if the repo indicates not found, e.g., by returning None
        mock_alert_repository.get_patient_alert_summary = AsyncMock(return_value=None) 

        # Act
        response = client.get(f"/api/v1/biometric-alerts/summary/patient/{patient_id_str}")

        # Assert
        # If repo raises EntityNotFoundError, endpoint should catch and return 404
        # If repo returns None, endpoint should handle and return 404
        assert response.status_code == status.HTTP_404_NOT_FOUND 

        mock_alert_repository.get_patient_alert_summary.assert_called_once_with(non_existent_patient_id)

        # Clean up overrides
        app.dependency_overrides = {}
