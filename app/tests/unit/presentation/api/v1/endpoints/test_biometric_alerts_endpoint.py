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
# Use AsyncClient for testing async endpoints
from httpx import AsyncClient 

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

# Apply asyncio marker to the class if methods are async
@pytest.mark.asyncio 
class TestBiometricAlertsEndpoints:
    """Unit tests for Biometric Alerts API Endpoints using AsyncClient."""

    # Use mock fixtures provided via conftest or defined locally
    # Example test using AsyncClient
    # Note: Ensure dependencies are overridden in the main app fixture (initialized_app in conftest.py)
    # or override them within tests if necessary.
    
    async def test_get_alert_rules(self, client: AsyncClient, get_valid_provider_auth_headers: Dict[str, str]): # Request AsyncClient and auth headers
        """Test retrieving alert rules successfully."""
        # This test likely needs the rule repository mocked via dependency override
        # in the app fixture (initialized_app). Assuming that's done in conftest.
        headers = get_valid_provider_auth_headers

        # Make async request
        response = await client.get("/api/v1/alerts/rules", headers=headers)

        assert response.status_code == status.HTTP_200_OK
        response_data = response.json()
        assert "rules" in response_data
        assert "total" in response_data
        # Add more assertions based on expected mock data from overridden repo

    async def test_create_alert_rule_from_template(
        self, 
        client: AsyncClient, # Use AsyncClient
        get_valid_provider_auth_headers: Dict[str, str], # Use auth fixture
        sample_patient_id: UUID,
        # Dependencies like rule_repo, rule_engine, event_processor 
        # should be mocked via app fixture override in conftest or here
        # mock_rule_repository: AsyncMock, 
        # mock_clinical_rule_engine: AsyncMock,
        # mock_biometric_event_processor: AsyncMock,
    ):
        """Test creating an alert rule from a template."""
        headers = get_valid_provider_auth_headers
        payload = {
            "template_id": "high_heart_rate",
            "patient_id": str(sample_patient_id),
            "customization": {
                "threshold_value": 110.0,
                "priority": "high" # Use schema enum value if applicable
            }
        }

        # Assuming mocks are set up via app fixture overrides
        response = await client.post("/api/v1/alerts/rules/from-template", headers=headers, json=payload)

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        assert response_data["name"] == "High Heart Rate Mock Rule" # Example check based on mock engine
        assert response_data["patient_id"] == str(sample_patient_id)
        assert response_data["priority"] == "high"
        # Add checks for event processor calls if needed

    async def test_create_alert_rule_from_condition(
        self, 
        client: AsyncClient, # Use AsyncClient
        get_valid_provider_auth_headers: Dict[str, str],
        sample_patient_id: UUID,
        # Dependencies mocked via app fixture override
    ):
        """Test creating a custom alert rule from conditions."""
        headers = get_valid_provider_auth_headers
        payload = {
            "name": "Custom Low Oxygen Rule",
            "description": "Alert when SpO2 drops below 92%",
            "patient_id": str(sample_patient_id),
            "priority": "critical", # Use schema enum value
            "conditions": [
                {
                    "metric_name": "blood_oxygen",
                    "comparator_operator": "less_than", # Use schema enum value
                    "threshold_value": 92.0,
                    "duration_minutes": 10
                }
            ],
            "logical_operator": "and", # Use schema enum value
            "is_active": True
        }

        response = await client.post("/api/v1/alerts/rules/from-condition", headers=headers, json=payload)

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        assert response_data["name"] == "Custom Low Oxygen Rule"
        assert response_data["patient_id"] == str(sample_patient_id)
        assert response_data["priority"] == "critical"
        assert len(response_data["conditions"]) == 1
        assert response_data["conditions"][0]["metric_name"] == "blood_oxygen"

    async def test_create_alert_rule_validation_error(self, client: AsyncClient, get_valid_provider_auth_headers: Dict[str, str], sample_patient_id: UUID):
        """Test creating an alert rule with invalid data results in 422."""
        headers = get_valid_provider_auth_headers
        invalid_payload = {
            "name": "Incomplete Rule",
            # Missing patient_id, priority, conditions etc.
        }
        response = await client.post("/api/v1/alerts/rules/from-condition", headers=headers, json=invalid_payload)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # ... continue refactoring other tests in the class ...
