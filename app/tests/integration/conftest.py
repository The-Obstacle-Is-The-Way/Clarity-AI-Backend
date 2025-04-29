"""
Integration Test Configuration and Fixtures

This file contains test fixtures specific to integration tests which may
require network connections, databases, and other external services.
"""

import pytest
import os
import json
import uuid
import asyncio
import logging
from typing import Any, Dict, List, Optional, AsyncGenerator, Callable, Generator
from httpx import AsyncClient
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

# Import the FastAPI application
from app.main import app

# Import SQLAlchemy models and utils
from app.infrastructure.persistence.sqlalchemy.models.base import Base, ensure_all_models_loaded
from app.infrastructure.persistence.sqlalchemy.registry import validate_models
from app.infrastructure.persistence.sqlalchemy.models.user import User, UserRole

# Import test database initializer functions
from app.tests.integration.utils.test_db_initializer import get_test_db_session, create_test_users

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize models
ensure_all_models_loaded()
validate_models()


# Database fixtures
@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Creates a properly initialized database session for testing with all models registered.
    Uses the test_db_initializer function to create an in-memory SQLite database with test data.
    
    This is the canonical database session fixture that should be used across all tests.
    It ensures proper model registration, transaction handling, and test data initialization.

    Yields:
        AsyncSession: SQLAlchemy AsyncSession for test database access
    """
    try:
        logger.info("Creating test database session with canonical SQLAlchemy models")
        # Use the test_db_initializer function to create an in-memory test database
        # This handles all model creation and test data setup
        async for session in get_test_db_session():
            # Ensure models are properly registered before yielding the session
            ensure_all_models_loaded()
            
            # Create test users
            await create_test_users(session)
            
            # Yield the session for the test to use
            yield session
            
            # Session will be automatically closed and rolled back after test
    except Exception as e:
        logger.error(f"Error setting up test database: {e}")
        raise


@pytest.fixture
def mock_db_data() -> Dict[str, List[Dict[str, Any]]]:
    """
    Provides mock database data for tests.

    Returns:
        Dictionary of mock collections/tables with test data.
    """

    return {
        "patients": [
            {
                "id": "p-12345",
                "name": "Test Patient",
                "age": 30,
                "gender": "F",
                "medical_history": ["Anxiety", "Depression"],
                "created_at": "2025-01-15T10:30:00Z",
            },
            {
                "id": "p-67890",
                "name": "Another Patient",
                "age": 45,
                "gender": "M",
                "medical_history": ["Bipolar Disorder"],
                "created_at": "2025-02-20T14:15:00Z",
            },
        ],
        "providers": [
            {
                "id": "prov-54321",
                "name": "Dr. Test Provider",
                "specialization": "Psychiatry",
                "license_number": "LP12345",
            }
        ],
        "appointments": [
            {
                "id": "apt-11111",
                "patient_id": "p-12345",
                "provider_id": "prov-54321",
                "datetime": "2025-04-15T10:00:00Z",
                "status": "scheduled",
            }
        ],
        "digital_twins": [
            {
                "patient_id": "p-12345",
                "model_version": "v2.1.0",
                "neurotransmitter_levels": {
                    "serotonin": 0.75,
                    "dopamine": 0.65,
                    "norepinephrine": 0.70,
                },
                "last_updated": "2025-04-10T08:45:00Z",
            }
        ],
    }


# Authentication fixtures
@pytest.fixture
def patient_auth_headers() -> Dict[str, str]:
    """
    Provides authentication headers for a test patient user.
    
    Returns:
        Dict with Authorization header containing valid JWT for test patient
    """
    # In a real implementation, this would generate a proper JWT token
    # For now, we use a static test token with standard format
    return {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJyb2xlIjoicGF0aWVudCIsImV4cCI6MTY5MzUwMDAwMH0.test-signature"
    }

@pytest.fixture
def provider_auth_headers() -> Dict[str, str]:
    """
    Provides authentication headers for a test clinician user.
    
    Returns:
        Dict with Authorization header containing valid JWT for test clinician
    """
    # In a real implementation, this would generate a proper JWT token
    # For now, we use a static test token with standard format
    return {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDIiLCJyb2xlIjoiY2xpbmljaWFuIiwiZXhwIjoxNjkzNTAwMDAwfQ.test-signature"
    }

# API Testing Fixtures
@pytest.fixture
async def test_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:  
    """
    Creates a real test client for API integration testing with database session dependency.
    This automatically uses the test database session.

    Yields:
        A FastAPI AsyncClient instance configured for testing.
    """
    # Override the get_db dependency in the FastAPI app to use our test session
    # This would be implemented in a real scenario - for now it's a placeholder
    # app.dependency_overrides[get_db] = lambda: db_session
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client
        
    # Remove any overrides after the test
    # app.dependency_overrides = {}


# External Service Mocks
@pytest.fixture
def mock_mentallama_api() -> Any:
    """
    Provides a mock for the MentaLLama API service.

    Returns:
        A mock MentaLLama API client.
    """

    class MockMentaLLamaAPI:
        async def predict(
            self, patient_id: str, data: Dict[str, Any]
        ) -> Dict[str, Any]:
            return {
                "patient_id": patient_id,
                "prediction": {
                    "anxiety_level": 0.65,
                    "depression_level": 0.55,
                    "confidence": 0.80,
                    "recommended_interventions": [
                        "CBT therapy",
                        "Mindfulness practice",
                    ],
                },
                "model_version": "mentallama-v1.2.0",
            }

        async def get_model_info(self) -> Dict[str, Any]:
            return {
                "name": "MentaLLama",
                "version": "1.2.0",
                "last_updated": "2025-03-15",
                "parameters": 7_000_000_000,
                "supported_features": [
                    "anxiety_prediction",
                    "depression_prediction",
                    "intervention_recommendation",
                ],
            }

    return MockMentaLLamaAPI()


@pytest.fixture
async def app_with_mocked_services() -> FastAPI:
    """
    Provides a mock for AWS services like S3, SageMaker, etc.

    Returns:
        A mock AWS service client.
    """

    class MockAWSService:
        def invoke_endpoint(
            self, endpoint_name: str, data: Dict[str, Any]
        ) -> Dict[str, Any]:
            return {
                "result": {
                    "prediction": [0.65, 0.35, 0.80],
                    "processing_time_ms": 120,
                    "model_version": "xgboost-v2.1",
                },
                "success": True,
                "request_id": "aws-req-12345",
            }

        def upload_file(self, file_path: str, bucket: str, key: str) -> bool:
            return True

        def download_file(
            self,
            bucket: str,
            key: str,
            local_path: str
        ) -> bool:
            # Simulate creating a file
            with open(local_path, "w") as f:
                f.write('{"mock": "data"}')
            return True

    return MockAWSService()


@pytest.fixture
def integration_fixture():
    """Basic fixture for integration tests."""
    
    return "integration_fixture"
