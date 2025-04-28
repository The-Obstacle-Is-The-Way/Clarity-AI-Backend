"""
Integration Test Configuration and Fixtures

This file contains test fixtures specific to integration tests which may
require network connections, databases, and other external services.
"""

import pytest
import os
import json
import asyncio
from typing import Any, Dict, List, Optional, AsyncGenerator, Callable, Generator
from httpx import AsyncClient
from fastapi import FastAPI
from app.main import app


# Database fixtures
@pytest.fixture
async def test_db_connection() -> AsyncGenerator[Any, None]:
    """
    Creates a test database connection.

    Yields:
        A database connection for testing.
    """
    # This would typically use SQLAlchemy, Motor, or another database client
    # Mock implementation for structure
    db_config = {
        "host": os.environ.get("TEST_DB_HOST", "localhost"),
        "port": int(os.environ.get("TEST_DB_PORT", "5432")),
        "user": os.environ.get("TEST_DB_USER", "test_user"),
        "password": os.environ.get("TEST_DB_PASSWORD", "test_password"),
        "database": os.environ.get("TEST_DB_NAME", "test_db"),
    }

    # Simulate DB connection
    connection = {"connected": True, "config": db_config}

    try:
        yield connection
    finally:
        # Cleanup would happen here
        pass


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


# API Testing Fixtures
# Commenting out potentially conflicting test_client fixture
@pytest.fixture
async def test_client() -> AsyncGenerator[AsyncClient, None]:  
    """
    Creates a real test client for API integration testing.

    Yields:
        A FastAPI TestClient instance.
    """
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


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
