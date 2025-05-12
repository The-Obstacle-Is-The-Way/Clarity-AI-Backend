"""
Global test configuration for the entire test suite.

This module contains fixtures and configurations that should be available
to all tests in the application. It is automatically loaded by pytest.
"""

import os
import sys
import pytest
import pytest_asyncio
import logging
from typing import Dict, Any, Generator

# Make the module available to be imported by tests
sys.modules['pytest_asyncio'] = pytest_asyncio

# Configure logging for tests
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@pytest.fixture(scope="session")
def base_test_config() -> Dict[str, Any]:
    """
    Returns a basic configuration dictionary for tests.
    This can be used as a base for other fixtures.
    """
    return {
        "testing": True,
        "debug": True,
    }

@pytest.fixture(scope="session")
def test_settings():
    """
    Create test application settings.
    
    This fixture provides a configuration that can be used for testing
    without connecting to real external services.
    """
    from app.core.config.settings import AppSettings
    
    # Create test settings with safe defaults
    return AppSettings(
        # Database settings
        POSTGRES_USER="test_user",
        POSTGRES_PASSWORD="test_password",
        POSTGRES_DB="test_db",
        POSTGRES_HOST="localhost",
        POSTGRES_PORT="5432",
        
        # Security settings
        SECRET_KEY="test_secret_key_for_testing_only",
        ALGORITHM="HS256",
        ACCESS_TOKEN_EXPIRE_MINUTES=30,
        REFRESH_TOKEN_EXPIRE_DAYS=7,
        
        # API settings
        API_V1_PREFIX="/api/v1",
        PROJECT_NAME="Clarity AI Backend Test",
        
        # Environment
        ENVIRONMENT="test",
        DEBUG=True,
        TESTING=True,
        
        # Redis settings
        REDIS_HOST="localhost",
        REDIS_PORT="6379",
        REDIS_PASSWORD="",
        
        # S3 settings
        AWS_S3_BUCKET_NAME="test-bucket",
        AWS_ACCESS_KEY_ID="test-access-key",
        AWS_SECRET_ACCESS_KEY="test-secret-key",
        AWS_REGION="us-east-1",
        
        # JWT settings
        JWT_SECRET_KEY="test_jwt_secret_for_testing_only",
        JWT_ALGORITHM="HS256",
        JWT_AUDIENCE="clarity-api",
        JWT_ISSUER="clarity-auth",
        
        # Machine learning service settings
        ML_SERVICE_URL="http://localhost:8000",
        ML_SERVICE_API_KEY="test-ml-api-key",
        
        # Other settings as needed
        PHI_ENCRYPTION_KEY="test_encryption_key_for_phi_data_testing_only"
    )

# Setup other global fixtures if needed
