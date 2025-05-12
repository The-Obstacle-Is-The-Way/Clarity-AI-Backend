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
    from app.core.config.settings import Settings
    
    # Create test settings with safe defaults
    return Settings(
        # Database settings
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        
        # Security settings
        JWT_SECRET_KEY="test_secret_key_for_testing_only",
        JWT_ALGORITHM="HS256",
        ACCESS_TOKEN_EXPIRE_MINUTES=30,
        JWT_REFRESH_TOKEN_EXPIRE_DAYS=7,
        
        # API settings
        API_V1_STR="/api/v1",
        PROJECT_NAME="Clarity AI Backend Test",
        
        # Environment
        ENVIRONMENT="test",
        TESTING=True,
        
        # Redis settings
        REDIS_URL="redis://localhost:6379/0",
        
        # JWT settings
        JWT_ISSUER="clarity-auth",
        JWT_AUDIENCE="clarity-api",
        
        # Other settings as needed
        PHI_ENCRYPTION_KEY="test_encryption_key_for_phi_data_testing_only"
    )

# Setup other global fixtures if needed
