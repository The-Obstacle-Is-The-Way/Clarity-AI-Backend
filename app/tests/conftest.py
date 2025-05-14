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
from typing import Dict, Any, Generator, AsyncGenerator
from fastapi import FastAPI
from httpx import AsyncClient
from starlette.middleware.base import BaseHTTPMiddleware

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

@pytest.fixture(scope="session")
def encryption_service():
    """
    Create a test encryption service.
    
    This fixture provides a consistent encryption service for tests.
    """
    from app.infrastructure.security.encryption import create_encryption_service
    
    # Use a fixed test key for consistent test results
    test_key = "test_encryption_key_for_phi_data_testing_only"
    test_salt = "test_salt_value_for_encryption_tests_only"
    
    return create_encryption_service(secret_key=test_key, salt=test_salt)

@pytest.fixture(autouse=True)
def disable_audit_logging_for_tests(request):
    """
    Automatically disable audit logging for all tests.
    
    This fixture runs automatically for all tests and disables audit logging
    to avoid database transaction errors in tests.
    """
    # Skip disabling for certain tests if needed
    if request.node.get_closest_marker('enable_audit_logging'):
        yield
        return
        
    # Override setup for FastAPI applications in the test
    fixture_names = dir(request)
    for name in ['app', 'app_instance', 'test_app', 'fastapi_app']:
        if name in fixture_names:
            app = request.getfixturevalue(name)
            if isinstance(app, FastAPI):
                app.state.disable_audit_middleware = True
                logger.debug(f"Disabled audit middleware for app fixture: {name}")
    
    yield

@pytest_asyncio.fixture
async def with_disabled_audit_middleware(request, app_instance):
    """
    Fixture that explicitly disables audit middleware for FastAPI app instances.
    
    This is useful for tests that directly create FastAPI applications or when
    the autouse fixture doesn't work.
    """
    if hasattr(app_instance, 'state'):
        app_instance.state.disable_audit_middleware = True
        logger.debug("Explicitly disabled audit middleware for test app")
    
    yield app_instance
    
    # Restore state if needed
    if hasattr(app_instance, 'state'):
        app_instance.state.disable_audit_middleware = False

# Setup other global fixtures if needed
