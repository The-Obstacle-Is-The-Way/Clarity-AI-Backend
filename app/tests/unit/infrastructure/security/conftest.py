"""
Fixtures for JWT service and token blacklist repository tests.

This module provides test fixtures that create controlled environments
for testing JWT-related functionality with proper dependency injection.
"""

import pytest
from unittest.mock import MagicMock

from app.config.settings import Settings
from app.tests.unit.infrastructure.security.mock_token_blacklist_repository import MockTokenBlacklistRepository


@pytest.fixture
def token_blacklist_repository():
    """Provide a mock token blacklist repository for testing."""
    return MockTokenBlacklistRepository()


@pytest.fixture
def user_repository():
    """Provide a mock user repository for JWT service testing."""
    mock_repo = MagicMock()
    # Configure mock to return predefined values for common methods
    return mock_repo


@pytest.fixture
def test_settings():
    """Create test settings with JWT-specific configuration."""
    settings = Settings(
        SECRET_KEY="test_secret_key_for_jwt_service_unit_tests",
        ALGORITHM="HS256",
        ACCESS_TOKEN_EXPIRE_MINUTES=30,
        JWT_REFRESH_TOKEN_EXPIRE_DAYS=7,
        ENVIRONMENT="test"
    )
    # Add custom attributes that are used by JWTService but not in Settings
    settings.JWT_ISSUER = "test-issuer"
    settings.JWT_AUDIENCE = "test-audience"
    return settings
