"""
Mock settings for testing.

This module provides a mock Settings class for testing.
"""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class MockSettings(BaseModel):
    """Mock settings class for testing."""

    # General application settings
    APP_NAME: str = "Clarity AI Backend"
    APP_ENV: str = "test"
    DEBUG: bool = True
    TESTING: bool = False

    # API configuration
    API_PREFIX: str = "/api"
    API_V1_STR: str = "/v1"

    # JWT settings
    JWT_SECRET_KEY: str = (
        "test_jwt_secret_key_that_is_sufficiently_long_for_testing_purposes_only"
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_ISSUER: str = "clarity-ai-test"
    JWT_AUDIENCE: str = "test-audience"

    # Database settings
    DATABASE_URL: str = "sqlite:///./test.db"

    # Redis settings
    REDIS_URL: str = "redis://localhost:6379/0"

    # Security settings
    SECURITY_PASSWORD_SALT: str = "test_password_salt_for_testing_purposes_only"

    # Audit log settings
    AUDIT_LOG_ENABLED: bool = False

    # Session settings
    SESSION_TIMEOUT_MINUTES: int = 30

    # CORS settings
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    def get_jwt_settings(self) -> Dict[str, Any]:
        """
        Get JWT settings.

        Returns:
            Dict[str, Any]: JWT settings
        """
        return {
            "secret_key": self.JWT_SECRET_KEY,
            "algorithm": self.JWT_ALGORITHM,
            "access_token_expire_minutes": self.ACCESS_TOKEN_EXPIRE_MINUTES,
            "refresh_token_expire_days": self.JWT_REFRESH_TOKEN_EXPIRE_DAYS,
            "issuer": self.JWT_ISSUER,
            "audience": self.JWT_AUDIENCE,
        }
