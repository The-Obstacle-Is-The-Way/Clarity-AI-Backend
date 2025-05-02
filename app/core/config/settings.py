"""
Application settings module.

This module provides configuration settings for the application, including
security settings, database connection, and other environment-specific values.
"""

import os
import secrets
from typing import List, Dict, Any, Optional
from pydantic import Field, field_validator, ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings using Pydantic for validation and environment variable loading."""
    
    # API Information
    API_TITLE: str = "Novamind API"
    API_DESCRIPTION: str = "The Novamind Mental Health Digital Twin API"
    API_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Security Settings
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(64))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SESSION_TIMEOUT_MINUTES: int = 60
    JWT_ISSUER: Optional[str] = None
    JWT_AUDIENCE: Optional[str] = None
    
    # CORS Settings
    CORS_ORIGINS: List[str] = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["*"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]
    
    # Database Settings
    DATABASE_URL: str = "sqlite:///./novamind.db"
    
    # Logging Settings
    LOG_LEVEL: str = "INFO"
    
    # Security Headers
    SECURITY_HEADERS: Dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    }
    
    # HIPAA Compliance Settings
    PHI_ENCRYPTION_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    AUDIT_LOG_RETENTION_DAYS: int = 365  # 1 year retention for HIPAA
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    
    # Legacy settings for backward compatibility
    POSTGRES_SERVER: Optional[str] = None
    POSTGRES_USER: Optional[str] = None
    POSTGRES_PASSWORD: Optional[str] = None
    POSTGRES_DB: Optional[str] = None
    POSTGRES_PORT: Optional[str] = None
    SECRET_KEY: Optional[str] = None
    
    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="allow"  # Allow extra fields to support legacy code
    )
    
    @field_validator("LOG_LEVEL")
    def validate_log_level(cls, v: str) -> str:
        """Validate that log level is one of the valid levels."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()


# Create a global settings instance
settings = Settings()


def get_settings() -> Settings:
    """
    Factory function to get the application settings.
    
    This function enables dependency injection of settings in FastAPI.
    It can be extended to provide test-specific settings or mocked settings.
    
    Returns:
        The application settings instance
    """
    return settings