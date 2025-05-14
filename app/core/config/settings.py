"""
Application settings module.

This module provides configuration settings for the application, including
security settings, database connection, and other environment-specific values.
"""

# Standard Library Imports
import logging
import os
import secrets
from pathlib import Path
from typing import Self

# Third-Party Imports
from pydantic import ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    """Application settings using Pydantic for validation and environment variable loading."""
    
    # API Information
    API_TITLE: str = "Novamind API"
    API_DESCRIPTION: str = "The Novamind Mental Health Digital Twin API"
    API_VERSION: str = "1.0.0"
    
    # Environment
    TESTING: bool = False  # Flag to indicate when running in test environment
    ENVIRONMENT: str = "development"  # development, staging, production
    VERSION: str = "0.1.0"  # Application version
    PROJECT_NAME: str = "Clarity AI"
    PROJECT_DESCRIPTION: str = "Mental Health Digital Twin API"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = Field(default=False if (ENVIRONMENT == "test" or ENVIRONMENT == "test") else True, env="DEBUG")
    
    # Server Settings
    SERVER_HOST: str = "127.0.0.1"  # Default host for the server
    SERVER_PORT: int = 8000  # Default port for the server
    UVICORN_WORKERS: int = 4  # Number of worker processes for production
    
    # Security Settings
    JWT_SECRET_KEY: SecretStr = Field(default_factory=lambda: secrets.token_urlsafe(64))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SESSION_TIMEOUT_MINUTES: int = 60
    JWT_ISSUER: str | None = None
    JWT_AUDIENCE: str | None = None
    
    # Public paths for AuthenticationMiddleware
    PUBLIC_PATHS: list[str] = Field(default_factory=lambda: [
        "/openapi.json",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/api/v1/auth/register", # Assuming registration is public
        "/api/v1/status/health", # Health checks are often public
        # Add other known public paths here
    ])
    
    # CORS Settings
    CORS_ORIGINS: list[str] = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list[str] = ["*"]
    CORS_ALLOW_HEADERS: list[str] = ["*"]
    
    # Database Settings
    DATABASE_URL: str = "sqlite+aiosqlite:///./novamind.db"
    ASYNC_DATABASE_URL: str | None = None  # Will be set based on DATABASE_URL if None
    DB_ECHO_LOG: bool = False  # Whether to echo SQL queries in logs
    
    # Logging Settings
    LOG_LEVEL: str = "INFO"
    
    # Audit Logging Settings
    AUDIT_LOG_FILE: str = Field(default="logs/audit.log")
    AUDIT_LOG_RETENTION_DAYS: int = 365  # 1 year retention for HIPAA
    AUDIT_LOG_MAX_SIZE_MB: int = 100  # Maximum size of a single audit log file in MB
    AUDIT_LOG_BACKUP_COUNT: int = 10  # Number of backup files to keep
    EXTERNAL_AUDIT_ENABLED: bool = False  # Whether to use external audit service
    
    # Monitoring and Error Tracking (Sentry)
    SENTRY_DSN: str | None = None
    SENTRY_TRACES_SAMPLE_RATE: float = 0.2  # Percentage of transactions to trace
    SENTRY_PROFILES_SAMPLE_RATE: float = 0.2  # Percentage of transactions to profile
    
    # Redis Configuration
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_SSL: bool = False
    
    # Rate Limiting
    RATE_LIMITING_ENABLED: bool = True
    DEFAULT_RATE_LIMITS: list[str] = ["60/minute", "1000/hour"]
    RATE_LIMIT_STRATEGY: str = "ip"
    
    # CORS Settings (extended with explicit typing)
    BACKEND_CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:8000"]
    
    # Security Headers
    SECURITY_HEADERS: dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    }
    
    # HIPAA Compliance Settings
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    
    # Legacy settings for backward compatibility
    POSTGRES_SERVER: str | None = None
    POSTGRES_USER: str | None = None
    POSTGRES_PASSWORD: str | None = None
    POSTGRES_DB: str | None = None
    POSTGRES_PORT: str | None = None
    SECRET_KEY: str | None = None
    
    # Security & Auth Settings
    HTTP_COOKIE_DOMAIN: str = Field(default="localhost")
    HTTP_COOKIE_MAX_AGE: int = Field(default=86400)
    HTTP_COOKIE_NAME: str = Field(default="clarity_session")
    HTTP_COOKIE_PATH: str = Field(default="/")
    HTTP_COOKIE_SAMESITE: str = Field(default="lax")
    HTTP_COOKIE_SECURE: bool = Field(default=True)
    
    # --- PHI Encryption Settings ---
    # PHI encryption settings with dummy keys for testing (NEVER use in production)
    # With proper environment setup, these will be overridden with real keys
    PHI_ENCRYPTION_KEY: str = Field(secrets.token_urlsafe(32), description="The current encryption key")
    PHI_ENCRYPTION_PREVIOUS_KEY: str | None = Field(None, description="Previous encryption key for rotation")
    TEST_OTHER_ENCRYPTION_KEY: str = Field(secrets.token_urlsafe(32), description="Secondary test key for encryption error testing")
    
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
    
    @model_validator(mode='after')
    def ensure_async_database_url(self) -> Self:
        """Ensure ASYNC_DATABASE_URL is set properly from DATABASE_URL."""
        if not self.ASYNC_DATABASE_URL and self.DATABASE_URL:
            db_url = self.DATABASE_URL
            # If it's a SQLite URL without async driver, convert it
            if db_url.startswith("sqlite:///") and "aiosqlite" not in db_url:
                self.ASYNC_DATABASE_URL = db_url.replace("sqlite:///", "sqlite+aiosqlite:///")
            else:
                # Otherwise, use the original URL
                self.ASYNC_DATABASE_URL = db_url
            logger.info(f"Set ASYNC_DATABASE_URL to {self.ASYNC_DATABASE_URL} based on DATABASE_URL")
        
        # Ensure ASYNC_DATABASE_URL is never None
        if not self.ASYNC_DATABASE_URL:
            self.ASYNC_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
            logger.warning("ASYNC_DATABASE_URL was None, set to default in-memory SQLite")
        
        # Ensure logs directory exists
        if self.AUDIT_LOG_FILE:
            log_dir = Path(self.AUDIT_LOG_FILE).parent
            if log_dir and not Path(log_dir).is_dir():
                Path(log_dir).mkdir(parents=True, exist_ok=True)
                logger.info(f"Created logs directory: {log_dir}")
        
        # Ensure DEBUG is set correctly based on environment
        if self.ENVIRONMENT in ("production", "test"):
            self.DEBUG = False
        
        return self


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
    # Check for test environment
    if os.environ.get("ENVIRONMENT") == "test" or os.environ.get("PYTEST_CURRENT_TEST"):
        # Determine test database type: in-memory (default) or file-based
        use_in_memory = os.environ.get("TEST_IN_MEMORY_DB", "True").lower() in ("true", "1", "yes")
        
        if use_in_memory:
            # In-memory SQLite for isolated, fast tests
            test_db_url = "sqlite+aiosqlite:///:memory:?cache=shared"
        else:
            # File-based SQLite in proper architecture location for persistent test data
            test_db_url = "sqlite+aiosqlite:///./app/infrastructure/persistence/data/test_db.sqlite3"
        
        logger.info(f"Running in TEST environment, using DB: {test_db_url}")
        
        # Modify the global settings instance for tests
        global settings
        settings.TESTING = True
        settings.ENVIRONMENT = "test"
        settings.DATABASE_URL = test_db_url
        settings.ASYNC_DATABASE_URL = test_db_url
        settings.SENTRY_DSN = None
        settings.AUDIT_LOG_FILE = "logs/audit_test.log"  # Test-specific audit log
        # Ensure JWT_SECRET_KEY is set for tests, even if default_factory had issues
        if not hasattr(settings, 'JWT_SECRET_KEY') or not settings.JWT_SECRET_KEY:
            settings.JWT_SECRET_KEY = "test_jwt_secret_for_test_environment_only_1234567890_abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ_01234567890_abcdefghijklmnopqrstuvwxyz"
            logger.warning("JWT_SECRET_KEY was not set for test environment, fallback applied.")
            
        return settings # Return the modified global instance
    
    # For non-test environments, ensure we have an async version of the database URL
    # This part will now operate on the potentially already modified global settings if in test mode,
    # or the original global settings if not in test mode.
    current_settings = settings 
    
    # If ASYNC_DATABASE_URL isn't explicitly set, derive it from DATABASE_URL
    if not current_settings.ASYNC_DATABASE_URL:
        db_url = current_settings.DATABASE_URL
        
        # Convert standard SQLite URL to async version if needed
        if db_url.startswith("sqlite:///") and not "aiosqlite" in db_url:
            current_settings.ASYNC_DATABASE_URL = db_url.replace("sqlite:///", "sqlite+aiosqlite:///")
            logger.info(f"Converted DATABASE_URL to async version: {current_settings.ASYNC_DATABASE_URL}")
        else:
            # For other database types, apply similar conversions or use as-is
            current_settings.ASYNC_DATABASE_URL = db_url
            
    return current_settings