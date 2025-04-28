"""
Tests for the configuration module.

This module tests that application configuration loads correctly
and handles environment variables properly.
"""
import os
import pytest
from pydantic import ValidationError

from app.config.settings import Settings, get_settings

# Load actual settings using Pydantic BaseSettings
settings = Settings()

# Removed import for settings as it's being mocked below
# from app.core.config import settings


@pytest.mark.db_required()
class TestSettings:
    """Test cases for the Settings class."""

    def test_default_settings(self):
        """Test that default settings are loaded correctly."""
        # Check essential configuration values
        assert settings.PROJECT_NAME == "Novamind Digital Twin"
        assert settings.API_V1_STR == "/api/v1"
        assert settings.ENVIRONMENT == "test"
        assert settings.SQLALCHEMY_DATABASE_URI is not None

        # Security settings
        assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 30

        # HIPAA settings
        assert settings.ENABLE_PHI_AUDITING is True

    def test_environment_override(self, monkeypatch):
        """Test that environment variables override default settings."""
        # Set environment variables
        monkeypatch.setenv("PROJECT_NAME", "Custom Project Name")
        monkeypatch.setenv("API_V1_STR", "/api/custom")
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")  # 1 hour
        monkeypatch.setenv("ENABLE_PHI_AUDITING", "False")

        # Re-initialize settings to pick up environment overrides
        settings_local = Settings()
        # Check that environment variables were applied
        assert settings_local.PROJECT_NAME == "Custom Project Name"
        assert settings_local.API_V1_STR == "/api/custom"
        assert settings_local.ENVIRONMENT == "production"
        assert settings_local.ACCESS_TOKEN_EXPIRE_MINUTES == 60
        assert settings_local.ENABLE_PHI_AUDITING is False

    def test_database_url_override(self, monkeypatch):
        """Test database URL override via environment variable."""
        test_db_url = "postgresql+asyncpg://testuser:testpass@testhost/testdb"
        monkeypatch.setenv("DATABASE_URL", test_db_url)

        # Re-initialize settings to pick up environment override
        settings_local = Settings()
        # Check database URL
        assert settings_local.SQLALCHEMY_DATABASE_URI == test_db_url

    def test_database_url_construction(self, monkeypatch):
        """Test that database URL is constructed correctly from components."""
        # Setup database environment variables
        test_db_url = "postgresql://test-user:test-password@test-db-server:5432/test-db"
        monkeypatch.setenv("DATABASE_URL", test_db_url)

        # Re-initialize settings to pick up DATABASE_URL override
        settings_local = Settings()
        # Check database URL
        assert settings_local.SQLALCHEMY_DATABASE_URI == test_db_url

    def test_testing_environment(self, monkeypatch):
        """Test settings specific to the testing environment."""
        # Set testing environment variables
        monkeypatch.setenv("TESTING", "1")
        monkeypatch.setenv("ENVIRONMENT", "testing")

        # Re-initialize settings to pick up overrides and set DEBUG
        settings_local = Settings()
        # Verify testing environment settings
        assert settings_local.ENVIRONMENT == "testing"
        # DEBUG env var should be set by Settings model
        assert "DEBUG" in os.environ

    def test_cors_origins_parsing(self, monkeypatch):
        """Test parsing of CORS_ORIGINS from environment variables."""
        # Test comma-separated string format
        monkeypatch.setenv(
            "CORS_ORIGINS",
            "http://localhost,https://example.com"
        )

        # Re-initialize settings to pick up CORS override
        settings_local = Settings()
        assert len(settings_local.CORS_ORIGINS) == 2
        assert "http://localhost" in settings_local.CORS_ORIGINS
        assert "https://example.com" in settings_local.CORS_ORIGINS

        # Test list format
        monkeypatch.setenv(
            "CORS_ORIGINS",
            '["http://localhost:8000", "https://api.example.com"]'
        )
        # Re-initialize settings to pick up list format override
        settings_local = Settings()
        assert len(settings_local.CORS_ORIGINS) == 2
        assert "http://localhost:8000" in settings_local.CORS_ORIGINS
        assert "https://api.example.com" in settings_local.CORS_ORIGINS

# Fixture to reset the lru_cache for get_settings before each test
@pytest.fixture(scope="function")
def reset_get_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()