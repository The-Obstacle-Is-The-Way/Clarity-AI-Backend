"""
Novamind Digital Twin Test Environment Setup.

This module ensures proper Python package setup for test discovery and execution.
It follows clean architecture principles to maintain separation of concerns
and adherence to SOLID design patterns.
"""

import os

# Configure test environment variables if not already set
if not os.environ.get("TESTING"):
    os.environ["TESTING"] = "1"

if not os.environ.get("ENVIRONMENT"):
    os.environ["ENVIRONMENT"] = "test"

# Import app modules to verify setup
try:
    from app.config.settings import Settings

    # Create settings instance to validate configuration
    settings = Settings()
    
    # Log settings for debugging
    if os.environ.get("LOG_LEVEL") == "DEBUG":
        print(f"Test environment configured with database: {settings.SQLALCHEMY_DATABASE_URI}")
except ImportError as e:
    print(f"Error in test setup: {e}")
    # Don't raise, as this might be called during initial container setup
    # when modules are still being installed
    pass 