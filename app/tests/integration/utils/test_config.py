"""
Test Configuration Module

This module provides consistent test configuration values across all test suites,
ensuring that JWT tokens and other security settings are consistent and valid.
"""

import os
from typing import Dict, Any
from pydantic import SecretStr

# Standard test settings used across all test suites
# These values MUST be consistent with what's used in fixture configurations
TEST_SECRET_KEY = "test-secret-key-for-testing-purposes-only"
TEST_JWT_ALGORITHM = "HS256"
TEST_JWT_TOKEN_EXPIRE_MINUTES = 30
TEST_JWT_ISSUER = "clarity-ai-test"

def get_test_settings_override() -> Dict[str, Any]:
    """
    Get dictionary of settings overrides for test environment.
    
    This ensures all tests use consistent configuration values.
    
    Returns:
        Dict with test settings overrides
    """
    return {
        "SECRET_KEY": SecretStr(TEST_SECRET_KEY),
        "JWT_SECRET_KEY": SecretStr(TEST_SECRET_KEY),
        "JWT_ALGORITHM": TEST_JWT_ALGORITHM,
        "ACCESS_TOKEN_EXPIRE_MINUTES": TEST_JWT_TOKEN_EXPIRE_MINUTES,
        "JWT_REFRESH_TOKEN_EXPIRE_DAYS": 7,
        "JWT_ISSUER": TEST_JWT_ISSUER,
        "TESTING": True,
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "DATABASE_ENCRYPTION_ENABLED": True,
    }

def setup_test_environment() -> None:
    """
    Configure test environment variables.
    
    Sets required environment variables for test environment.
    """
    os.environ["TESTING"] = "true"
    os.environ["ENVIRONMENT"] = "test"
    os.environ["SECRET_KEY"] = TEST_SECRET_KEY
    os.environ["JWT_SECRET_KEY"] = TEST_SECRET_KEY
    os.environ["JWT_ALGORITHM"] = TEST_JWT_ALGORITHM
    os.environ["JWT_ISSUER"] = TEST_JWT_ISSUER
