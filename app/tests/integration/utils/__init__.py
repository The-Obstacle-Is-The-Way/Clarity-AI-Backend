"""
Integration Test Utilities

This package provides a clean, standardized approach to database initialization
and utilities for integration testing in the Novamind platform.

All database testing infrastructure is centralized in test_db_initializer.py,
which serves as the single source of truth for test database sessions.
"""

# Import and expose the standardized test database initializer
from app.tests.integration.utils.test_db_initializer import (
    TEST_CLINICIAN_ID,
    # Test models (REMOVED - Use real models now)
    # TestBase, 
    # TestUser,
    # TestPatient,
    # Test data constants
    TEST_USER_ID,
    # Helper functions
    create_test_patient_domain,
    create_test_users,
    # Database session
    get_test_db_session,
    verify_table_exists,
)
