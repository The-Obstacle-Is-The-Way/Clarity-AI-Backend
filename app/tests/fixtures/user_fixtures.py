"""
User fixtures for testing authentication and authorization.

This module provides common user test fixtures used across test cases.
"""
from uuid import UUID

from app.domain.enums.role import Role

# Test user ID (constant for predictable tests)
test_user_id = UUID("12345678-1234-5678-1234-567812345678")

# Default test roles
test_roles = [Role.USER]

# Admin test roles
admin_roles = [Role.ADMIN]

# Clinician test roles
clinician_roles = [Role.CLINICIAN]

# Researcher test roles
researcher_roles = [Role.RESEARCHER]

# Multi-role test
multi_roles = [Role.ADMIN, Role.CLINICIAN, Role.RESEARCHER]
