"""
API security module compatibility layer.

This module provides backward compatibility for tests and code
that still references the old app.security.api module.

DO NOT USE THIS IN NEW CODE - use app.core.security instead.
"""

# Re-export from the clean architecture location
from app.core.security import (
    check_permission,
    has_role,
    verify_hipaa_compliance,
    verify_input_sanitization,
    verify_output_sanitization
)
