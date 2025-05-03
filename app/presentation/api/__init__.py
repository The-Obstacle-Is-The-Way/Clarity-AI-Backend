"""
API layer compatibility module.

This module provides backward compatibility for tests and code
that still references the old app.presentation.api structure.

DO NOT USE THIS IN NEW CODE - use app.api instead.
"""

# Re-export from the new location
from app.api import *
