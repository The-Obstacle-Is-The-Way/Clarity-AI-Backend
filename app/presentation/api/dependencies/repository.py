"""
Repository dependencies for API routes.

This module provides FastAPI dependency functions for repository access,
following clean architecture principles with proper dependency injection patterns.
This is a compatibility module that re-exports from database.py.
"""

# Re-export from database.py for backward compatibility
from app.presentation.api.dependencies.database import get_repository, DatabaseSessionDep

# Maintain backward compatibility with existing imports
get_repository_dependency = get_repository