"""
Digital Twin Core Service Mock Redirection Module.

This module provides a clean redirection to the canonical implementation
following Clean Architecture principles with proper separation of concerns.
"""

# Import the canonical implementation from mocks subdirectory
from app.infrastructure.services.mocks.mock_digital_twin_core_service import MockDigitalTwinCoreService

# Export only the service class to maintain a clean interface
__all__ = ["MockDigitalTwinCoreService"]
