"""
Enhanced Digital Twin Core Service Mock Redirection Module.

This module provides a clean redirection to the canonical implementation
following Clean Architecture principles with proper separation of concerns.
"""

# Re-export from the canonical implementation for backward compatibility
from app.infrastructure.services.mocks.mock_enhanced_digital_twin_core_service import (
    MockEnhancedDigitalTwinCoreService
)

# Re-export the neurotransmitter service implementation following clean architecture
from app.infrastructure.services.mocks.mock_enhanced_digital_twin_neurotransmitter_service import (
    MockEnhancedDigitalTwinNeurotransmitterService
)

# Export all relevant service classes to maintain a clean interface
__all__ = ["MockEnhancedDigitalTwinCoreService", "MockEnhancedDigitalTwinNeurotransmitterService"]
