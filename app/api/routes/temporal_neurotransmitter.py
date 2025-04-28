"""
Alias module for Temporal Neurotransmitter DI dependencies used by integration tests.
"""

from app.infrastructure.di.container import get_service
from app.presentation.api.dependencies.auth import get_current_user, verify_provider_access

def get_temporal_neurotransmitter_service():
    """Dependency override for TemporalNeurotransmitter service."""
    return get_service("temporal_neurotransmitter")

__all__ = [
    "get_temporal_neurotransmitter_service",
    "get_current_user",
    "verify_provider_access",
]