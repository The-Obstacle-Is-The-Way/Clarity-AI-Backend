"""
Dependencies for service providers.

This package contains dependency injection providers for application services.
Each module provides typed dependencies for a specific service domain.
"""

# Export commonly used dependencies
from app.presentation.api.dependencies.services.patient_service import (
    PatientServiceDep,
    get_patient_service,
)

__all__ = [
    "PatientServiceDep",
    "get_patient_service",
]
