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
from app.presentation.api.dependencies.actigraphy import (
    ActigraphyServiceDep,
    get_actigraphy_service,
)
from app.presentation.api.v1.dependencies.digital_twin import (
    DigitalTwinServiceDep,
    get_digital_twin_service,
)

__all__ = [
    "PatientServiceDep",
    "get_patient_service",
    "ActigraphyServiceDep",
    "get_actigraphy_service",
    "DigitalTwinServiceDep",
    "get_digital_twin_service",
]
