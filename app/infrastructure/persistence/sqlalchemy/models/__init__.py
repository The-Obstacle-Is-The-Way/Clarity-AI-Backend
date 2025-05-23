"""SQLAlchemy models package.

This package contains all SQLAlchemy ORM models used by the application.
These models represent the database schema and are used for database operations.

IMPORTANT: This module follows clean architecture principles:
1. First import Base to establish the registry
2. Then import models in dependency order to avoid circular imports
3. Register all models with SQLAlchemy using the canonical registry
"""

import logging
import sys
from importlib import import_module
from typing import TYPE_CHECKING, Any, List, Optional, Type, cast

# First import the Base class to establish registry
from app.infrastructure.persistence.sqlalchemy.registry import (
    ensure_all_models_registered,
    validate_models,
)

from .analytics import AnalyticsEventModel
from .base import AuditMixin, Base, TimestampMixin

# Import models in dependency order (models with no dependencies first)
from .provider import ProviderModel
from .user import User, UserRole

# Create forward references for models that might not be available
if TYPE_CHECKING:
    from .appointment import AppointmentModel as AppointmentModelType
    from .audit_log import AuditLog as AuditLogType
    from .biometric_alert_model import BiometricAlertModel as BiometricAlertModelType
    from .biometric_rule import BiometricRuleModel as BiometricRuleModelType
    from .biometric_twin_model import BiometricTwinModel as BiometricTwinModelType
    from .clinical_note import ClinicalNoteModel as ClinicalNoteModelType
    from .digital_twin import DigitalTwinModel as DigitalTwinModelType
    from .medication import MedicationModel as MedicationModelType

# Optional model imports - these may not be available in all environments
# Using Any as a fallback type for models that couldn't be imported
BiometricAlertModel: type[Any] | None = None
BiometricRuleModel: type[Any] | None = None
BiometricTwinModel: type[Any] | None = None
DigitalTwinModel: type[Any] | None = None

# Try to import the biometric and digital twin models
try:
    from .biometric_alert_model import BiometricAlertModel
    from .biometric_rule import BiometricRuleModel
    from .biometric_twin_model import BiometricTwinModel
    from .digital_twin import DigitalTwinModel
except ImportError as e:
    logging.warning(f"Some biometric or digital twin models could not be imported: {e}")

from .patient import Patient

# Import other optional models
AppointmentModel: type[Any] | None = None
try:
    from .appointment import AppointmentModel
except ImportError:
    logging.warning("AppointmentModel could not be imported")

ClinicalNoteModel: type[Any] | None = None
try:
    from .clinical_note import ClinicalNoteModel
except ImportError:
    logging.warning("ClinicalNoteModel could not be imported")

MedicationModel: type[Any] | None = None
try:
    from .medication import MedicationModel
except ImportError:
    logging.warning("MedicationModel could not be imported")

AuditLog: type[Any] | None = None
try:
    from .audit_log import AuditLog
except ImportError:
    logging.warning("AuditLog could not be imported")


# Define a helper function to conditionally include models in __all__
def _include_if_available(model_name: str, model_obj: Any) -> list[str]:
    """Helper function to conditionally include models in __all__."""
    return [model_name] if model_obj is not None else []


# Comprehensive list of all models for proper export
__all__ = [
    "AnalyticsEventModel",
    "AuditMixin",
    "Base",
    "Patient",
    "ProviderModel",
    "TimestampMixin",
    "User",
    "UserRole",
]

# Extend __all__ with optional models that were successfully imported
__all__.extend(_include_if_available("AppointmentModel", AppointmentModel))
__all__.extend(_include_if_available("AuditLog", AuditLog))
__all__.extend(_include_if_available("BiometricAlertModel", BiometricAlertModel))
__all__.extend(_include_if_available("BiometricRuleModel", BiometricRuleModel))
__all__.extend(_include_if_available("BiometricTwinModel", BiometricTwinModel))
__all__.extend(_include_if_available("ClinicalNoteModel", ClinicalNoteModel))
__all__.extend(_include_if_available("DigitalTwinModel", DigitalTwinModel))
__all__.extend(_include_if_available("MedicationModel", MedicationModel))

# This ensures all models are properly validated during application startup
# Commented out to avoid auto-execution on import which can cause issues in tests
# validate_models()

# Call ensure_all_models_registered to make sure all models are properly registered
ensure_all_models_registered()
