"""SQLAlchemy models package.

This package contains all SQLAlchemy ORM models used by the application.
These models represent the database schema and are used for database operations.

IMPORTANT: This module follows a specific import pattern to prevent circular imports.
1. First import Base to establish the registry
2. Then import each model individually to register it with SQLAlchemy
3. Avoid circular dependencies by careful import ordering
"""

# First import the Base class to establish registry
from app.infrastructure.persistence.sqlalchemy.registry import ensure_all_models_registered

from .base import Base

# Then import models that depend on User
from .patient import Patient
from .provider import ProviderModel

# Then import models in dependency order (models with no dependencies first)
from .user import User, UserRole

# from .audit_log import AuditLogModel
# from .biometric_alert_model import BiometricAlertModel
# from .biometric_rule import BiometricRuleModel
# from .biometric_twin_model import BiometricTwinModel
# from .digital_twin import DigitalTwinModel

__all__ = [
    "AppointmentModel",
    "Base",
    "ClinicalNoteModel",
    "MedicationModel",
    "Patient",
    "ProviderModel",
    "User",
    "UserRole",
    # Add other model names here
]
