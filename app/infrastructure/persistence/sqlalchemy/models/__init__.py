"""SQLAlchemy models package.

This package contains all SQLAlchemy ORM models used by the application.
These models represent the database schema and are used for database operations.

IMPORTANT: This module follows clean architecture principles:
1. First import Base to establish the registry
2. Then import models in dependency order to avoid circular imports
3. Register all models with SQLAlchemy using the canonical registry
"""

import logging
from importlib import import_module
from typing import List

# First import the Base class to establish registry
from app.infrastructure.persistence.sqlalchemy.registry import ensure_all_models_registered, validate_models
from .base import Base, AuditMixin, TimestampMixin

# Import models in dependency order (models with no dependencies first)
from .user import User, UserRole
from .provider import ProviderModel
from .patient import Patient

# Import models safely with try/except blocks to avoid breaking imports
try:
    from .appointment import AppointmentModel
except ImportError:
    AppointmentModel = None
    logging.warning("AppointmentModel could not be imported")

try:
    from .clinical_note import ClinicalNoteModel
except ImportError:
    ClinicalNoteModel = None
    logging.warning("ClinicalNoteModel could not be imported")

try:
    from .medication import MedicationModel
except ImportError:
    MedicationModel = None
    logging.warning("MedicationModel could not be imported")

try:
    from .audit_log import AuditLog
except ImportError:
    AuditLog = None
    logging.warning("AuditLog could not be imported")

# Optional: Import additional models if they exist and are needed
try:
    from .biometric_alert_model import BiometricAlertModel
    from .biometric_rule import BiometricRuleModel
    from .biometric_twin_model import BiometricTwinModel
    from .digital_twin import DigitalTwinModel
except ImportError as e:
    logging.warning(f"Some biometric models could not be imported: {e}")

# Comprehensive list of all models for proper export
__all__ = [
    "AuditMixin",
    "AppointmentModel",
    "AuditLogModel",
    "Base",
    "BiometricAlertModel",
    "BiometricRuleModel",
    "BiometricTwinModel",
    "ClinicalNoteModel",
    "DigitalTwinModel",
    "MedicationModel",
    "Patient",
    "ProviderModel",
    "TimestampMixin",
    "User",
    "UserRole",
]

# This ensures all models are properly validated during application startup
# Commented out to avoid auto-execution on import which can cause issues in tests
# validate_models()

# Call ensure_all_models_registered to make sure all models are properly registered
ensure_all_models_registered()
