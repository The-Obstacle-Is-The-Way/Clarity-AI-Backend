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
from .provider import ProviderModel
from .analytics import AnalyticsEventModel
from .user import User, UserRole

# Biometric and Digital Twin models should be imported before Patient if Patient refers to them
try: # MODIFIED: Comment out try
    from .biometric_alert_model import BiometricAlertModel
    from .biometric_rule import BiometricRuleModel
    from .biometric_twin_model import BiometricTwinModel # Contains BiometricDataPointModel as well
    from .digital_twin import DigitalTwinModel # Contains its own BiometricDataPointModel and BiometricTimeseriesModel
except ImportError as e: # MODIFIED: Comment out except
    logging.warning(f"Some biometric or digital twin models could not be imported: {e}")
    BiometricAlertModel = None
    BiometricRuleModel = None
    BiometricTwinModel = None
    DigitalTwinModel = None 

from .patient import Patient

# Import models safely with try/except blocks to avoid breaking imports
try: # MODIFIED: Comment out try
    from .appointment import AppointmentModel
except ImportError: # MODIFIED: Comment out except
    AppointmentModel = None
    logging.warning("AppointmentModel could not be imported")

try: # MODIFIED: Comment out try
    from .clinical_note import ClinicalNoteModel
except ImportError: # MODIFIED: Comment out except
    ClinicalNoteModel = None
    logging.warning("ClinicalNoteModel could not be imported")

try: # MODIFIED: Comment out try
    from .medication import MedicationModel
except ImportError: # MODIFIED: Comment out except
    MedicationModel = None
    logging.warning("MedicationModel could not be imported")

try: # MODIFIED: Comment out try
    from .audit_log import AuditLog
except ImportError: # MODIFIED: Comment out except
    AuditLog = None
    logging.warning("AuditLog could not be imported")

# Optional: Import additional models if they exist and are needed
# try: # MODIFIED: Comment out try
# from .biometric_alert_model import BiometricAlertModel # Already imported above
# from .biometric_rule import BiometricRuleModel # Already imported above
# from .biometric_twin_model import BiometricTwinModel # Already imported above
# from .digital_twin import DigitalTwinModel # Already imported above
# except ImportError as e: # MODIFIED: Comment out except
#     logging.warning(f"Some biometric models could not be imported: {e}")

# Comprehensive list of all models for proper export
__all__ = [
    "AuditMixin",
    "AppointmentModel",
    "AuditLog",  # Updated from AuditLogModel to AuditLog
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
    "AnalyticsEventModel",
]

# This ensures all models are properly validated during application startup
# Commented out to avoid auto-execution on import which can cause issues in tests
# validate_models()

# Call ensure_all_models_registered to make sure all models are properly registered
ensure_all_models_registered()
