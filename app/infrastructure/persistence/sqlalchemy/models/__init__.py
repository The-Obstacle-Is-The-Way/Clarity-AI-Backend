"""
SQLAlchemy models package.

Imports all models to ensure they are registered with the Base metadata
before being used, preventing relationship configuration errors.
"""
from .base import Base
# Import Patient *before* User to resolve relationship dependency
from .patient import Patient
from .user import User, UserRole
from .provider import ProviderModel
# Other models can follow
from .appointment import AppointmentModel
from .medication import MedicationModel
from .clinical_note import ClinicalNoteModel
# Import other models as needed, e.g.:
# from .analytics import AnalyticsEventModel
# from .audit_log import AuditLogModel
# from .biometric_alert_model import BiometricAlertModel
# from .biometric_rule import BiometricRuleModel
# from .biometric_twin_model import BiometricTwinModel
# from .digital_twin import DigitalTwinModel

__all__ = [
    "Base",
    "User",
    "UserRole",
    "ProviderModel",
    "Patient",
    "AppointmentModel",
    "MedicationModel",
    "ClinicalNoteModel",
    # Add other model names here
]
