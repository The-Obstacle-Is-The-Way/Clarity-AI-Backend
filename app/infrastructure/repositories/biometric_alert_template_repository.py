"""
Biometric Alert Template Repository module.

This module re-exports the SQLAlchemy implementation of the BiometricAlertTemplateRepository
to provide a clean import path following Clean Architecture principles.
"""

from app.infrastructure.repositories.sqlalchemy.biometric_alert_template_repository import (
    SQLAlchemyBiometricAlertTemplateRepository as BiometricAlertTemplateRepositoryImpl,
)

# Re-export for clean imports
BiometricAlertTemplateRepository = BiometricAlertTemplateRepositoryImpl
