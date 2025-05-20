"""
Biometric Alert Repository module.

This module re-exports the SQLAlchemy implementation of the BiometricAlertRepository
to provide a clean import path following Clean Architecture principles.
"""

from app.infrastructure.repositories.sqlalchemy.biometric_alert_repository import (
    SQLAlchemyBiometricAlertRepository as BiometricAlertRepositoryImpl,
)

# Re-export for clean imports
BiometricAlertRepository = BiometricAlertRepositoryImpl