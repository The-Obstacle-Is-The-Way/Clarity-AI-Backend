"""
Biometric Alert Rule Repository module.

This module re-exports the SQLAlchemy implementation of the BiometricAlertRuleRepository
to provide a clean import path following Clean Architecture principles.
"""

from app.infrastructure.repositories.sqlalchemy.biometric_alert_rule_repository import (
    SQLAlchemyBiometricAlertRuleRepository as BiometricAlertRuleRepositoryImpl,
)

# Re-export for clean imports
BiometricAlertRuleRepository = BiometricAlertRuleRepositoryImpl
