"""
Biometric Event Processor Service module.

This module re-exports the domain implementation of the BiometricEventProcessor
to provide a clean import path following Clean Architecture principles.
"""

from app.domain.services.biometric_event_processor import (
    BiometricEventProcessor as DomainBiometricEventProcessor,
    ClinicalRuleEngine,
)

# Re-export for clean imports
BiometricEventProcessor = DomainBiometricEventProcessor