"""
Dependencies for Biometric Alert related functionality in the Presentation Layer.

Provides dependency functions to inject repositories and services required
by the biometric alert endpoints.
"""

from typing import Annotated

from fastapi import Depends

# Import Interfaces (adjust paths as needed based on final structure)
from app.domain.repositories.biometric_alert_repository import BiometricAlertRepository
from app.domain.repositories.biometric_alert_rule_repository import (
    BiometricAlertRuleRepository,
)
from app.domain.repositories.biometric_alert_template_repository import (
    BiometricAlertTemplateRepository,
)
from app.domain.services.biometric_event_processor import BiometricEventProcessor

# TODO: Import actual factory functions for implementations when available
# from app.infrastructure.repositories.biometric_alert_repository import get_biometric_alert_repository
# from app.infrastructure.repositories.biometric_alert_rule_repository import get_biometric_alert_rule_repository
# from app.infrastructure.repositories.biometric_alert_template_repository import get_biometric_alert_template_repository
# from app.application.services.biometric_event_processor import get_biometric_event_processor

# --- Placeholder Dependency Functions --- #
# These will be replaced by functions that inject actual implementations


async def get_alert_repository() -> BiometricAlertRepository | None:
    """Placeholder dependency for BiometricAlertRepository."""
    print("Warning: Using placeholder get_alert_repository")
    # In a real scenario: return get_biometric_alert_repository(session=Depends(get_async_session))
    return None


async def get_rule_repository() -> BiometricAlertRuleRepository | None:
    """Placeholder dependency for BiometricAlertRuleRepository."""
    print("Warning: Using placeholder get_rule_repository")
    # In a real scenario: return get_biometric_alert_rule_repository(session=Depends(get_async_session))
    return None


async def get_template_repository() -> BiometricAlertTemplateRepository | None:
    """Placeholder dependency for BiometricAlertTemplateRepository."""
    print("Warning: Using placeholder get_template_repository")
    # In a real scenario: return get_biometric_alert_template_repository(session=Depends(get_async_session))
    return None


async def get_event_processor() -> BiometricEventProcessor | None:
    """Placeholder dependency for BiometricEventProcessor."""
    print("Warning: Using placeholder get_event_processor")
    # In a real scenario: return get_biometric_event_processor(...)
    return None


# --- Type Hinted Dependencies --- #
# Use 'any' for now until concrete implementations are provided
AlertRepoDep = Annotated[any, Depends(get_alert_repository)]
RuleRepoDep = Annotated[any, Depends(get_rule_repository)]
TemplateRepoDep = Annotated[any, Depends(get_template_repository)]
EventProcessorDep = Annotated[any, Depends(get_event_processor)]

__all__ = [
    "get_alert_repository",
    "get_rule_repository",
    "get_template_repository",
    "get_event_processor",
    "AlertRepoDep",
    "RuleRepoDep",
    "TemplateRepoDep",
    "EventProcessorDep",
]
