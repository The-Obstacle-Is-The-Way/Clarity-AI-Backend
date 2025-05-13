"""
Core Service Dependencies for the Presentation Layer.

This module provides FastAPI dependency functions for accessing core application
services and repositories within the API endpoints.
"""

import logging
from typing import Annotated

from fastapi import Depends

# Correct service/factory imports
from app.application.services.digital_twin_service import DigitalTwinApplicationService
from app.core.config import settings
# from app.infrastructure.ml.pat.bedrock_pat import BedrockPAT # Example PAT implementation
from app.infrastructure.ml.pat.service import PATService # Correct path
from app.application.services.audit_log_service import AuditLogService
from app.core.interfaces.services.audit_logger_interface import IAuditLogger
from app.presentation.api.dependencies.repositories import get_audit_log_repository

logger = logging.getLogger(__name__)

# --- Dependency Functions --- #

def get_digital_twin_service() -> DigitalTwinApplicationService:
    """
    Provide a Digital Twin service implementation.
    
    Backward compatibility function - use app.api.dependencies instead in new code.
    
    Returns:
        Digital Twin service implementation
    """
    # Simple stub implementation to allow test collection
    return None

def get_xgboost_service() -> None:
    """
    Provide an XGBoost service implementation.
    
    Backward compatibility function - use app.api.dependencies instead in new code.
    
    Returns:
        None (Stub implementation)
    """
    # NOTE: Original import failed, returning None as a stub for now.
    return None

# Provide PATService Implementation
def get_pat_service() -> PATService:
    # Simple instantiation assuming BedrockPAT is the chosen implementation
    # Configuration details might be needed depending on BedrockPAT.__init__
    # return PATService(pat_model=BedrockPAT(config=settings)) # Pass the model instance - BedrockPAT missing
    # NOTE: Returning None as a stub until BedrockPAT is available.
    return None

async def get_audit_logger(
    repository = Depends(get_audit_log_repository)
) -> IAuditLogger:
    """
    Get the audit logger for the current request.
    
    Args:
        repository: The audit log repository
        
    Returns:
        IAuditLogger: The audit logger
    """
    return AuditLogService(repository)

# Define typed dependencies for better code organization
AuditLoggerDep = Annotated[IAuditLogger, Depends(get_audit_logger)]
