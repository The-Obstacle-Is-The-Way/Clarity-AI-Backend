"""
XGBoost service dependency injection module.

This module provides dependency injection for XGBoost services,
supporting both the legacy implementation and the new factory-based approach.
"""

import logging
from fastapi import Request

# Import core interfaces and services
from app.core.services.ml.xgboost.interface import XGBoostInterface

# Import factory for creating XGBoost service instances
from app.core.services.ml.xgboost.factory import create_xgboost_service

# Import auth dependencies
from app.presentation.api.dependencies.auth import get_current_user, verify_provider_access

# Set up logger
logger = logging.getLogger(__name__)

# Dependency provider for XGBoost service via factory
def get_xgboost_service(request: Request) -> XGBoostInterface:
    """
    Resolve the XGBoostInterface implementation using the factory pattern.
    
    Order of precedence:
    1. If a test or startup has set `app.state.xgboost_service`, use that
    2. Otherwise, create a new service instance using the factory
    
    Returns:
        An implementation of XGBoostInterface
    """
    # Check if a service instance has been set on app.state (typically for testing)
    svc = getattr(request.app.state, 'xgboost_service', None)
    if svc is not None:
        logger.debug("Using XGBoost service from app.state")
        return svc
    
    # Otherwise, create a new service using the factory
    logger.debug("Creating new XGBoost service from factory")
    return create_xgboost_service(implementation_name="aws")

# Default no-op permission validator for XGBoost API routes; tests may patch this
def validate_permissions() -> None:
    """No-op permission validator for XGBoost routes. Can be patched in tests."""
    return None
    
__all__ = ["get_xgboost_service", "get_current_user", "verify_provider_access", "validate_permissions"]