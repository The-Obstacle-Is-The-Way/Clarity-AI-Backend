"""
Machine learning service dependencies for FastAPI.

This module provides dependency injection functions for machine learning
services to be used in FastAPI route handlers.
"""

from typing import Annotated

from fastapi import Depends

from app.core.services.ml.xgboost.interface import XGBoostInterface
from app.core.services.ml.xgboost.factory_refactored import create_xgboost_service
from app.infrastructure.aws.service_factory_provider import get_aws_service_factory


def get_xgboost_service() -> XGBoostInterface:
    """
    Dependency provider for XGBoost service.
    
    Returns:
        Configured XGBoost service implementation
    """
    # Ensure AWS services are properly initialized
    aws_factory = get_aws_service_factory()
    
    # Create and return the service
    return create_xgboost_service(implementation_name="aws")


# Type alias for use in route handler function signatures
XGBoostService = Annotated[XGBoostInterface, Depends(get_xgboost_service)]
