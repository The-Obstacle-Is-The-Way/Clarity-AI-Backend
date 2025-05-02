"""
Machine learning service dependencies for FastAPI.

This module provides dependency injection functions for machine learning
services to be used in FastAPI route handlers.
"""

from typing import Annotated

from fastapi import Depends

from app.core.services.ml.xgboost.interface import XGBoostInterface
from app.core.services.ml.xgboost.factory import create_xgboost_service

def get_xgboost_service() -> XGBoostInterface:
    """
    Dependency injector for XGBoostService.
    Creates an instance of XGBoostService using the factory.
    """
    service = create_xgboost_service()
    return service


# Type alias for use in route handler function signatures
XGBoostService = Annotated[XGBoostInterface, Depends(get_xgboost_service)]
