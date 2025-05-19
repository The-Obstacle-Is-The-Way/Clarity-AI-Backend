"""
Machine Learning Module Routes.

This module aggregates all ML-related routes.
"""

from fastapi import APIRouter

from app.presentation.api.v1.routes.ml.xgboost import router as xgboost_router

# Create main ML router
router = APIRouter()

# Include XGBoost router
router.include_router(xgboost_router, prefix="/xgboost")

__all__ = ["router"] 