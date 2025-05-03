"""
XGBoost service compatibility module.

TEMPORARY COMPATIBILITY LAYER - This is a transitional module that redirects to the clean architecture implementation.
All new code should be written in the application/domain/infrastructure layers following clean architecture principles.

DO NOT USE THIS IN NEW CODE - use app.application.services.ml.xgboost_service instead.
"""

# Re-export from the clean architecture location
from app.application.services.ml.xgboost_service import XGBoostService
from app.domain.interfaces.ml import XGBoostInterface
