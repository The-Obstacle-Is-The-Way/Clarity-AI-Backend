"""
ML interfaces package.

This module defines the domain interfaces for ML services,
following clean architecture principles and the dependency inversion principle.
"""

from app.domain.interfaces.ml.xgboost import XGBoostInterface

__all__ = ["XGBoostInterface"]
