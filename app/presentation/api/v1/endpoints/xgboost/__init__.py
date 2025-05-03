"""
XGBoost endpoints compatibility module.

This module provides backward compatibility for tests and code
that still references the old app.presentation.api.v1.endpoints.xgboost module.

DO NOT USE THIS IN NEW CODE - use app.api.routes.v1.endpoints.xgboost instead.
"""

# Re-export from the new location
from app.api.routes.v1.endpoints.xgboost.router import router
