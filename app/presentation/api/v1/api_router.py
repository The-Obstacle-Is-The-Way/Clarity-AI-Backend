# app/presentation/api/v1/api_router.py
"""
Main API router for version 1 of the Clarity AI Backend API.

Aggregates all endpoint routers for this version.
"""

from fastapi import APIRouter

# Import actual routes
from app.api.routes import auth

# Import routers from subdirectories (assuming a 'router' object in each)
from .endpoints.actigraphy import router as actigraphy_router
from .endpoints.analytics import router as analytics_router
from .endpoints.biometric_alerts import router as biometric_alerts_router
from .endpoints.biometric_alert_rules import router as biometric_alert_rules_router
from .endpoints.digital_twin import router as digital_twin_router
from .endpoints.xgboost import router as xgboost_router

# Create the main router for API v1
api_v1_router = APIRouter()

# Include routers from individual files
api_v1_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_v1_router.include_router(analytics_router, prefix="/analytics", tags=["Analytics"])

# Include routers from subdirectories
api_v1_router.include_router(actigraphy_router, prefix="/actigraphy", tags=["Actigraphy"])
api_v1_router.include_router(biometric_alerts_router, prefix="/biometric-alerts", tags=["Biometric Alerts"])
api_v1_router.include_router(biometric_alert_rules_router, prefix="/biometric-alert-rules", tags=["Biometric Alert Rules"])
api_v1_router.include_router(digital_twin_router, prefix="/digital-twin", tags=["Digital Twin"])
api_v1_router.include_router(xgboost_router, prefix="/xgboost", tags=["XGBoost Models"])

# Add a simple health check endpoint for v1
@api_v1_router.get("/health", tags=["Health"])
async def health_check():
    """Basic health check for API v1."""
    return {"status": "ok", "version": "v1"}
