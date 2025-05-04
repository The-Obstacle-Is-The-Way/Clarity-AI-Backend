# app/presentation/api/v1/api_router.py
"""
Main API router for version 1 of the Clarity AI Backend API.

Aggregates all endpoint routers for this version.
"""

from fastapi import APIRouter

# Import individual endpoint routers
from .endpoints import analytics, auth

# Import routers from subdirectories (assuming a 'router' object in each)
from .endpoints.actigraphy import router as actigraphy_router
from .endpoints.biometric import router as biometric_router
from .endpoints.biometric_alerts import router as biometric_alerts_router
from .endpoints.digital_twins import router as digital_twins_router
from .endpoints.xgboost import router as xgboost_router

# Create the main router for API v1
api_v1_router = APIRouter()

# Include routers from individual files
api_v1_router.include_router(analytics.router, prefix="/analytics", tags=["Analytics"])
api_v1_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])

# Include routers from subdirectories
api_v1_router.include_router(actigraphy_router, prefix="/actigraphy", tags=["Actigraphy"])
api_v1_router.include_router(biometric_router, prefix="/biometric", tags=["Biometric"])
api_v1_router.include_router(biometric_alerts_router, prefix="/biometric-alerts", tags=["Biometric Alerts"])
api_v1_router.include_router(digital_twins_router, prefix="/digital-twins", tags=["Digital Twins"])
api_v1_router.include_router(xgboost_router, prefix="/xgboost", tags=["XGBoost Models"])

# Add a simple health check endpoint for v1
@api_v1_router.get("/health", tags=["Health"])
async def health_check():
    """Basic health check for API v1."""
    return {"status": "ok", "version": "v1"}
