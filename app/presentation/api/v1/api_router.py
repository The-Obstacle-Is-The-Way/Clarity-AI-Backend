# app/presentation/api/v1/api_router.py
"""
Main API router for version 1 of the Clarity AI Backend API.

Aggregates all endpoint routers for this version.
"""

from fastapi import APIRouter

# Corrected imports pointing to the canonical router location
from app.presentation.api.v1.routes.actigraphy import router as actigraphy_router
from app.presentation.api.v1.routes.analytics import router as analytics_router
from app.presentation.api.v1.routes.auth import router as auth_router
from app.presentation.api.v1.routes.biometric import router as biometric_router
from app.presentation.api.v1.routes.biometric_alert_rules import (
    router as biometric_alert_rules_router,
)
from app.presentation.api.v1.routes.biometric_alerts import (
    router as biometric_alerts_router,
)
from app.presentation.api.v1.routes.digital_twin import (
    router as digital_twin_router,
)
from app.presentation.api.v1.routes.ml import router as ml_router
from app.presentation.api.v1.routes.temporal_neurotransmitter import (
    router as temporal_neurotransmitter_router,
)
from app.presentation.api.v1.routes.xgboost import router as xgboost_router

# Create the main router for API v1
api_v1_router = APIRouter()

# Include routers using the new variable names
api_v1_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_v1_router.include_router(actigraphy_router, prefix="/actigraphy", tags=["Actigraphy"])
api_v1_router.include_router(analytics_router, prefix="/analytics", tags=["Analytics"])
api_v1_router.include_router(biometric_router, prefix="/biometrics", tags=["Biometrics"])
api_v1_router.include_router(
    biometric_alerts_router, prefix="/biometric-alerts", tags=["Biometric Alerts"]
)
api_v1_router.include_router(
    biometric_alert_rules_router,
    prefix="/biometric-alert-rules",
    tags=["Biometric Alert Rules"],
)
api_v1_router.include_router(ml_router, prefix="/ml", tags=["Machine Learning"])
api_v1_router.include_router(
    temporal_neurotransmitter_router,
    prefix="/temporal-neurotransmitter",
    tags=["Temporal Neurotransmitter"],
)
api_v1_router.include_router(xgboost_router, prefix="/xgboost", tags=["XGBoost"])
api_v1_router.include_router(digital_twin_router, prefix="/digital-twin", tags=["Digital Twin"])


# Add a simple health check endpoint for v1
@api_v1_router.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    """Check the health of the API."""
    return {"status": "OK"}
