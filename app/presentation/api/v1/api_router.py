# app/presentation/api/v1/api_router.py
"""
Main API router for version 1 of the Clarity AI Backend API.

Aggregates all endpoint routers for this version.
"""

from fastapi import APIRouter

from app.presentation.api.v1.endpoints.analytics import router as analytics_router

# Import our new biometric alert rules endpoint
from app.presentation.api.v1.endpoints.biometric_alert_rules import (
    router as biometric_alert_rules_router_endpoint,
)

# Import our new biometric alerts endpoint
from app.presentation.api.v1.endpoints.biometric_alerts import (
    router as biometric_alerts_endpoint_router,
)
from app.presentation.api.v1.endpoints.actigraphy import router as actigraphy_router_endpoint

# Corrected imports pointing to the canonical router location
# Removed old analytics routes import - now using consolidated endpoints file
from app.presentation.api.v1.endpoints.auth import router as auth_router
from app.presentation.api.v1.endpoints.biometric import router as biometric_router
from app.presentation.api.v1.endpoints.digital_twin import router as digital_twin_router
from app.presentation.api.v1.endpoints.mentallama import router as mentallama_router
from app.presentation.api.v1.endpoints.ml import router as ml_router
from app.presentation.api.v1.endpoints.patient import router as patient_router_endpoint
from app.presentation.api.v1.routes.temporal_neurotransmitter import (
    router as temporal_neurotransmitter_router,
)
from app.presentation.api.v1.routes.xgboost import router as xgboost_router

# Create the main router for API v1
api_v1_router = APIRouter()

# Include routers using the new variable names
api_v1_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])  # Using endpoints version
api_v1_router.include_router(actigraphy_router_endpoint, prefix="/actigraphy", tags=["Actigraphy"])
# Use consolidated analytics endpoints
api_v1_router.include_router(analytics_router, prefix="/analytics", tags=["Analytics"])
api_v1_router.include_router(biometric_router, prefix="/biometrics", tags=["Biometrics"])  # Using endpoints version

# Prefer our endpoint implementation over the route version
api_v1_router.include_router(
    biometric_alerts_endpoint_router,
    prefix="/biometric-alerts",
    tags=["Biometric Alerts"],
)

# Include alert rules endpoint implementations
api_v1_router.include_router(
    biometric_alert_rules_router_endpoint,
    prefix="/biometric-alert-rules",
    tags=["Biometric Alert Rules"],
)

api_v1_router.include_router(ml_router, prefix="/ml", tags=["Machine Learning"])  # Using endpoints version
api_v1_router.include_router(mentallama_router, prefix="/mentallama", tags=["MentaLLaMA"])  # Using endpoints version
api_v1_router.include_router(
    temporal_neurotransmitter_router,
    prefix="/temporal-neurotransmitter",
    tags=["Temporal Neurotransmitter"],
)
api_v1_router.include_router(xgboost_router, prefix="/xgboost", tags=["XGBoost"])
api_v1_router.include_router(digital_twin_router, prefix="/digital-twin", tags=["digital-twin"])  
# Use the endpoint implementation instead of the route version
api_v1_router.include_router(patient_router_endpoint, prefix="/patients", tags=["Patients"])


# Add a simple health check endpoint for v1
@api_v1_router.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    """Check the health of the API."""
    return {"status": "OK"}
