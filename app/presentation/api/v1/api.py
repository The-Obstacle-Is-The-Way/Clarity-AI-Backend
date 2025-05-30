"""API router aggregation for v1 endpoints.

This module centralizes all individual endpoint routers into a single
`api_router` that is included by the FastAPI application factory.  Keeping
router wiring in one place prevents circular-import issues and helps mypy
discover the symbols (e.g. `api_router`, `alerts_router`).
"""

from fastapi import APIRouter

# Import individual endpoint routers. Do NOT execute application logic here -
# only import routers to avoid side-effects during module import.
from app.presentation.api.v1.endpoints.audit_logs import router as audit_logs_router
from app.presentation.api.v1.endpoints.biometric_alerts import router as alerts_router

# Public router exported to the application factory
api_router: APIRouter = APIRouter()

# Mount sub-routers. Prefixes/tags are defined at the aggregation point to avoid
# duplication across endpoint modules.
api_router.include_router(alerts_router, prefix="/biometric-alerts", tags=["biometric_alerts"])
api_router.include_router(audit_logs_router, tags=["audit"])
