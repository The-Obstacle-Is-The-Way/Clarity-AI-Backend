"""
Biometric Alerts API endpoints V1.

This package contains the router and endpoint definitions for biometric alert rules and events.
"""

from fastapi import APIRouter

router = APIRouter(
    prefix="/biometric-alerts",
    tags=["biometric-alerts"],
)

# TODO: Define actual biometric alert endpoints here
# Example:
# @router.get("/rules")
# async def get_alert_rules():
#     return {"message": "Biometric alert rules endpoint stub"}
