"""
Biometric API endpoints V1.

This package contains the router and endpoint definitions for biometric data.
"""

from fastapi import APIRouter

router = APIRouter(
    prefix="/biometric",
    tags=["biometric"],
)

# TODO: Define actual biometric endpoints here
# Example:
# @router.get("/data")
# async def get_biometric_data():
#     return {"message": "Biometric data endpoint stub"}
