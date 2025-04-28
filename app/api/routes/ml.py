"""Compatibility stub for verify_api_key used in integration tests."""
from fastapi import HTTPException, status
import asyncio

async def verify_api_key():
    """
    Stub verify_api_key for integration test compatibility.
    Actual authentication is handled by middleware.
    """
    return True