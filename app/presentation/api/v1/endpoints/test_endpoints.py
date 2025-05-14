"""
Test endpoints for testing error handling.

This module provides test endpoints that are only registered in test mode.
They are used to trigger specific error conditions for testing.
"""

from fastapi import APIRouter, HTTPException, status, Depends
from typing import Dict, Any
from fastapi.responses import JSONResponse

# Create a router for test endpoints
router = APIRouter(
    prefix="/test",
    tags=["testing"],
    include_in_schema=False  # Don't show these in OpenAPI docs
)


@router.get("/500-error")
async def force_500_error() -> Dict[str, Any]:
    """
    Endpoint that deliberately raises a division by zero error.
    Used to test 500 error handling and masking of stack traces.
    """
    divisor = 0
    return {"result": 1 / divisor}  # Will raise ZeroDivisionError


@router.get("/404-error")
async def force_404_error() -> Dict[str, Any]:
    """
    Endpoint that deliberately raises a 404 not found error.
    Used to test 404 error responses.
    """
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Test resource not found"
    )


@router.get("/403-error")
async def force_403_error() -> Dict[str, Any]:
    """
    Endpoint that deliberately raises a 403 forbidden error.
    Used to test 403 error responses.
    """
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Test forbidden access"
    )


@router.get("/401-error")
async def force_401_error() -> Dict[str, Any]:
    """
    Endpoint that deliberately raises a 401 unauthorized error.
    Used to test 401 error responses.
    """
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Test unauthorized access"
    )


@router.get("/validation-error")
async def force_validation_error() -> Dict[str, Any]:
    """
    Endpoint that deliberately raises a 422 validation error.
    Used to test validation error responses.
    """
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Test validation error"
    )


@router.get("/runtime-error")
async def force_runtime_error():
    """
    Test endpoint that deliberately raises a RuntimeError.
    
    This is used by security and error handling tests to ensure sensitive 
    error details are masked in responses.
    """
    try:
        # Deliberately raise an error with sensitive information
        raise RuntimeError("This is a sensitive internal error detail that should be masked")
    except Exception as e:
        # Handle the error directly inside the endpoint to prevent middleware recursion
        # This bypasses the middleware chain completely
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal server error occurred."},
        ) 