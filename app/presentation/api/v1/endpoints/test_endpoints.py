"""
Test endpoints for testing error handling.

This module provides test endpoints that are only registered in test mode.
They are used to trigger specific error conditions for testing.
"""

from typing import Any, NoReturn

from fastapi import APIRouter, HTTPException, status

# Create a router for test endpoints
router = APIRouter(
    prefix="/test",
    tags=["testing"],
    include_in_schema=False,  # Don't show these in OpenAPI docs
)


@router.get("/500-error")
async def force_500_error():
    """
    Test endpoint that deliberately raises a ZeroDivisionError.

    This is an alternate error endpoint that raises a different exception
    for testing error masking and handling.
    """
    # Deliberately divide by zero to raise error
    _ = 1 / 0  # ZeroDivisionError
    # This line is never reached
    return {"message": "This should never be returned"}


@router.get("/404-error")
async def force_404_error() -> dict[str, Any]:
    """
    Endpoint that deliberately raises a 404 not found error.
    Used to test 404 error responses.
    """
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Test resource not found")


@router.get("/403-error")
async def force_403_error() -> dict[str, Any]:
    """
    Endpoint that deliberately raises a 403 forbidden error.
    Used to test 403 error responses.
    """
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Test forbidden access")


@router.get("/401-error")
async def force_401_error() -> dict[str, Any]:
    """
    Endpoint that deliberately raises a 401 unauthorized error.
    Used to test 401 error responses.
    """
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Test unauthorized access")


@router.get("/validation-error")
async def force_validation_error() -> dict[str, Any]:
    """
    Endpoint that deliberately raises a 422 validation error.
    Used to test validation error responses.
    """
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Test validation error"
    )


@router.get("/hello")
async def test_hello():
    """Simple hello endpoint for tests."""
    return {"message": "Hello from test API"}


@router.get("/error")
async def test_error() -> NoReturn:
    """Test endpoint that raises an HTTP exception."""
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Test error")


@router.get("/runtime-error")
async def test_runtime_error() -> NoReturn:
    """Test endpoint that raises a RuntimeError with sensitive information that should be masked."""
    raise RuntimeError("This is a sensitive internal error detail that should be masked")


@router.get("/value-error")
async def test_value_error() -> NoReturn:
    """Test endpoint that raises a ValueError."""
    raise ValueError("This is a test ValueError")
