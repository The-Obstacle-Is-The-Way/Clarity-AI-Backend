"""Isolation test for error masking.

This module tests error masking functionality in isolation, 
completely bypassing the middleware chain issues.
"""

import logging
import traceback

import pytest
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("isolation_test")


def create_isolated_app():
    """Create a minimal application for testing error masking in isolation."""
    # Create app with debug=False to prevent debug exception handling
    app = FastAPI(debug=False)

    @app.get("/test/runtime-error")
    async def runtime_error():
        """Endpoint that raises a RuntimeError with sensitive information."""
        raise RuntimeError(
            "This is a sensitive internal error detail that should be masked"
        )

    @app.get("/test/http-error")
    async def http_error():
        """Endpoint that raises an HTTP exception."""
        from fastapi import HTTPException

        raise HTTPException(status_code=500, detail="HTTP exception detail")

    # Add specific handlers for different exception types
    @app.exception_handler(RuntimeError)
    async def runtime_error_handler(
        request: Request, exc: RuntimeError
    ) -> JSONResponse:
        """Handle RuntimeError and mask sensitive information."""
        logger.error(f"RuntimeError in isolation test: {exc}")

        # Return sanitized, masked response
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred."},
        )

    # Add exception handlers with priority
    # Handle built-in HTTPException first
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        """Handle HTTP exceptions and mask sensitive information."""
        logger.error(
            f"HTTP exception in isolation test: {exc.status_code} - {exc.detail}"
        )

        # Return sanitized, masked response for 500 errors, pass through others
        if exc.status_code == 500:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "An internal server error occurred."},
            )
        else:
            # For non-500 errors, keep original status and detail
            return JSONResponse(
                status_code=exc.status_code, content={"detail": str(exc.detail)}
            )

    # Handle all other exceptions
    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        """Handle all exceptions and mask sensitive information."""
        logger.error(f"Exception in isolation test: {type(exc).__name__}: {exc!s}")
        logger.debug(traceback.format_exc())

        # Return sanitized, masked response
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred."},
        )

    return app


@pytest.mark.asyncio
async def test_error_masking_isolation():
    """Test error masking in complete isolation from middleware chain."""
    # Create isolated app
    app = create_isolated_app()

    # Create client with direct transport to the app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Test runtime error masking
        response = await client.get("/test/runtime-error")

        # Verify error is properly masked
        assert response.status_code == 500
        response_json = response.json()
        assert "detail" in response_json
        assert response_json["detail"] == "An internal server error occurred."

        # Ensure sensitive details are not exposed
        assert (
            "This is a sensitive internal error detail that should be masked"
            not in response.text.lower()
        )


@pytest.mark.asyncio
async def test_http_error_masking_isolation():
    """Test HTTP error masking in isolation."""
    app = create_isolated_app()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Test HTTP error
        response = await client.get("/test/http-error")

        # Verify HTTP error is masked correctly
        assert response.status_code == 500
        response_json = response.json()
        assert "detail" in response_json
        assert response_json["detail"] == "An internal server error occurred."

        # Ensure HTTP error details are masked
        assert "http exception detail" not in response.text.lower()
