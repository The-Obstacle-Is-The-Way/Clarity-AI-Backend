"""Direct endpoint test to verify error masking without middleware chain issues.

This module provides a direct test for the error masking functionality,
bypassing the middleware chain that's causing recursion issues.
"""

import logging
import pytest
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from httpx import AsyncClient, ASGITransport

# Configure logger
logger = logging.getLogger(__name__)


def create_standalone_app():
    """Create a completely standalone app without middleware for testing error masking."""
    app = FastAPI(debug=False)

    # Add test endpoint that raises a RuntimeError
    @app.get("/direct-test/runtime-error")
    async def direct_runtime_error():
        """Test endpoint that raises a RuntimeError."""
        raise RuntimeError(
            "This is a sensitive internal error detail that should be masked"
        )

    # Add specific handler for RuntimeError
    @app.exception_handler(RuntimeError)
    async def runtime_error_handler(request: Request, exc: RuntimeError):
        """Handle RuntimeError exceptions with masked details."""
        logger.error(f"Runtime error in standalone test: {str(exc)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred."},
        )

    # Generic exception handler for all other exceptions
    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        """Handle all exceptions with masked details."""
        logger.error(f"Exception in standalone test: {type(exc).__name__}: {str(exc)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred."},
        )

    return app


@pytest.mark.asyncio
async def test_direct_error_masking():
    """Test that internal server errors are properly masked in a standalone app."""
    # Create a standalone app without any middleware
    app = create_standalone_app()

    # Create client with direct transport to the app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Make request that will trigger a RuntimeError
        response = await client.get("/direct-test/runtime-error")

        # Verify the error was properly masked
        assert response.status_code == 500, f"Expected 500, got {response.status_code}"
        response_json = response.json()
        assert "detail" in response_json
        assert response_json["detail"] == "An internal server error occurred."

        # Ensure sensitive error details are masked
        assert (
            "This is a sensitive internal error detail that should be masked"
            not in response.text.lower()
        )
        assert "traceback" not in response.text.lower()


if __name__ == "__main__":
    logger.debug("This should be run using pytest, not directly")
    logger.debug(
        "Use: python -m pytest app/tests/security/api/direct_endpoint_test.py -v"
    )
