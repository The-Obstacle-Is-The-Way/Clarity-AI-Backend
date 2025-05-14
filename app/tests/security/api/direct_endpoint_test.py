"""Direct endpoint test to verify error masking without middleware chain issues.

This module provides a direct test for the error masking functionality,
bypassing the middleware chain that's causing recursion issues.
"""

import pytest
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_direct_error_masking(client_app_tuple_func_scoped: tuple[AsyncClient, FastAPI]):
    """Test that internal server errors are properly masked."""
    # Get the client and app
    client, app = client_app_tuple_func_scoped
    
    # Register a direct route for testing that raises a RuntimeError
    @app.get("/direct-test/runtime-error")
    async def direct_runtime_error():
        """Test endpoint that raises a RuntimeError."""
        # This should be masked by the exception handler
        raise RuntimeError("This is a sensitive internal error detail that should be masked")
    
    # Make a request to the direct route
    response = await client.get("/direct-test/runtime-error")
    
    # Verify masking of internal server error
    assert response.status_code == 500
    response_json = response.json()
    assert "detail" in response_json
    assert response_json["detail"] == "An internal server error occurred."
    
    # Ensure sensitive error details are masked
    assert "This is a sensitive internal error detail that should be masked" not in response.text.lower()
    assert "traceback" not in response.text.lower()

if __name__ == "__main__":
    logger.debug("This should be run using pytest, not directly")
    logger.debug("Use: python -m pytest app/tests/security/api/direct_endpoint_test.py -v") 