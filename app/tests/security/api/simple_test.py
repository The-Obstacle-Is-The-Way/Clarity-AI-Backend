"""Simple direct test of the API endpoint to identify the hanging issue."""

import asyncio
import sys
import logging
import pytest
from httpx import AsyncClient
from fastapi import FastAPI
from fastapi.responses import JSONResponse

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("simple_test")

# Create a minimal FastAPI app with a test endpoint
app = FastAPI(debug=False)

@app.get("/test-error")
async def test_runtime_error():
    """Endpoint that deliberately raises a RuntimeError."""
    logger.debug("Test endpoint called, raising error")
    raise RuntimeError("Simple test error that should be masked")

@app.exception_handler(RuntimeError)
async def runtime_error_handler(request, exc):
    """Custom exception handler for RuntimeError."""
    logger.debug(f"Exception handler called for: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred."}
    )

@pytest.mark.asyncio
async def test_simple_error_endpoint():
    """Test that a basic endpoint with error works correctly."""
    logger.debug("Starting simple error endpoint test")
    
    # Create test client
    async with AsyncClient(app=app, base_url="http://test") as client:
        try:
            # Set timeout to prevent test from hanging
            logger.debug("Sending request to test endpoint")
            response = await asyncio.wait_for(
                client.get("/test-error"),
                timeout=5.0
            )
            
            logger.debug(f"Got response: {response.status_code}")
            logger.debug(f"Response text: {response.text}")
            
            # Check basic error response
            assert response.status_code == 500
            response_json = response.json()
            assert "detail" in response_json
            assert response_json["detail"] == "An internal server error occurred."
            logger.debug("Test passed successfully")
            
        except asyncio.TimeoutError:
            logger.error("TEST TIMED OUT - The request is hanging!")
            assert False, "Test timed out - request hanging"
        except Exception as e:
            logger.error(f"Test failed with: {type(e).__name__}: {e}")
            raise

if __name__ == "__main__":
    logger.debug("This script should be run through pytest, not directly")
    logger.debug("Use: python -m pytest app/tests/security/api/simple_test.py -v") 