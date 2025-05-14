"""Direct test of the runtime error endpoint with explicit async handling."""

import asyncio
import sys
import logging
import pytest
from fastapi import FastAPI, Request, status
from fastapi.routing import APIRouter
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from httpx import AsyncClient, ASGITransport

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("direct_endpoint_test")

# Create a minimal test application
def create_test_app():
    """Create a minimal test application with runtime error endpoint."""
    app = FastAPI(debug=False)
    
    # Create a router for test endpoints
    router = APIRouter(prefix="/test-api/test")
    
    @router.get("/runtime-error")
    async def force_runtime_error():
        """Test endpoint that deliberately raises a RuntimeError."""
        logger.debug("Runtime error endpoint called, raising exception")
        raise RuntimeError("This is a sensitive internal error detail that should be masked")
    
    # Register the router
    app.include_router(router)
    
    # Register exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Global exception handler to mask error details."""
        logger.debug(f"Global exception handler called for: {type(exc).__name__}: {str(exc)}")
        
        # Determine appropriate status code
        if isinstance(exc, HTTPException):
            status_code = exc.status_code
            detail = str(exc.detail)
        elif isinstance(exc, RequestValidationError):
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
            detail = str(exc.errors())
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            detail = "An internal server error occurred."
            
        return JSONResponse(
            status_code=status_code,
            content={"detail": detail}
        )
    
    return app

@pytest.mark.asyncio
async def test_runtime_error_endpoint():
    """Test that the runtime error endpoint properly masks sensitive details."""
    logger.debug("Creating test application")
    app = create_test_app()
    
    logger.debug("Creating test client")
    transport = ASGITransport(app=app)
    
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        try:
            # Use timeout to prevent test from hanging
            logger.debug("Sending request to runtime error endpoint")
            response = await asyncio.wait_for(
                client.get("/test-api/test/runtime-error"),
                timeout=5.0
            )
            
            logger.debug(f"Got response: status={response.status_code}, text={response.text}")
            
            # Verify proper error handling
            assert response.status_code == 500, f"Expected 500, got {response.status_code}"
            response_json = response.json()
            assert "detail" in response_json, f"Response missing 'detail' field: {response_json}"
            assert response_json["detail"] == "An internal server error occurred.", \
                   f"Expected generic error message, got: {response_json['detail']}"
            
            # Verify sensitive information is masked
            assert "This is a sensitive internal error detail that should be masked" not in response.text.lower(), \
                   "Sensitive information was leaked in the response"
            assert "traceback" not in response.text.lower(), \
                   "Traceback information was leaked in the response"
            
            logger.debug("Test passed successfully")
            
        except asyncio.TimeoutError:
            logger.error("TEST TIMED OUT - The request is hanging!")
            assert False, "Test timed out - request is hanging"
        except Exception as e:
            logger.error(f"Test failed with: {type(e).__name__}: {e}")
            raise

if __name__ == "__main__":
    logger.debug("This should be run using pytest, not directly")
    logger.debug("Use: python -m pytest app/tests/security/api/direct_endpoint_test.py -v") 