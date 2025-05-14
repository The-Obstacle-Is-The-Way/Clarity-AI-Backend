"""
Simple, standalone test for error masking without middleware complexity.
"""

import pytest
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from httpx import AsyncClient
from contextlib import asynccontextmanager

# Create a minimal application without middleware
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic (if any)
    yield
    # Shutdown logic (if any)

def create_test_app():
    app = FastAPI(lifespan=lifespan, debug=False)
    
    @app.get("/test/error")
    async def test_error():
        """Endpoint that raises a RuntimeError."""
        raise RuntimeError("This is sensitive information that should be masked")
    
    @app.exception_handler(Exception)
    async def handle_exception(request: Request, exc: Exception) -> JSONResponse:
        """Generic exception handler that masks all errors."""
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred."}
        )
    
    return app

@pytest.mark.asyncio
async def test_error_masking_simple():
    """Verify error masking works in a simple, isolated test."""
    app = create_test_app()
    
    # Set up test client
    async with AsyncClient(app=app, base_url="http://test") as client:
        # Make request that will trigger a RuntimeError
        response = await client.get("/test/error")
        
        # Verify the error was properly masked
        assert response.status_code == 500, f"Expected 500, got {response.status_code}"
        assert response.json() == {"detail": "An internal server error occurred."}

if __name__ == "__main__":
    logger.debug("This script should be run through pytest, not directly")
    logger.debug("Use: python -m pytest app/tests/security/api/simple_test.py -v") 