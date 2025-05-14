"""
Test error masking using FastAPI's TestClient.
"""

import pytest
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

# Create a very simple test app
def create_testclient_app():
    app = FastAPI(debug=False)
    
    @app.get("/error")
    def error_endpoint():
        """Endpoint that raises a RuntimeError."""
        raise RuntimeError("This is sensitive information that should be masked")
    
    @app.exception_handler(Exception)
    def exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Generic exception handler that masks all errors."""
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred."}
        )
    
    return app

def test_error_masking_with_testclient():
    """Verify error masking works properly using TestClient."""
    app = create_testclient_app()
    client = TestClient(app)
    
    # Make request that will trigger a RuntimeError
    response = client.get("/error")
    
    # Verify the error was properly masked
    assert response.status_code == 500
    assert response.json() == {"detail": "An internal server error occurred."}
    assert "This is sensitive information that should be masked" not in response.text 