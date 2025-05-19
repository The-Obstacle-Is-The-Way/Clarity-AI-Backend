"""
Integration tests for the middleware chain.

These tests verify that all middleware components work together properly in sequence,
focusing on the request ID middleware which doesn't require database setup.
"""

import pytest
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.testclient import TestClient
import uuid
from unittest.mock import patch, MagicMock

from app.core.config.settings import get_settings
from app.presentation.middleware.request_id import RequestIdMiddleware


# Create a simple test app for middleware testing
def create_test_app():
    """Create a minimal test application with our middleware for testing."""
    app = FastAPI()

    # Add a health endpoint
    @app.get("/health")
    def health():
        return {"status": "ok"}

    # Add a protected endpoint
    @app.get("/api/v1/users/me")
    def get_current_user(request: Request):
        # This endpoint would normally require authentication
        # For testing, we'll check for a test auth header
        if "X-Test-Auth-Bypass" in request.headers:
            return {"id": "test-user-id", "email": "test@example.com"}
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Add middlewares in the correct order
    app.add_middleware(RequestIdMiddleware)

    # Note: We're not adding the full AuthenticationMiddleware since it requires
    # database setup, but our tests can still verify the request ID functionality

    return app


@pytest.fixture
def test_client():
    """Create a TestClient with our minimal test application."""
    app = create_test_app()
    with TestClient(app) as client:
        yield client


class TestMiddlewareChain:
    """Tests for the middleware chain integration."""

    def test_request_id_propagation(self, test_client):
        """Test that RequestIdMiddleware generates and propagates request IDs."""
        # Make a request with no Request-ID header
        response = test_client.get("/health")
        assert response.status_code == 200

        # Response should include an X-Request-ID header
        assert "X-Request-ID" in response.headers
        request_id = response.headers["X-Request-ID"]
        assert uuid.UUID(request_id)  # Should be a valid UUID

        # Make another request with the same Request-ID
        response2 = test_client.get("/health", headers={"X-Request-ID": request_id})
        assert response2.status_code == 200
        assert response2.headers["X-Request-ID"] == request_id

    @patch("app.presentation.middleware.request_id.uuid.uuid4")
    def test_middleware_with_mocked_uuid(self, mock_uuid, test_client):
        """Test middleware with a mocked UUID for predictable testing."""
        # Mock UUID generation to have a predictable request ID
        test_uuid = uuid.UUID("12345678-1234-5678-1234-567812345678")
        mock_uuid.return_value = test_uuid

        # Make request to endpoint
        response = test_client.get("/health")

        # Verify request ID was generated and propagated
        assert "X-Request-ID" in response.headers
        assert response.headers["X-Request-ID"] == str(test_uuid)
        assert response.status_code == 200

    def test_authentication_behavior(self, test_client):
        """Test authentication-like behavior with our simplified setup."""
        # Without auth headers
        response = test_client.get("/api/v1/users/me")
        assert response.status_code == 401

        # With test auth headers
        auth_headers = {
            "X-Test-Auth-Bypass": "ADMIN:00000000-0000-0000-0000-000000000001"
        }
        response = test_client.get("/api/v1/users/me", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["id"] == "test-user-id"
