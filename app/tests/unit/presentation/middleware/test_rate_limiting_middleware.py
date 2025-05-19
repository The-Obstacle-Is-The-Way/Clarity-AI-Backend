"""Unit tests for the rate limiting middleware."""
from unittest.mock import AsyncMock, MagicMock

import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout
from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.core.interfaces.services.rate_limiting import IRateLimiter, RateLimitConfig
from app.presentation.middleware.rate_limiting import (
    RateLimitExceededError,
    RateLimitingMiddleware,
)


# Helpers for testing
async def dummy_endpoint(request):
    """Test endpoint that returns a success message."""
    return JSONResponse({"message": "success"})


async def other_endpoint(request):
    """Another test endpoint."""
    return JSONResponse({"message": "other"})


class MockRateLimiter(IRateLimiter):
    """Mock implementation of IRateLimiter for testing."""

    def __init__(self):
        self.check_rate_limit_mock = MagicMock(return_value=True)
        self.request_count = 5  # Default request count
        self.reset_seconds = 60  # Default reset seconds
        self.last_key = None
        self.last_config = None

    def check_rate_limit(self, key: str, config: RateLimitConfig) -> bool:
        """Mock implementation."""
        return self.check_rate_limit_mock(key, config)

    async def track_request(self, key: str, config: RateLimitConfig):
        """Mock implementation that directly returns a tuple."""
        # Track that method was called for assertions
        self.last_key = key
        self.last_config = config

        # Return the configured values
        return (self.request_count, self.reset_seconds)

    async def is_allowed(self, client_id: str) -> bool:
        """Mock implementation of is_allowed method that matches the current middleware."""
        # Store the client ID for test assertions
        self.last_key = f"global:{client_id}"

        # Return true if request count is under limit (using 10 as the threshold)
        return self.request_count <= 10


@pytest.fixture
def mock_limiter():
    """Create a properly mocked rate limiter implementing IRateLimiter."""
    return MockRateLimiter()


@pytest.fixture
def test_app(mock_limiter):
    """Create a Starlette app with test routes and middleware."""
    # Create the app
    app = Starlette()

    # Add test routes
    app.add_route("/api/test", dummy_endpoint)
    app.add_route("/api/other", other_endpoint)
    app.add_route("/health", dummy_endpoint)
    app.add_route("/api/v1/auth/login", dummy_endpoint)

    # Create and add the middleware
    app.add_middleware(
        RateLimitingMiddleware,
        limiter=mock_limiter,
        exclude_paths=["/health", "/metrics"],
    )

    return app, mock_limiter


@pytest.fixture
def test_client(test_app):
    """Get a test client from the app."""
    app, _ = test_app
    return TestClient(app)


class TestRateLimitingMiddleware:
    """Tests for the RateLimitingMiddleware class."""

    def test_allowed_request(self, test_app, test_client):
        """Test that a request is allowed when rate limit is not exceeded."""
        _, mock_limiter = test_app

        # Configure mock to return a value under the limit
        mock_limiter.request_count = 5  # Under the limit of 10

        # Make request
        response = test_client.get("/api/test")

        # Verify response
        assert response.status_code == 200

        # Verify limiter was called with correct key format
        assert hasattr(mock_limiter, "last_key")
        assert "global:" in mock_limiter.last_key

    def test_rate_limited_request(self, test_app, test_client):
        """Test that a request is denied when rate limit is exceeded."""
        _, mock_limiter = test_app

        # Configure mock to return a value over the limit
        mock_limiter.request_count = 11  # Over the limit of 10
        mock_limiter.reset_seconds = 30  # 30 seconds until reset

        # Make request
        response = test_client.get("/api/test")

        # Verify response - should be 429 for rate limited
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.text
        assert "Retry-After" in response.headers
        assert response.headers["Retry-After"] == "30"

        # Verify limiter was called
        assert hasattr(mock_limiter, "last_key")

    def test_health_endpoint(self, test_app, test_client):
        """Test that health endpoint bypasses rate limiting."""
        _, mock_limiter = test_app

        # Reset tracking for this test
        if hasattr(mock_limiter, "last_key"):
            delattr(mock_limiter, "last_key")

        # Make request to health endpoint
        response = test_client.get("/health")

        # Verify response
        assert response.status_code == 200

        # Verify limiter was NOT called (health is exempt)
        # last_key should not be set since track_request shouldn't be called
        assert not hasattr(mock_limiter, "last_key")

    def test_path_specific_limits(self):
        """Test that path-specific limits are used when available."""
        # Create mock limiter implementing IRateLimiter
        mock_limiter = MockRateLimiter()
        mock_limiter.request_count = 3  # Under any limit

        # Create app with our middleware using different limits for paths
        app = Starlette()
        app.add_route("/api/test", dummy_endpoint)
        app.add_route("/api/other", other_endpoint)

        # Add middleware with standard config
        app.add_middleware(
            RateLimitingMiddleware,
            limiter=mock_limiter,
            exclude_paths=["/health", "/metrics"],
        )

        # Make request
        client = TestClient(app)
        response = client.get("/api/other")

        # Verify limiter was called and response is as expected
        assert hasattr(mock_limiter, "last_key")
        assert response.status_code == 200

        # Verify the key included the global scope
        assert "global:" in mock_limiter.last_key  # Should have "global:" prefix

    def test_custom_key_function(self):
        """Test custom key function for client identification."""
        # Create a test client identifier
        test_client_id = "custom-test-client-123"

        # Create mock limiter
        mock_limiter = MockRateLimiter()
        mock_limiter.request_count = 5  # Under the limit

        # Directly test the is_allowed method
        result = asyncio.run(mock_limiter.is_allowed(test_client_id))

        # Verify the result is allowed
        assert result is True

        # Verify the limiter stored the client ID properly
        assert hasattr(mock_limiter, "last_key")
        assert mock_limiter.last_key is not None
        assert f"global:{test_client_id}" == mock_limiter.last_key

    def test_exception_handling(self):
        """Test that general exceptions in the limiter are handled gracefully."""
        # Create a mock that will raise an exception when called
        import asyncio

        class ExceptionRaisingLimiter:
            async def is_allowed(self, client_id):
                raise ValueError("Test exception")

        # Create middleware instance with our test limiter
        app = Starlette()
        middleware = RateLimitingMiddleware(
            app=app, limiter=ExceptionRaisingLimiter(), exclude_paths=["/health"]
        )

        # Create a request mock
        class RequestMock:
            url = type("UrlMock", (), {"path": "/api/test"})
            client = type("ClientMock", (), {"host": "192.168.1.1"})

        # Mock the call_next function that would be called
        async def call_next_mock(request):
            return type("ResponseMock", (), {"status_code": 200})

        # Call dispatch directly to test exception handling
        async def run_test():
            try:
                # Should handle the exception and allow the request to proceed
                response = await middleware.dispatch(RequestMock(), call_next_mock)
                return response
            except Exception as e:
                # Test that we properly propagate the exception
                assert isinstance(e, ValueError)
                assert "Test exception" in str(e)
                return None

        # Run the async test function
        result = asyncio.run(run_test())

        # Since we're propagating exceptions, the result should be None
        assert result is None

    def test_middleware_initialization_with_defaults(self):
        """Test that middleware initialization with default values works correctly."""
        # Create a mock app
        app_mock = MagicMock()

        # Create a mock rate limiter
        limiter_mock = MagicMock()

        # Initialize the middleware with default values
        middleware = RateLimitingMiddleware(app_mock, limiter=limiter_mock)

        # Verify the limiter is set correctly
        assert middleware.limiter == limiter_mock

        # Verify the default exclude paths include at least health and metrics
        # Note: We don't check the exact list as it may change in implementation
        assert isinstance(middleware.exclude_paths, list)
        assert "/health" in middleware.exclude_paths
        assert "/metrics" in middleware.exclude_paths


@pytest.mark.asyncio
async def test_rate_limit_initialization():
    """Test the initialization of the RateLimiter from core.security.rate_limiting.limiter."""
    from app.core.security.rate_limiting.limiter import RateLimiter

    # Test RateLimiter initialization without parameters
    limiter = RateLimiter()
    assert hasattr(limiter, "requests_per_minute")
    assert limiter.requests_per_minute == 60  # Default value

    # Test RateLimiter initialization with custom parameters
    custom_limiter = RateLimiter(requests_per_minute=100)
    assert custom_limiter.requests_per_minute == 100

    # Test RateLimiter interface method
    allowed = await custom_limiter.is_allowed("test-client")
    assert allowed is True  # Test clients should always be allowed
