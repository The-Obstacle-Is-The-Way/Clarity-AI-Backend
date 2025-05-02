"""Unit tests for rate limiting dependencies."""
from unittest.mock import MagicMock, patch

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from app.infrastructure.security.rate_limiting.limiter import RateLimiter
from app.presentation.api.dependencies.rate_limiter import (
    RateLimitDependency,
    admin_rate_limit,
    rate_limit,
    sensitive_rate_limit,
)


@pytest.fixture
def mock_limiter():
    """Create a mock rate limiter."""
    limiter = MagicMock(spec=RateLimiter)
    # Default to allowing requests
    limiter.check_rate_limit.return_value = True
    return limiter

@pytest.fixture
def app_with_rate_limited_routes(mock_limiter):
    """Create a FastAPI app with rate-limited routes."""
    app = FastAPI()

    # Create rate limit dependencies with the mock limiter
    basic_rate_limit = RateLimitDependency(requests=10, window_seconds=60, limiter=mock_limiter)
    sensitive_limit = RateLimitDependency(requests=5, window_seconds=60, block_seconds=300, limiter=mock_limiter, scope_key="sensitive")
    admin_limit = RateLimitDependency(requests=100, window_seconds=60, limiter=mock_limiter, scope_key="admin")

    # Define routes with different rate limits
    @app.get("/api/basic")
    async def basic_endpoint(rate_check=Depends(basic_rate_limit)):
        return {"message": "basic"}

    @app.post("/api/sensitive")
    async def sensitive_endpoint(rate_check=Depends(sensitive_limit)):
        return {"message": "sensitive"}

    @app.get("/api/admin")
    async def admin_endpoint(rate_check=Depends(admin_limit)):
        return {"message": "admin"}

    # Test route with factory function
    @app.get("/api/factory")
    @rate_limit(requests=15, window_seconds=30, scope_key="factory")
    async def factory_endpoint(request: Request):
        return {"message": "factory"}

    return TestClient(app)

@pytest.fixture
def client(app_with_rate_limited_routes):
    """Create a test client for the FastAPI app."""
    return app_with_rate_limited_routes

class TestRateLimitDependency:
    """Test suite for the rate limit dependency."""

    def test_init(self):
        """Test initialization of the rate limit dependency."""
        # Test with default values
        dependency = RateLimitDependency()
        assert dependency.requests == 10
        assert dependency.window_seconds == 60
        assert dependency.block_seconds == 300
        assert dependency.scope_key == "default"
        assert dependency.limiter is not None

        # Test with custom values
        custom = RateLimitDependency(requests=5, window_seconds=30, block_seconds=600, scope_key="custom")
        assert custom.requests == 5
        assert custom.window_seconds == 30
        assert custom.block_seconds == 600
        assert custom.scope_key == "custom"

    async def test_default_key_func(self):
        """Test the default key function for extracting client IPs."""
        dependency = RateLimitDependency()

        # Test with X-Forwarded-For header
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"}
        assert dependency._default_key_func(mock_request) == "1.2.3.4"

        # Test with direct client connection
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {}
        mock_request.client = MagicMock()
        mock_request.client.host = "9.10.11.12"
        assert dependency._default_key_func(mock_request) == "9.10.11.12"

        # Test with no client information
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {}
        mock_request.client = None
        assert dependency._default_key_func(mock_request) == "unknown"

    @pytest.mark.asyncio
    async def test_get_rate_limit_key(self):
        """Test getting the rate limit key with scope."""
        dependency = RateLimitDependency(scope_key="test_scope")

        # Mock the key_func to return a fixed value
        dependency.key_func = MagicMock(return_value="test_ip")

        # Create mock request
        mock_request = MagicMock(spec=Request)

        # Get the key
        key = await dependency._get_rate_limit_key(mock_request)

        # Should be the value from key_func
        assert key == "test_ip"

        # Check key_func was called with the request
        dependency.key_func.assert_called_once_with(mock_request)

    @pytest.mark.asyncio
    async def test_call_under_limit(self, mock_limiter):
        """Test the __call__ method when under the rate limit."""
        dependency = RateLimitDependency(limiter=mock_limiter)
        mock_request = MagicMock(spec=Request)

        # Configure limiter to allow the request
        mock_limiter.check_rate_limit.return_value = True

        # Call the dependency
        result = await dependency(mock_request)

        # Should return None when under limit
        assert result is None

        # Check limiter was called
        mock_limiter.check_rate_limit.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_over_limit(self, mock_limiter):
        """Test the __call__ method when over the rate limit."""
        dependency = RateLimitDependency(limiter=mock_limiter, window_seconds=60, error_message="Custom error message")
        mock_request = MagicMock(spec=Request)
        mock_request.url.path = "/test/path"

        # Configure limiter to block the request
        mock_limiter.check_rate_limit.return_value = False

        # Call should raise HTTPException
        with pytest.raises(Exception) as excinfo:
            await dependency(mock_request)

        # Check exception details
        assert "status_code" in str(excinfo.value)
        assert "Custom error message" in str(excinfo.value)

        # Check limiter was called
        mock_limiter.check_rate_limit.assert_called_once()

class TestRateLimitDependencyIntegration:
    """Integration tests for the rate limit dependency with FastAPI."""

    def test_basic_route_allowed(self, client, mock_limiter):
        """Test a basic route that is under the rate limit."""
        # Configure limiter to allow the request
        mock_limiter.check_rate_limit.return_value = True

        # Make request
        response = client.get("/api/basic")

        # Should succeed
        assert response.status_code == 200
        assert response.json() == {"message": "basic"}

        # Check limiter was called with correct parameters
        mock_limiter.check_rate_limit.assert_called_once()
        args, kwargs = mock_limiter.check_rate_limit.call_args
        assert args[0] in ["route:testclient", "127.0.0.1", "testclient"]  # Key varies by test runner
        assert args[1].requests == 10
        assert args[1].window_seconds == 60

    def test_basic_route_blocked(self, client, mock_limiter):
        """Test a basic route that exceeds the rate limit."""
        # Configure limiter to block the request
        mock_limiter.check_rate_limit.return_value = False

        # Make request
        response = client.get("/api/basic")

        # Should be rate limited
        assert response.status_code == 429
        assert "Rate limit exceeded" in response.json()["detail"]

    def test_sensitive_route_uses_scope(self, client, mock_limiter):
        """Test that the sensitive route uses the correct scope key."""
        # Configure limiter to allow the request
        mock_limiter.check_rate_limit.return_value = True

        # Make request
        response = client.post("/api/sensitive")

        # Should succeed
        assert response.status_code == 200

        # Check limiter was called with correct parameters
        args, kwargs = mock_limiter.check_rate_limit.call_args
        assert "sensitive:" in args[0]  # Should have sensitive scope prefix
        assert args[1].requests == 5  # Stricter limit
        assert args[1].block_seconds == 300  # Has blocking configured

    def test_admin_route_uses_higher_limits(self, client, mock_limiter):
        """Test that the admin route uses higher rate limits."""
        # Configure limiter to allow the request
        mock_limiter.check_rate_limit.return_value = True

        # Make request
        response = client.get("/api/admin")

        # Should succeed
        assert response.status_code == 200

        # Check limiter was called with correct parameters
        args, kwargs = mock_limiter.check_rate_limit.call_args
        assert "admin:" in args[0]  # Should have admin scope prefix
        assert args[1].requests == 100  # Higher limit

    def test_factory_route(self, client, mock_limiter):
        """Test route using the factory function."""
        # Configure limiter to allow the request
        mock_limiter.check_rate_limit.return_value = True

        # Make request
        response = client.get("/api/factory")

        # Should succeed
        assert response.status_code == 200

        # Check limiter was called with correct parameters
        args, kwargs = mock_limiter.check_rate_limit.call_args
        assert "factory:" in args[0]  # Should have factory scope prefix
        assert args[1].requests == 15  # Custom limit
        assert args[1].window_seconds == 30  # Custom window

class TestRateLimitFactoryFunctions:
    """Test suite for the rate limit factory functions."""

    @patch("app.presentation.api.dependencies.rate_limiter.RateLimitDependency")
    def test_rate_limit(self, mock_dependency_class):
        """Test the regular rate_limit factory function."""
        # Create a rate limit with factory function
        result = rate_limit(requests=20, window_seconds=40, block_seconds=60, scope_key="test")

        # Verify dependency was created with correct parameters
        mock_dependency_class.assert_called_once_with(requests=20, window_seconds=40, block_seconds=60, scope_key="test")

        # Result should be the created dependency
        assert result == mock_dependency_class.return_value

    @patch("app.presentation.api.dependencies.rate_limiter.RateLimitDependency")
    def test_sensitive_rate_limit(self, mock_dependency_class):
        """Test the sensitive_rate_limit factory function."""
        # Create a sensitive rate limit
        result = sensitive_rate_limit(scope_key="custom")

        # Verify dependency was created with correct parameters
        mock_dependency_class.assert_called_once_with(requests=5, window_seconds=60, block_seconds=300, error_message="Too many attempts. Please try again later.", scope_key="custom")

        # Result should be the created dependency
        assert result == mock_dependency_class.return_value

    @patch("app.presentation.api.dependencies.rate_limiter.RateLimitDependency")
    def test_admin_rate_limit(self, mock_dependency_class):
        """Test the admin_rate_limit factory function."""
        # Create an admin rate limit
        result = admin_rate_limit()

        # Verify dependency was created with correct parameters
        mock_dependency_class.assert_called_once_with(requests=100, window_seconds=60, block_seconds=None, scope_key="admin")

        # Result should be the created dependency
        assert result == mock_dependency_class.return_value

        # Test with custom scope key
        mock_dependency_class.reset_mock()
        result = admin_rate_limit(scope_key="custom_admin")
        mock_dependency_class.assert_called_once_with(requests=100, window_seconds=60, block_seconds=None, scope_key="custom_admin")
