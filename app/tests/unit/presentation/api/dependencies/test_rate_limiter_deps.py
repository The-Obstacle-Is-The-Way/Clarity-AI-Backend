"""Unit tests for rate limiting dependencies."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.core.interfaces.services.rate_limiting import IRateLimiter, RateLimitConfig
from app.presentation.api.dependencies.rate_limiter_deps import (
    RateLimitDependency,
    admin_rate_limit,
    rate_limit,
    sensitive_rate_limit,
)


class MockRateLimiter(IRateLimiter):
    """Mock implementation of IRateLimiter for testing."""
    
    def __init__(self):
        self.check_rate_limit = MagicMock(return_value=True)
        self.track_request = AsyncMock(return_value=(1, 60))
    
    def check_rate_limit(self, key: str, config: RateLimitConfig) -> bool:
        """Mock implementation."""
        return True
    
    async def track_request(self, key: str, config: RateLimitConfig):
        """Mock implementation."""
        return 1, 60


@pytest.fixture
def mock_limiter():
    """Create a mock rate limiter."""
    return MockRateLimiter()


@pytest.fixture
def app_with_rate_limited_routes(mock_limiter):
    """Create a FastAPI app with rate-limited routes."""
    app = FastAPI()

    # Create rate limit dependencies with the mock limiter
    basic_rate_limit = RateLimitDependency(
        requests=10, 
        window_seconds=60, 
        limiter=mock_limiter
    )
    
    sensitive_limit = RateLimitDependency(
        requests=5, 
        window_seconds=60, 
        block_seconds=300, 
        scope_key="sensitive", 
        limiter=mock_limiter
    )
    
    admin_limit = RateLimitDependency(
        requests=100, 
        window_seconds=60, 
        scope_key="admin", 
        limiter=mock_limiter
    )

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
    async def factory_endpoint(rate_check=Depends(rate_limit(requests=15, window_seconds=30))):
        return {"message": "factory"}

    return app  # Return the FastAPI app directly instead of a TestClient


@pytest.fixture
async def client(app_with_rate_limited_routes):
    """Create a test client for the FastAPI app."""
    async with AsyncClient(app=app_with_rate_limited_routes, base_url="http://testserver") as async_client:
        yield async_client


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
        assert dependency.limiter is None

        # Test with custom values
        custom = RateLimitDependency(
            requests=5, 
            window_seconds=30, 
            block_seconds=600, 
            scope_key="custom"
        )
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

        # Should be the value from key_func with scope prefix
        assert key == "test_scope:test_ip"

        # Check key_func was called with the request
        dependency.key_func.assert_called_once_with(mock_request)

    @pytest.mark.asyncio
    async def test_call_under_limit(self, mock_limiter):
        """Test the __call__ method when under the rate limit."""
        dependency = RateLimitDependency(limiter=mock_limiter)
        mock_request = MagicMock(spec=Request)

        # Configure limiter to return below limit
        mock_limiter.track_request.return_value = (5, 60)  # 5 requests, 60 seconds left

        # Call the dependency
        result = await dependency(mock_request)

        # Should return None when under limit
        assert result is None

        # Check limiter was called
        mock_limiter.track_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_over_limit(self, mock_limiter):
        """Test the __call__ method when over the rate limit."""
        dependency = RateLimitDependency(
            limiter=mock_limiter, 
            window_seconds=60, 
            error_message="Custom error message"
        )
        mock_request = MagicMock(spec=Request)
        mock_request.url.path = "/test/path"

        # Configure limiter to return over limit
        mock_limiter.track_request.return_value = (11, 30)  # 11 requests, 30 seconds left

        # Call should raise HTTPException
        with pytest.raises(Exception) as excinfo:
            await dependency(mock_request)

        # Check exception details
        assert "429" in str(excinfo.value) or "Too Many Requests" in str(excinfo.value)
        assert "Custom error message" in str(excinfo.value)

        # Check limiter was called
        mock_limiter.track_request.assert_called_once()


class TestRateLimitDependencyIntegration:
    """Integration tests for the rate limit dependency with FastAPI."""

    @pytest.mark.asyncio
    async def test_basic_route_allowed(self, client, mock_limiter):
        """Test a basic route that is under the rate limit."""
        # Configure limiter to return under limit
        mock_limiter.track_request.return_value = (5, 60)  # 5 requests, 60 seconds left

        # Make request
        response = await client.get("/api/basic")

        # Should succeed
        assert response.status_code == 200
        assert response.json() == {"message": "basic"}

        # Check limiter was called
        assert mock_limiter.track_request.called

    @pytest.mark.asyncio
    async def test_basic_route_blocked(self, client, mock_limiter):
        """Test a basic route that exceeds the rate limit."""
        # Configure limiter to return over limit
        mock_limiter.track_request.return_value = (11, 30)  # 11 requests, 30 seconds left

        # Make request
        response = await client.get("/api/basic")

        # Should be rate limited
        assert response.status_code == 429
        assert "exceeded" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_sensitive_route_uses_scope(self, client, mock_limiter):
        """Test that the sensitive route uses the correct scope key."""
        # Make request
        await client.post("/api/sensitive")

        # Get the key used in limiter.track_request
        args, _ = mock_limiter.track_request.call_args
        key = args[0]
        
        # Verify correct scope was used
        assert "sensitive:" in key

    @pytest.mark.asyncio
    async def test_admin_route_uses_higher_limits(self, client, mock_limiter):
        """Test that the admin route uses higher rate limits."""
        # Make request
        await client.get("/api/admin")

        # Get the config passed to limiter.track_request
        call_args = mock_limiter.track_request.call_args
        args = call_args[0] if call_args and len(call_args) > 0 else ()
        kwargs = call_args[1] if call_args and len(call_args) > 1 else {}
        
        config = kwargs.get('config', args[1] if len(args) > 1 else None)
        
        # Verify higher limits
        assert config.requests == 100

    @pytest.mark.asyncio
    async def test_factory_route(self, client, mock_limiter):
        """Test a route using the factory function."""
        # Make request
        response = await client.get("/api/factory")

        # Verify limiter was called
        # For AsyncMock we need to wait for it to be called
        assert mock_limiter.track_request.called or mock_limiter.track_request.await_count > 0


@pytest.fixture
def mock_dependency_class():
    """Create a mock for the dependency class."""
    with patch('app.presentation.api.dependencies.rate_limiter_deps.RateLimitDependency') as mock:
        yield mock


class TestRateLimitFactoryFunctions:
    """Test suite for the rate limit factory functions."""

    def test_rate_limit(self, mock_dependency_class):
        """Test the regular rate_limit factory function."""
        # Call the factory with custom parameters
        rate_limit(requests=15, window_seconds=45, block_seconds=400, scope_key="test")
        
        # Verify dependency was created with correct parameters
        mock_dependency_class.assert_called_once_with(
            requests=15,
            window_seconds=45,
            block_seconds=400,
            scope_key="test",
            error_message="Rate limit exceeded. Please try again later."
        )

    def test_sensitive_rate_limit(self, mock_dependency_class):
        """Test the sensitive_rate_limit factory function."""
        # Call the factory with custom parameters
        sensitive_rate_limit(requests=3, window_seconds=30)
        
        # Verify dependency was created with correct parameters
        mock_dependency_class.assert_called_once_with(
            requests=3,
            window_seconds=30,
            block_seconds=600,
            scope_key="sensitive",
            error_message="Rate limit exceeded for sensitive operation. Please try again later."
        )

    def test_admin_rate_limit(self, mock_dependency_class):
        """Test the admin_rate_limit factory function."""
        # Call the factory with default parameters
        admin_rate_limit()
        
        # Verify dependency was created with correct parameters
        mock_dependency_class.assert_called_once_with(
            requests=100,
            window_seconds=60,
            block_seconds=300,
            scope_key="admin",
            error_message="Admin rate limit exceeded. Please try again later."
        )