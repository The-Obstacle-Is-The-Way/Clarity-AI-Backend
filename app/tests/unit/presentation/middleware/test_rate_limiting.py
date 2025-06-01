"""
Unit tests for RateLimitingMiddleware.

Tests the rate limiting middleware's ability to limit requests
and handle excluded paths properly.
"""
import pytest
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.middleware import Middleware

from app.core.security.rate_limiting.service import RateLimiterService
from app.presentation.middleware.rate_limiting import RateLimitingMiddleware


class MockRateLimiter(RateLimiterService):
    """Mock rate limiter that can be configured to allow or deny requests."""

    def __init__(self, allow_requests=True):
        self.allow_requests = allow_requests
        self.process_called = False
        self.check_called = False

    async def is_allowed(self, identifier: str) -> bool:
        """
        Return configured allow_requests value.
        
        Args:
            identifier: Unique key identifying the request source
            
        Returns:
            True if allow_requests is True, False otherwise
        """
        return self.allow_requests

    async def check_rate_limit(self, request: Request) -> bool:
        """
        Check if request is allowed based on configured value.
        
        Args:
            request: The incoming HTTP request
            
        Returns:
            True if allow_requests is True, False otherwise
        """
        self.check_called = True
        return self.allow_requests
        
    async def process_request(self, request: Request) -> bool:
        """
        Process the request and update internal state.
        
        Args:
            request: The incoming HTTP request
            
        Returns:
            True if allow_requests is True, False otherwise
        """
        self.process_called = True
        return self.allow_requests


@pytest.fixture
def app_with_rate_limiting_allowed():
    """
    Create a test FastAPI app with rate limiting middleware that allows requests.
    
    Returns:
        FastAPI app configured with rate limiting middleware and the rate limiter instance
    """
    app = FastAPI()
    
    # Setup rate limiter with configured behavior
    rate_limiter = MockRateLimiter(allow_requests=True)
    
    # Add middleware with optional path exclusions
    app.add_middleware(
        RateLimitingMiddleware,
        limiter=rate_limiter,
        exclude_paths=[],
    )
    
    # Add test routes
    @app.get("/")
    async def root():
        return {"message": "Hello World"}
        
    @app.get("/health")
    async def health():
        return {"status": "ok"}
    
    @app.get("/error")
    async def error():
        # Test exception handling in middleware
        raise ValueError("Test error")
    
    return app, rate_limiter


@pytest.fixture
def app_with_rate_limiting_blocked():
    """
    Create a test FastAPI app with rate limiting middleware that blocks requests.
    
    Returns:
        FastAPI app configured with rate limiting middleware and the rate limiter instance
    """
    app = FastAPI()
    
    # Setup rate limiter with configured behavior
    rate_limiter = MockRateLimiter(allow_requests=False)
    
    # Add middleware with optional path exclusions
    app.add_middleware(
        RateLimitingMiddleware,
        limiter=rate_limiter,
        exclude_paths=[],
    )
    
    # Add test routes
    @app.get("/")
    async def root():
        return {"message": "Hello World"}
        
    @app.get("/health")
    async def health():
        return {"status": "ok"}
    
    @app.get("/error")
    async def error():
        # Test exception handling in middleware
        raise ValueError("Test error")
    
    return app, rate_limiter


@pytest.fixture
def app_with_excluded_paths():
    """
    Create a test FastAPI app with rate limiting middleware that blocks requests
    but excludes certain paths.
    
    Returns:
        FastAPI app configured with rate limiting middleware and the rate limiter instance
    """
    app = FastAPI()
    
    # Setup rate limiter with configured behavior
    rate_limiter = MockRateLimiter(allow_requests=False)
    
    # Add middleware with path exclusions
    app.add_middleware(
        RateLimitingMiddleware,
        limiter=rate_limiter,
        exclude_paths=["/health"],
    )
    
    # Add test routes
    @app.get("/")
    async def root():
        return {"message": "Hello World"}
        
    @app.get("/health")
    async def health():
        return {"status": "ok"}
    
    return app, rate_limiter


def test_rate_limiting_allowed(app_with_rate_limiting_allowed):
    """Test that requests are allowed when limiter allows them."""
    app, rate_limiter = app_with_rate_limiting_allowed
    client = TestClient(app)
    
    response = client.get("/")
    
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World"}
    assert rate_limiter.check_called  # Ensure check method was called


def test_rate_limiting_blocked(app_with_rate_limiting_blocked):
    """Test that requests are blocked when limiter denies them."""
    app, rate_limiter = app_with_rate_limiting_blocked
    client = TestClient(app)
    
    response = client.get("/")
    
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["detail"]
    assert "Retry-After" in response.headers
    assert rate_limiter.check_called  # Ensure check method was called


def test_rate_limiting_excluded_path(app_with_excluded_paths):
    """Test that excluded paths bypass rate limiting."""
    app, rate_limiter = app_with_excluded_paths
    client = TestClient(app)
    
    # This path should be rate limited
    response = client.get("/")
    assert response.status_code == 429
    
    # This path should bypass rate limiting
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_rate_limiting_exception_handling(app_with_rate_limiting_allowed):
    """Test that middleware properly handles exceptions in the request chain."""
    app, rate_limiter = app_with_rate_limiting_allowed
    client = TestClient(app)
    
    # TestClient raises the exception rather than returning a 500 status code
    # This verifies that the middleware correctly propagates exceptions
    with pytest.raises(ValueError, match="Test error"):
        client.get("/error")
        
    # Verify the rate limiter was called before the exception
    assert rate_limiter.check_called
