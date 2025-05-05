import logging
from collections.abc import Callable

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse

logger = logging.getLogger(__name__)

class RateLimitExceededError(Exception):
    def __init__(self, detail="Rate limit exceeded", retry_after=60):
        super().__init__(detail)
        self.retry_after = retry_after

class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for enforcing API rate limits.
    
    This middleware tracks and limits the number of requests from clients
    based on configured limits and timeframes to prevent API abuse.
    """
    
    EXCLUDED_PATHS = ["/health", "/metrics"]
    
    def __init__(self, app, limiter=None):
        """
        Initialize the rate limiting middleware.
        
        Args:
            app: The FastAPI application
            limiter: Rate limiter service/component to use for limit enforcement
                 (Expected interface: process_request(request), process_response(response), get_headers())
        """
        super().__init__(app)
        self.limiter = limiter
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and enforce rate limits, skipping excluded paths.
        
        Args:
            request: The incoming HTTP request
            call_next: The next middleware/endpoint in the chain
            
        Returns:
            The HTTP response from downstream handlers or a 429 Too Many Requests
            response if rate limits are exceeded
        """
        if any(request.url.path.startswith(path) for path in self.EXCLUDED_PATHS):
            logger.debug(f"Skipping rate limiting for excluded path: {request.url.path}")
            return await call_next(request)
            
        if not self.limiter:
            logger.warning(f"Rate limiter not configured, passing through request for: {request.url.path}")
            return await call_next(request)

        try:
            logger.debug(f"Processing rate limit check for: {request.url.path}")
            await self.limiter.process_request(request)
            
            response = await call_next(request)
            
            await self.limiter.process_response(response)
            headers = await self.limiter.get_headers()
            if headers:
                logger.debug(f"Adding rate limit headers: {headers}")
                response.headers.update(headers)
            
            return response

        except RateLimitExceededError as e: 
            retry_after = getattr(e, 'retry_after', '60')
            logger.warning(f"Rate limit exceeded for {request.url.path}. Retry after: {retry_after}s")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": str(e) or "Rate limit exceeded"},
                headers={"Retry-After": str(retry_after)}
            )
        except Exception as e:
            logger.error(f"Unexpected error during rate limiting for {request.url.path}: {e}", exc_info=True)
            return await call_next(request) 
