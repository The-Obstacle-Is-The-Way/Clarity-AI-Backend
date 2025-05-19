"""
Rate Limiter Service Definition.

Contains the interface or concrete implementation for the rate limiting service.
"""

from abc import ABC, abstractmethod

from fastapi import Request

# Placeholder - In a real implementation, this might depend on Redis, etc.


class RateLimiterService(ABC):
    """Abstract base class for a rate limiter service."""

    @abstractmethod
    async def is_allowed(self, identifier: str) -> bool:
        """
        Check if a request from the given identifier is allowed.

        Args:
            identifier: Unique key identifying the request source (e.g., IP, user_id).

        Returns:
            True if the request is allowed, False otherwise.
        """
        pass

    @abstractmethod
    async def check_rate_limit(self, request: Request) -> bool:
        """
        Check if the request is within rate limits.

        Args:
            request: The incoming HTTP request

        Returns:
            True if the request is allowed, False if rate limited
        """
        pass


# Placeholder implementation/factory
# TODO: Replace with actual implementation (e.g., using Redis)
class InMemoryRateLimiter(RateLimiterService):
    """Simple in-memory rate limiter (for demonstration/testing)."""

    async def is_allowed(self, identifier: str) -> bool:
        # Basic placeholder - allows all requests
        print(
            f"Warning: Using placeholder InMemoryRateLimiter for {identifier}. Allowing request."
        )
        return True

    async def check_rate_limit(self, request: Request) -> bool:
        """
        Check if the request is within rate limits.

        In this simplified implementation, we always allow requests.

        Args:
            request: The incoming HTTP request

        Returns:
            True, always allowing requests
        """
        # In test environments, always allow requests
        client_ip = request.client.host if request.client else "unknown"
        return await self.is_allowed(client_ip)


def get_rate_limiter_service() -> RateLimiterService:
    """
    Dependency provider/factory for the rate limiter service.

    Returns:
        An instance of the configured RateLimiterService.
    """
    # TODO: Add logic to instantiate the correct service based on config
    # For now, return the placeholder implementation.
    return InMemoryRateLimiter()


__all__ = ["RateLimiterService", "get_rate_limiter_service"]
