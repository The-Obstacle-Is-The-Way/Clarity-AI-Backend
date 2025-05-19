from abc import ABC, abstractmethod
from typing import Any

from app.domain.entities.user import User


class ITokenService(ABC):
    """Interface for token management services."""

    @abstractmethod
    def generate_tokens(self, user: User) -> dict[str, str]:
        """
        Generate access and refresh tokens for a user.

        Args:
            user: The user entity to generate tokens for

        Returns:
            Dictionary containing access_token and refresh_token
        """
        pass

    @abstractmethod
    def validate_access_token(self, token: str) -> dict[str, Any]:
        """
        Validate an access token and return its payload.

        Args:
            token: The access token to validate

        Returns:
            The decoded token payload
        """
        pass

    @abstractmethod
    def validate_refresh_token(self, token: str) -> dict[str, Any]:
        """
        Validate a refresh token and return its payload.

        Args:
            token: The refresh token to validate

        Returns:
            The decoded token payload
        """
        pass

    @abstractmethod
    def refresh_tokens(self, refresh_token: str, user: User) -> dict[str, str]:
        """
        Generate new access and refresh tokens using a valid refresh token.

        Args:
            refresh_token: The refresh token to validate
            user: The user entity to generate new tokens for

        Returns:
            Dictionary containing new access_token and refresh_token
        """
        pass

    @abstractmethod
    def revoke_token(self, token: str) -> None:
        """
        Revoke (blacklist) a token.

        Args:
            token: The token to revoke
        """
        pass

    @abstractmethod
    def revoke_user_tokens(self, user_id: str) -> None:
        """
        Revoke all tokens for a specific user.

        Args:
            user_id: The ID of the user whose tokens to revoke
        """
        pass

    @abstractmethod
    def get_user_from_token(self, token: str) -> dict[str, Any]:
        """
        Extract and return the user information from a token.

        Args:
            token: The token to extract user information from

        Returns:
            Dictionary containing user information from the token
        """
        pass
