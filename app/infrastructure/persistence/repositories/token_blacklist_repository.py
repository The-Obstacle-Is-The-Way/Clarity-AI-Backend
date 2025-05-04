"""
Token Blacklist Repository Implementation.

This module provides a repository for managing blacklisted tokens.
"""

from datetime import datetime

from app.domain.exceptions.repository import RepositoryException
from app.domain.interfaces.token_repository import ITokenRepository
from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)


class TokenBlacklistRepository(ITokenRepository):
    """
    Repository implementation for managing blacklisted tokens.
    
    This implementation uses in-memory storage for development/testing.
    For production, this should be replaced with a Redis or database implementation.
    """

    def __init__(self):
        """Initialize the token blacklist repository."""
        # In-memory storage for blacklisted tokens
        # Structure: {token: expiry_datetime}
        self._token_blacklist: dict[str, datetime] = {}
        
        # User token mapping for quick revocation of all user tokens
        # Structure: {user_id: set(tokens)}
        self._user_tokens: dict[str, set[str]] = {}
        
        # Session token mapping for quick revocation of all session tokens
        # Structure: {session_id: set(tokens)}
        self._session_tokens: dict[str, set[str]] = {}
        
        logger.info("TokenBlacklistRepository initialized")

    async def blacklist_token(self, token: str, expires_at: datetime) -> None:
        """
        Add a token to the blacklist.

        Args:
            token: The token to blacklist
            expires_at: When the token expires

        Raises:
            RepositoryException: If the operation fails
        """
        try:
            self._token_blacklist[token] = expires_at
            logger.debug(f"Token blacklisted until {expires_at.isoformat()}")
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e!s}")
            raise RepositoryException(f"Failed to blacklist token: {e!s}")

    async def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token: The token to check

        Returns:
            True if blacklisted, False otherwise

        Raises:
            RepositoryException: If the operation fails
        """
        try:
            # Check if token is in the blacklist
            if token not in self._token_blacklist:
                return False
                
            # Check if token has expired from the blacklist
            if self._token_blacklist[token] < datetime.utcnow():
                # Clean up expired token
                del self._token_blacklist[token]
                return False
                
            return True
        except Exception as e:
            logger.error(f"Failed to check token blacklist: {e!s}")
            raise RepositoryException(f"Failed to check token blacklist: {e!s}")

    async def blacklist_user_tokens(self, user_id: str) -> None:
        """
        Blacklist all tokens for a specific user.

        Args:
            user_id: The user identifier

        Raises:
            RepositoryException: If the operation fails
        """
        try:
            # Add an extra year to the expiration to ensure tokens are rejected
            expiry = datetime.utcnow().replace(year=datetime.utcnow().year + 1)
            
            # Blacklist all user tokens
            if user_id in self._user_tokens:
                for token in self._user_tokens[user_id]:
                    self._token_blacklist[token] = expiry
                
                # Log the number of tokens blacklisted
                logger.info(f"Blacklisted {len(self._user_tokens[user_id])} tokens for user {user_id}")
                
        except Exception as e:
            logger.error(f"Failed to blacklist user tokens: {e!s}")
            raise RepositoryException(f"Failed to blacklist user tokens: {e!s}")

    async def blacklist_session_tokens(self, session_id: str) -> None:
        """
        Blacklist all tokens for a specific session.

        Args:
            session_id: The session identifier

        Raises:
            RepositoryException: If the operation fails
        """
        try:
            # Add an extra year to the expiration to ensure tokens are rejected
            expiry = datetime.utcnow().replace(year=datetime.utcnow().year + 1)
            
            # Blacklist all session tokens
            if session_id in self._session_tokens:
                for token in self._session_tokens[session_id]:
                    self._token_blacklist[token] = expiry
                
                # Log the number of tokens blacklisted
                logger.info(f"Blacklisted {len(self._session_tokens[session_id])} tokens for session {session_id}")
                
        except Exception as e:
            logger.error(f"Failed to blacklist session tokens: {e!s}")
            raise RepositoryException(f"Failed to blacklist session tokens: {e!s}")

    async def cleanup_expired_tokens(self) -> int:
        """
        Remove expired tokens from the blacklist.

        Returns:
            Number of expired tokens removed

        Raises:
            RepositoryException: If the operation fails
        """
        try:
            now = datetime.utcnow()
            expired_tokens = [
                token for token, expires_at in self._token_blacklist.items()
                if expires_at < now
            ]
            
            # Remove expired tokens
            for token in expired_tokens:
                del self._token_blacklist[token]
                
                # Remove from user tokens mapping if present
                for user_id, tokens in self._user_tokens.items():
                    if token in tokens:
                        tokens.remove(token)
                        
                # Remove from session tokens mapping if present
                for session_id, tokens in self._session_tokens.items():
                    if token in tokens:
                        tokens.remove(token)
            
            # Log cleanup results
            if expired_tokens:
                logger.debug(f"Removed {len(expired_tokens)} expired tokens from blacklist")
                
            return len(expired_tokens)
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired tokens: {e!s}")
            raise RepositoryException(f"Failed to cleanup expired tokens: {e!s}")

    async def get_active_sessions(self, user_id: str) -> list[str]:
        """
        Get all active sessions for a user.

        Args:
            user_id: The user identifier

        Returns:
            List of active session IDs

        Raises:
            RepositoryException: If the operation fails
        """
        try:
            # In a production implementation, this would query the database
            # or cache for active sessions associated with the user
            # For this in-memory implementation, we don't track this directly
            
            # Return empty list for now
            return []
            
        except Exception as e:
            logger.error(f"Failed to get active sessions: {e!s}")
            raise RepositoryException(f"Failed to get active sessions: {e!s}")
            
    def add_token_to_user(self, user_id: str, token: str) -> None:
        """
        Associate a token with a user for tracking.
        
        Args:
            user_id: The user identifier
            token: The token to associate
        """
        if user_id not in self._user_tokens:
            self._user_tokens[user_id] = set()
            
        self._user_tokens[user_id].add(token)
        
    def add_token_to_session(self, session_id: str, token: str) -> None:
        """
        Associate a token with a session for tracking.
        
        Args:
            session_id: The session identifier
            token: The token to associate
        """
        if session_id not in self._session_tokens:
            self._session_tokens[session_id] = set()
            
        self._session_tokens[session_id].add(token) 