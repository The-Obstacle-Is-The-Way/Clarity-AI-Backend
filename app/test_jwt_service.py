"""
Simple test script for JWT service.

This directly tests the JWT service implementation without the entire FastAPI framework.
"""

import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

from domain.exceptions import TokenBlacklistedException as TokenBlacklistedError
from infrastructure.repositories.memory_token_blacklist_repository import (
    MemoryTokenBlacklistRepository,
)
from infrastructure.security.jwt.jwt_service import JWTService


async def test_jwt_service() -> None:
    """Basic test for JWT service functionality."""
    print("Testing JWT Service...")

    # Create a mock settings object
    class MockSettings:
        JWT_SECRET_KEY = "testsecretkeythatisverylong"
        JWT_ALGORITHM = "HS256"
        ACCESS_TOKEN_EXPIRE_MINUTES = 30
        JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7
        ENVIRONMENT = "test"
        JWT_ISSUER = "test-issuer"
        JWT_AUDIENCE = "test-audience"

    # Create repositories and service
    blacklist_repo = MemoryTokenBlacklistRepository()
    mock_settings = MockSettings()
    jwt_service = JWTService(
        secret_key=mock_settings.JWT_SECRET_KEY,
        algorithm=mock_settings.JWT_ALGORITHM,
        access_token_expire_minutes=mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        refresh_token_expire_days=mock_settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS,
        issuer=mock_settings.JWT_ISSUER,
        audience=mock_settings.JWT_AUDIENCE,
        settings=mock_settings,
        token_blacklist_repository=blacklist_repo
    )

    # Test token creation
    user_id = str(uuid4())
    print(f"Creating tokens for user: {user_id}")

    # Create access token
    access_token = await jwt_service.create_access_token(user_id=user_id)
    print(f"Access token: {access_token[:20]}...")

    # Create refresh token
    refresh_token = await jwt_service.create_refresh_token(user_id=user_id)
    print(f"Refresh token: {refresh_token[:20]}...")

    # Decode and validate tokens
    access_payload = await jwt_service.verify_token(access_token)
    print(f"Access token payload: {access_payload}")

    refresh_payload = jwt_service.verify_refresh_token(refresh_token)
    print(f"Refresh token payload: {refresh_payload}")

    # Test refresh token
    new_access_token = await jwt_service.refresh_access_token(refresh_token)
    print(f"New access token: {new_access_token[:20]}...")

    # Test token blacklisting
    await jwt_service.blacklist_token(
        token=access_token, expires_at=datetime.now() + timedelta(hours=1)
    )
    is_blacklisted = await jwt_service.is_token_blacklisted(access_token)
    print(f"Token blacklisted: {is_blacklisted}")

    # Try to verify blacklisted token
    try:
        await jwt_service.verify_token(access_token)
        print("❌ ERROR: Token blacklist check failed!")
        exit(1)
    except TokenBlacklistedError:
        print("✅ Token blacklist check passed")

    print("JWT Service test completed successfully!")


if __name__ == "__main__":
    asyncio.run(test_jwt_service())
