"""
Simple test script for JWT service.

This directly tests the JWT service implementation without the entire FastAPI framework.
"""

import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

from app.infrastructure.security.jwt.jwt_service import JWTService, TokenBlacklistedError
from app.infrastructure.repositories.memory_token_blacklist_repository import MemoryTokenBlacklistRepository


async def test_jwt_service():
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
    jwt_service = JWTService(
        settings=MockSettings(),
        token_blacklist_repository=blacklist_repo
    )
    
    # Test token creation
    user_id = str(uuid4())
    print(f"Creating tokens for user: {user_id}")
    
    # Create access token
    access_token = jwt_service.create_access_token(subject=user_id)
    print(f"Access token: {access_token[:20]}...")
    
    # Create refresh token
    refresh_token = jwt_service.create_refresh_token(subject=user_id)
    print(f"Refresh token: {refresh_token[:20]}...")
    
    # Decode and validate tokens
    access_payload = jwt_service.decode_token(access_token)
    print(f"Access token payload: {access_payload}")
    
    refresh_payload = jwt_service.decode_token(refresh_token)
    print(f"Refresh token payload: {refresh_payload}")
    
    # Test refresh token
    new_access_token = jwt_service.refresh_access_token(refresh_token)
    print(f"New access token: {new_access_token[:20]}...")
    
    # Test token blacklisting
    await jwt_service.blacklist_token(token=access_token, expires_at=datetime.now() + timedelta(hours=1))
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