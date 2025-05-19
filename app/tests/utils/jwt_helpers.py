"""
JWT Test Helpers.

This module provides utility functions for testing JWT functionality.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

# Constants for testing
TEST_SECRET_KEY = (
    "test_jwt_secret_key_that_is_sufficiently_long_for_testing_purposes_only"
)
TEST_ALGORITHM = "HS256"
TEST_ISSUER = "clarity-tests"
TEST_AUDIENCE = "test-audience"


def create_test_token(
    subject: str,
    token_type: str = "access",
    expiry_delta: timedelta | None = None,
    custom_claims: dict[str, Any] | None = None,
    secret_key: str = TEST_SECRET_KEY,
    expired: bool = False,
    algorithm: str = TEST_ALGORITHM,
) -> str:
    """
    Create a JWT token for testing.

    Args:
        subject: The subject claim (user ID)
        token_type: Type of token (access, refresh)
        expiry_delta: Custom expiration time
        custom_claims: Additional claims to include
        secret_key: Secret key for signing the token
        expired: Whether to create an expired token
        algorithm: Algorithm to use for signing

    Returns:
        str: JWT token
    """
    now = datetime.now(UTC)

    if expired:
        exp = now - timedelta(hours=1)
    elif expiry_delta:
        exp = now + expiry_delta
    elif token_type == "refresh":
        exp = now + timedelta(days=7)
    else:
        exp = now + timedelta(minutes=30)

    payload = {
        "sub": subject,
        "exp": int(exp.timestamp()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "jti": "test-jti-" + token_type,
        "type": token_type,
        "iss": TEST_ISSUER,
        "aud": TEST_AUDIENCE,
    }

    # Add refresh-specific claims
    if token_type == "refresh":
        payload["refresh"] = True
        payload["family_id"] = "test-family-id"

    # Add custom claims
    if custom_claims:
        payload.update(custom_claims)

    # Encode the token
    return jwt.encode(payload, secret_key, algorithm=algorithm)


def decode_test_token(
    token: str,
    secret_key: str = TEST_SECRET_KEY,
    verify: bool = True,
    algorithm: str = TEST_ALGORITHM,
) -> dict[str, Any]:
    """
    Decode a JWT token for testing.

    Args:
        token: The token to decode
        secret_key: Secret key for verification
        verify: Whether to verify the token
        algorithm: Algorithm to use for verification

    Returns:
        Dict[str, Any]: Decoded token payload
    """
    options = {"verify_signature": verify}

    if not verify:
        options.update({"verify_exp": False, "verify_aud": False, "verify_iss": False})

    return jwt.decode(token, secret_key, algorithms=[algorithm], options=options)


def get_test_jwt_service_config() -> dict[str, Any]:
    """
    Get configuration for JWTService in tests.

    Returns:
        Dict[str, Any]: Configuration for JWTService
    """
    return {
        "secret_key": TEST_SECRET_KEY,
        "algorithm": TEST_ALGORITHM,
        "access_token_expire_minutes": 30,
        "refresh_token_expire_days": 7,
        "issuer": TEST_ISSUER,
        "audience": TEST_AUDIENCE,
    }
