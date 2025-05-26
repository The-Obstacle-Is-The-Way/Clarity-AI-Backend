"""
Jose JWT adapter for Clarity AI Backend.

Adapts the python-jose library for JWT operations while providing a consistent
interface to ensure security and HIPAA compliance.
"""

from typing import Any, cast

# Import JWT functionalities from python-jose
from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWTClaimsError

# Re-export common exceptions to avoid direct dependency on jose
__all__ = ["ExpiredSignatureError", "JWTClaimsError", "JWTError", "decode", "encode"]


def encode(
    claims: dict[str, Any],
    key: str,
    algorithm: str = "HS256",
    headers: dict[str, Any] | None = None,
    access_token: bool = False,
) -> str:
    """
    Encode a set of claims into a JWT token.

    Args:
        claims: Payload to encode
        key: Key to sign the token with
        algorithm: Algorithm to use for signing
        headers: Additional headers to include
        access_token: Whether this is an access token (for potential custom behavior)

    Returns:
        Encoded JWT token as a string
    """
    # Implement any custom claims or headers processing here
    actual_headers = headers or {}

    # Set token type claim for security
    if access_token:
        actual_headers.update({"typ": "JWT", "use": "access"})

    # Encode with jose
    return cast(str, jwt.encode(claims, key, algorithm=algorithm, headers=actual_headers))


def decode(
    token: str,
    key: str = "",
    algorithms: list[str] | None = None,
    audience: str | None = None,
    issuer: str | None = None,
    subject: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Decode a JWT token and return its claims.

    Args:
        token: JWT token to decode
        key: Key to verify the token signature
        algorithms: Allowed algorithms
        audience: Expected audience
        issuer: Expected issuer
        subject: Expected subject
        options: Additional options for decoding

    Returns:
        The decoded token claims

    Raises:
        JWTError: If the token is invalid
        ExpiredSignatureError: If the token has expired
    """
    # Default algorithms
    if algorithms is None:
        algorithms = ["HS256"]

    # Default options ensuring security
    if options is None:
        options = {
            "verify_signature": True,
            "verify_aud": audience is not None,
            "verify_iss": issuer is not None,
            "verify_sub": subject is not None,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "leeway": 0,
        }

    # Decode with jose
    return cast(dict[str, Any], jwt.decode(
        token,
        key,
        algorithms=algorithms,
        audience=audience,
        issuer=issuer,
        subject=subject,
        options=options,
    ))
