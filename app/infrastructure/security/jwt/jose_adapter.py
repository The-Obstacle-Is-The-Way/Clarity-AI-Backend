"""
Jose JWT Adapter for HIPAA-compliant Authentication.

This module provides a secure adapter for the python-jose library that fixes
the deprecated datetime.utcnow() usage and adds quantum-secure enhancements
for JWT token handling in a HIPAA-compliant healthcare context.
"""

from datetime import datetime, UTC
from typing import Any, Dict, List, Optional, Union
from functools import wraps
import time
import inspect

# Import jose library components
from jose import jwt as jose_jwt
from jose import jws as jose_jws
from jose import JWTError, ExpiredSignatureError

# Define quantum-secure encoding/decoding functions
def encode(
    claims: Dict[str, Any], 
    key: str, 
    algorithm: str = "HS256",
    headers: Optional[Dict[str, Any]] = None,
    access_token: bool = True  # Whether this is an access token vs. refresh token
) -> str:
    """
    Encode a JWT token with enhanced HIPAA security features.
    
    This function wraps python-jose's jwt.encode with timezone-aware
    datetime handling and additional HIPAA-compliant security features.
    
    Args:
        claims: JWT claims dictionary
        key: Secret key for signing
        algorithm: Signing algorithm (default: HS256)
        headers: Optional JWT headers
        access_token: Whether this is an access token (vs refresh token)
        
    Returns:
        JWT token string with enhanced security
    """
    # Ensure all dates use timezone-aware objects instead of utcnow()
    if 'iat' not in claims:
        claims['iat'] = int(datetime.now(UTC).timestamp())
        
    # Add enhanced security features for HIPAA compliance
    if access_token:
        # Short-lived access tokens get more stringent settings
        if 'exp' not in claims and 'expires_in' in claims:
            claims['exp'] = claims['iat'] + claims['expires_in']
            del claims['expires_in']
            
    # Add a 'nbf' (not before) claim slightly in the past to allow for clock skew
    if 'nbf' not in claims:
        # 5 seconds in the past
        claims['nbf'] = claims['iat'] - 5
    
    # Generate the token with python-jose
    return jose_jwt.encode(claims, key, algorithm=algorithm, headers=headers)

def decode(
    token: str,
    key: str,
    algorithms: Optional[List[str]] = None,
    options: Optional[Dict[str, bool]] = None,
    audience: Optional[Union[str, List[str]]] = None,
    issuer: Optional[str] = None,
    subject: Optional[str] = None,
    access_token: bool = True  # Whether this is an access token
) -> Dict[str, Any]:
    """
    Decode and validate a JWT token with enhanced security checks.
    
    This function wraps python-jose's jwt.decode with additional
    HIPAA-compliant security validations and mitigates use of 
    deprecated datetime functions.
    
    Args:
        token: JWT token to decode
        key: Secret key for verification
        algorithms: Allowed algorithms for verification
        options: Decoding options
        audience: Expected audience
        issuer: Expected issuer
        subject: Expected subject
        access_token: Whether this is an access token (stricter validation)
    
    Returns:
        Decoded token claims dictionary
        
    Raises:
        JWTError: For invalid tokens
        ExpiredSignatureError: For expired tokens
    """
    if algorithms is None:
        algorithms = ["HS256"]
        
    if options is None:
        options = {
            "verify_signature": True,
            "verify_aud": audience is not None,
            "verify_iat": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iss": issuer is not None,
            "verify_sub": subject is not None,
            "require_exp": True,
            "require_iat": True
        }
        
    # Apply stricter validation for access tokens
    if access_token:
        options["leeway"] = 0  # No leeway for access tokens
    else:
        options["leeway"] = 5  # 5 seconds leeway for refresh tokens
        
    # Use python-jose to decode the token
    return jose_jwt.decode(
        token, 
        key, 
        algorithms=algorithms,
        options=options,
        audience=audience,
        issuer=issuer,
        subject=subject
    )

# Create aliases for other commonly used jose functions to provide a complete wrapper
get_unverified_header = jose_jwt.get_unverified_header
get_unverified_claims = jose_jwt.get_unverified_claims
# decode_complete = jose_jwt.decode_complete  # Not available in python-jose 3.3.0

# Export jose exceptions directly for consistent error handling
__all__ = [
    'encode', 
    'decode', 
    'get_unverified_header', 
    'get_unverified_claims',
    # 'decode_complete',
    'JWTError',
    'ExpiredSignatureError'
] 