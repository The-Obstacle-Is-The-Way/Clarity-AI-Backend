"""
Patch for python-jose library to fix datetime.utcnow() deprecation warnings.

This module monkey patches the jose.jwt module to replace deprecated datetime.utcnow()
calls with the recommended datetime.now(datetime.UTC) approach.
"""

import functools
import logging
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from jose import jwt

logger = logging.getLogger(__name__)


def patch_jose_jwt() -> None:
    """
    Apply monkey patch to jose.jwt module to fix datetime.utcnow() deprecation warnings.
    
    This function replaces the _get_now function in jose.jwt with a version that uses
    datetime.now(timezone.utc) instead of datetime.utcnow().
    """
    try:
        # Store the original function
        original_get_now = getattr(jwt, "_get_now", None)
        
        # Define the patched function
        def patched_get_now() -> int:
            """Return the current time as seconds since epoch."""
            from calendar import timegm
            return timegm(datetime.now(timezone.utc).utctimetuple())
        
        # Apply the patch only if the original function exists
        if original_get_now is not None:
            jwt._get_now = patched_get_now
            logger.info("Successfully patched jose.jwt._get_now to use timezone-aware datetime")
        else:
            logger.warning("Could not patch jose.jwt: _get_now function not found")
            
    except Exception as e:
        logger.error(f"Failed to apply jose.jwt patch: {e}")


def with_patched_jose(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator to apply jose.jwt patch before executing a function.
    
    Args:
        func: The function to wrap
        
    Returns:
        Wrapped function with jose.jwt patch applied
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        patch_jose_jwt()
        return func(*args, **kwargs)
        
    return wrapper  # Explicit return for Mypy
