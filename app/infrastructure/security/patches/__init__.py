"""
Security patches module for fixing third-party library issues.

This package contains patches for third-party libraries to fix deprecation
warnings and other issues that cannot be fixed directly in the libraries.
"""

from app.infrastructure.security.patches.jose_patch import patch_jose_jwt, with_patched_jose

__all__ = ["patch_jose_jwt", "with_patched_jose"]
