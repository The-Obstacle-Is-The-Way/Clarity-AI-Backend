"""
App Factory Compatibility Module.

This module re-exports the create_application function from app.factory
to maintain backward compatibility with existing imports.
"""

from app.factory import create_application, lifespan

__all__ = ["create_application", "lifespan"]
