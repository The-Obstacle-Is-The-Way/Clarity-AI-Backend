"""
Configuration package.

This package contains application configuration and settings.
"""

from app.core.config.settings import get_settings, Settings, settings

__all__ = ["get_settings", "Settings", "settings"]