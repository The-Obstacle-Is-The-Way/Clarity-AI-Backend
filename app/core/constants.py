"""
Application constants.

This module defines constants used throughout the application,
including enums, cache keys, and other static values.
"""

from enum import Enum


class Environment(str, Enum):
    """Application environment types."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(Enum):
    """Log level constants for structured logging."""

    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class CacheNamespace:
    """Cache key namespaces to prevent key collisions."""

    # User-related caches
    USER = "user"
    SESSION = "session"

    # Rate limiting
    RATE_LIMIT = "rate_limit"

    # Feature flags
    FEATURE_FLAGS = "feature_flags"

    # Analytics
    ANALYTICS = "analytics"

    # Content caching
    CONTENT = "content"

    # API caching
    API = "api"


class EventType:
    """Analytics event types."""

    # User events
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_REGISTER = "user.register"
    USER_UPDATE = "user.update"

    # Content events
    CONTENT_VIEW = "content.view"
    CONTENT_SEARCH = "content.search"

    # Feature events
    FEATURE_USE = "feature.use"

    # API events
    API_REQUEST = "api.request"
    API_ERROR = "api.error"


class LogCategory:
    """Log message categories for structured logging."""

    SECURITY = "security"
    PERFORMANCE = "performance"
    ERROR = "error"
    AUDIT = "audit"
    INFO = "info"
    DEBUG = "debug"


class HeaderName:
    """HTTP header names used by the application."""

    REQUEST_ID = "X-Request-ID"
    CORRELATION_ID = "X-Correlation-ID"
    API_KEY = "X-API-Key"
    CLIENT_ID = "X-Client-ID"
    USER_AGENT = "User-Agent"
    CONTENT_TYPE = "Content-Type"
    AUTHORIZATION = "Authorization"
    RATE_LIMIT_LIMIT = "X-RateLimit-Limit"
    RATE_LIMIT_REMAINING = "X-RateLimit-Remaining"
    RATE_LIMIT_RESET = "X-RateLimit-Reset"


def get_content_type(file_extension: str) -> str:
    """
    Get the content type for a file extension.

    Args:
        file_extension: File extension without the dot

    Returns:
        Content type string
    """
    content_types = {
        "html": "text/html",
        "htm": "text/html",
        "css": "text/css",
        "js": "application/javascript",
        "json": "application/json",
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "svg": "image/svg+xml",
        "ico": "image/x-icon",
        "pdf": "application/pdf",
        "xml": "application/xml",
        "zip": "application/zip",
        "txt": "text/plain",
        "csv": "text/csv",
        "mp3": "audio/mpeg",
        "mp4": "video/mp4",
        "webm": "video/webm",
        "ogg": "audio/ogg",
        "wav": "audio/wav",
        "webp": "image/webp",
    }

    return content_types.get(file_extension.lower(), "application/octet-stream")
