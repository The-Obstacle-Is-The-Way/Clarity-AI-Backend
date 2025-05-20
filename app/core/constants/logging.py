"""
Logging Constants Module

This module defines constants and enumerations related to logging
to ensure consistent log levels and formats across the application.
"""

from enum import Enum


class LogLevel(str, Enum):
    """
    Standard log levels for application logging.

    These levels align with standard Python logging levels
    but are provided as an enum for type safety and consistency.
    """

    CRITICAL = "CRITICAL"  # Critical errors requiring immediate attention
    ERROR = "ERROR"  # Error conditions
    WARNING = "WARNING"  # Warning conditions
    INFO = "INFO"  # Informational messages
    DEBUG = "DEBUG"  # Debug-level messages
    TRACE = "TRACE"  # Detailed trace information (more verbose than DEBUG)
