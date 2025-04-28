"""
Datetime utilities for the Novamind Digital Twin platform.

This module provides mathematically precise datetime handling with timezone awareness,
ensuring consistent behavior across all Python versions and computational contexts.
Following clean architecture principles, this abstraction isolates the core domain
from implementation details of the Python standard library.
"""

import datetime
from typing import Optional

# Define a true UTC timezone following mathematical principles
# This creates a single source of truth for UTC timezone access
# rather than relying on implementation-specific imports
UTC = datetime.timezone.utc

def now_utc() -> datetime.datetime:
    """
    Get the current time in UTC with timezone information.
    
    Returns:
        Current datetime in UTC with explicit timezone information
    """
    return datetime.datetime.now(UTC)

def from_timestamp_utc(timestamp: float) -> datetime.datetime:
    """
    Convert a Unix timestamp to a UTC datetime.
    
    Args:
        timestamp: Unix timestamp (seconds since epoch)
        
    Returns:
        Datetime object in UTC timezone
    """
    return datetime.datetime.fromtimestamp(timestamp, tz=UTC)

def to_utc(dt: datetime.datetime) -> datetime.datetime:
    """
    Ensure a datetime is in UTC timezone.
    
    If datetime is naive (no timezone), assumes it is UTC.
    If datetime has a different timezone, converts to UTC.
    
    Args:
        dt: Datetime object to convert
        
    Returns:
        Datetime in UTC timezone
    """
    if dt.tzinfo is None:
        # Assume naive datetimes are already UTC
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)

def format_iso8601(dt: datetime.datetime) -> str:
    """
    Format datetime as ISO-8601 string with UTC timezone indicator.
    
    Args:
        dt: Datetime to format, will be converted to UTC if needed
        
    Returns:
        ISO-8601 formatted string with UTC timezone ('Z' suffix)
    """
    utc_dt = to_utc(dt)
    # Format with 'Z' suffix to explicitly indicate UTC
    return utc_dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

def parse_iso8601(iso_str: str) -> datetime.datetime:
    """
    Parse ISO-8601 string into UTC datetime.
    
    Handles various ISO format variations.
    
    Args:
        iso_str: ISO-8601 formatted datetime string
        
    Returns:
        Datetime object in UTC timezone
    """
    # Handle format with Z suffix
    if iso_str.endswith('Z'):
        iso_str = iso_str[:-1] + '+00:00'
    
    # Parse with timezone information
    dt = datetime.datetime.fromisoformat(iso_str)
    return to_utc(dt)
