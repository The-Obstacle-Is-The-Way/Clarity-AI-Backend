"""
DateTime Utilities

This module provides datetime utility functions and constants for consistent
datetime handling throughout the application. It ensures proper timezone
management and ISO 8601 formatting.
"""

import datetime
from typing import Optional, Union

# Standard UTC timezone constant for consistent usage across the application
UTC = datetime.timezone.utc

def now() -> datetime.datetime:
    """
    Get current UTC datetime with timezone information.
    
    Returns:
        datetime.datetime: Current time in UTC with timezone info
    """
    return datetime.datetime.now(UTC)

def utc_now() -> datetime.datetime:
    """
    Alias for now() - provides current UTC datetime.
    
    Returns:
        datetime.datetime: Current time in UTC with timezone info
    """
    return now()

def now_utc() -> datetime.datetime:
    """
    Alias for utc_now() - provides current UTC datetime.
    Added for backward compatibility with existing code.
    
    Returns:
        datetime.datetime: Current time in UTC with timezone info
    """
    return utc_now()

def format_iso(dt: Optional[datetime.datetime] = None) -> str:
    """
    Format a datetime as ISO 8601 string with timezone info.
    
    Args:
        dt: Datetime to format. If None, current UTC time is used.
        
    Returns:
        str: ISO 8601 formatted datetime string
    """
    if dt is None:
        dt = now()
    elif dt.tzinfo is None:
        # Ensure timezone info is present
        dt = dt.replace(tzinfo=UTC)
        
    return dt.isoformat()

def parse_iso(iso_str: str) -> datetime.datetime:
    """
    Parse an ISO 8601 string into a datetime object with timezone info.
    
    Args:
        iso_str: ISO 8601 formatted datetime string
        
    Returns:
        datetime.datetime: Parsed datetime with timezone info
        
    Raises:
        ValueError: If the string cannot be parsed as ISO format
    """
    dt = datetime.datetime.fromisoformat(iso_str)
    
    # Ensure timezone info is present
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
        
    return dt

def to_utc(dt: datetime.datetime) -> datetime.datetime:
    """
    Convert a datetime to UTC timezone.
    
    Args:
        dt: Datetime to convert
        
    Returns:
        datetime.datetime: Datetime in UTC timezone
    """
    if dt.tzinfo is None:
        # Assume naive datetimes are already UTC
        return dt.replace(tzinfo=UTC)
    
    return dt.astimezone(UTC)

def timestamp_ms() -> int:
    """
    Get current UTC timestamp in milliseconds.
    
    Returns:
        int: Current timestamp in milliseconds
    """
    return int(now().timestamp() * 1000)

def days_between(start: Union[datetime.datetime, str], end: Union[datetime.datetime, str]) -> int:
    """
    Calculate the number of days between two datetimes.
    
    Args:
        start: Start datetime or ISO string
        end: End datetime or ISO string
        
    Returns:
        int: Number of days between start and end
    """
    # Convert strings to datetime if needed
    if isinstance(start, str):
        start = parse_iso(start)
    
    if isinstance(end, str):
        end = parse_iso(end)
    
    # Ensure both datetimes have timezone info
    start = to_utc(start)
    end = to_utc(end)
    
    # Calculate days
    delta = end - start
    return delta.days

def format_iso8601(dt: Optional[datetime.datetime] = None) -> str:
    """
    Alias for format_iso() - format a datetime as ISO 8601 string.
    Added for backward compatibility with existing code.
    
    Args:
        dt: Datetime to format. If None, current UTC time is used.
        
    Returns:
        str: ISO 8601 formatted datetime string
    """
    return format_iso(dt)
