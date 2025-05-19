"""
Datetime utilities for consistent timezone handling.

This module provides constants and helper functions for working
with dates and times in a consistent manner across the application.
"""

import datetime
from typing import Optional, Union
from zoneinfo import ZoneInfo

# Standard timezone for all application operations
UTC = ZoneInfo("UTC")


def now() -> datetime.datetime:
    """
    Get current datetime in UTC.

    Returns:
        datetime.datetime: Current time in UTC timezone
    """
    return datetime.datetime.now(UTC)


def now_utc() -> datetime.datetime:
    """
    Get current datetime in UTC.
    Added for backward compatibility with existing code.

    Returns:
        datetime.datetime: Current time in UTC timezone
    """
    return now()


def today() -> datetime.date:
    """
    Get current date in UTC.

    Returns:
        datetime.date: Current date in UTC timezone
    """
    return now().date()


def format_iso(dt: datetime.datetime) -> str:
    """
    Format datetime in ISO 8601 format with timezone.

    Args:
        dt: Datetime to format

    Returns:
        str: ISO 8601 formatted datetime string
    """
    return dt.isoformat()


def parse_iso(date_str: str) -> datetime.datetime:
    """
    Parse ISO 8601 datetime string to datetime object.

    Ensures the result has UTC timezone if none specified.

    Args:
        date_str: ISO 8601 formatted string

    Returns:
        datetime.datetime: Parsed datetime with timezone
    """
    dt = datetime.datetime.fromisoformat(date_str)
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


def days_between(
    start: Union[datetime.datetime, str], end: Union[datetime.datetime, str]
) -> int:
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
