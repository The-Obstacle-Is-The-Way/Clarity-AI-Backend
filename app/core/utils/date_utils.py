"""
Date and time utility functions for the Clarity Digital Twin platform.

This module provides standardized timezone-aware datetime functions and other date utilities
for consistent handling of dates and times throughout the application.
Ensures HIPAA compliance by providing consistent timestamps for audit logging.
"""

import logging
from datetime import date, datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# Timezone-aware functions


def utcnow() -> datetime:
    """
    Get the current UTC datetime with timezone information.

    Returns a timezone-aware datetime object using timezone.utc.
    Compatible with test frameworks that patch datetime.

    Returns:
        datetime: Current UTC time as a timezone-aware datetime object
    """
    try:
        # Python 3.12+ approach
        from datetime import UTC

        return datetime.now(UTC)
    except (ImportError, AttributeError):
        # Fallback for older Python versions and test frameworks
        return datetime.now(timezone.utc)


def from_timestamp(timestamp: float) -> datetime:
    """
    Convert a UNIX timestamp to a timezone-aware UTC datetime.

    Args:
        timestamp: UNIX timestamp (seconds since epoch)

    Returns:
        datetime: Timezone-aware UTC datetime
    """
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def as_utc(dt: datetime) -> datetime:
    """
    Ensure a datetime is timezone-aware as UTC.

    If the datetime is naive (no timezone), assume it's UTC.
    If it has a timezone, convert it to UTC.

    Args:
        dt: Input datetime object

    Returns:
        datetime: Timezone-aware UTC datetime
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_aware(dt: datetime) -> bool:
    """
    Check if a datetime object is timezone-aware.

    Args:
        dt: Datetime object to check

    Returns:
        bool: True if datetime has timezone info, False otherwise
    """
    return dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None


# Date range and formatting functions


def is_date_in_range(
    check_date: datetime | date,
    start_date: datetime | date,
    end_date: datetime | date,
) -> bool:
    """
    Check if a date is within a specified range (inclusive).

    Args:
        check_date: The date to check
        start_date: The start of the range
        end_date: The end of the range

    Returns:
        bool: True if the date is within the range, False otherwise
    """
    # Normalize to date if datetime
    if isinstance(check_date, datetime):
        check_date = check_date.date()
    if isinstance(start_date, datetime):
        start_date = start_date.date()
    if isinstance(end_date, datetime):
        end_date = end_date.date()

    return start_date <= check_date <= end_date


def format_date_iso(dt: datetime | date, include_time: bool = True) -> str:
    """
    Format a date or datetime object as an ISO 8601 string.

    Args:
        dt: The date or datetime to format
        include_time: Whether to include time information if available

    Returns:
        str: Formatted ISO 8601 string
    """
    if isinstance(dt, datetime) and include_time:
        # Make timezone-aware if it isn't already
        if not is_aware(dt):
            dt = as_utc(dt)
        # Format datetime as ISO 8601 with UTC 'Z' suffix
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        if isinstance(dt, datetime):
            dt = dt.date()
        return dt.strftime("%Y-%m-%d")


def parse_iso_date(date_str: str) -> datetime | date:
    """
    Parse an ISO 8601 date or datetime string.

    Args:
        date_str: The ISO 8601 string to parse

    Returns:
        Union[datetime, date]: Parsed datetime or date object

    Raises:
        ValueError: If the string cannot be parsed
    """
    # Try parsing as datetime first
    try:
        if "T" in date_str:
            # Has time component
            if date_str.endswith("Z"):
                # UTC timezone marker
                dt = datetime.fromisoformat(date_str[:-1])
                return as_utc(dt)
            elif (
                "+" in date_str or "-" in date_str[10:]
            ):  # Check for timezone markers after date part
                # Has timezone info
                return datetime.fromisoformat(date_str)
            else:
                # No timezone, interpret as UTC
                dt = datetime.fromisoformat(date_str)
                return as_utc(dt)
        else:
            # Date only
            return datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        # Try other ISO 8601 formats
        formats = [
            "%Y-%m-%d",
            "%Y%m%d",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                if "T" in fmt:
                    # It's a datetime, make it timezone-aware
                    return as_utc(dt)
                return dt.date()
            except ValueError:
                continue

        # If we get here, none of the formats worked
        raise ValueError(f"Could not parse {date_str} as ISO 8601 date/datetime")


def get_age_from_birthdate(birthdate: datetime | date) -> int:
    """
    Calculate age in years from a birthdate.

    Args:
        birthdate: The birthdate to calculate age from

    Returns:
        int: Age in years
    """
    if isinstance(birthdate, datetime):
        birthdate = birthdate.date()

    today = date.today()

    # Calculate age
    age = today.year - birthdate.year

    # Adjust age if birthday hasn't occurred yet this year
    if (today.month, today.day) < (birthdate.month, birthdate.day):
        age -= 1

    return max(0, age)  # Ensure age is never negative


def add_time_to_datetime(
    dt: datetime, days: int = 0, hours: int = 0, minutes: int = 0, seconds: int = 0
) -> datetime:
    """
    Add a specific amount of time to a datetime object.
    Maintains timezone awareness.

    Args:
        dt: The datetime to add time to
        days: Number of days to add
        hours: Number of hours to add
        minutes: Number of minutes to add
        seconds: Number of seconds to add

    Returns:
        datetime: A new datetime with the time added
    """
    delta = timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
    return dt + delta


def get_start_of_day(dt: datetime) -> datetime:
    """
    Get the start of the day (midnight) for a given datetime.
    Preserves timezone information.

    Args:
        dt: Input datetime

    Returns:
        datetime: Start of day
    """
    return datetime.combine(dt.date(), datetime.min.time(), tzinfo=dt.tzinfo)


def get_end_of_day(dt: datetime) -> datetime:
    """
    Get the end of the day (23:59:59.999999) for a given datetime.
    Preserves timezone information.

    Args:
        dt: Input datetime

    Returns:
        datetime: End of day
    """
    return datetime.combine(dt.date(), datetime.max.time(), tzinfo=dt.tzinfo)
