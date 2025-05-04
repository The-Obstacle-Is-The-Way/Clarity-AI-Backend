"""
Date and time utility functions for the Novamind Digital Twin platform.

This module provides reusable date and time utilities that can be used
across the application.
"""
from datetime import date, datetime


def is_date_in_range(
    check_date: datetime | date,
    start_date: datetime | date,
    end_date: datetime | date
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


def format_date_iso(
    dt: datetime | date, 
    include_time: bool = True
) -> str:
    """
    Format a date or datetime object as an ISO 8601 string.
    
    Args:
        dt: The date or datetime to format
        include_time: Whether to include time information if available
        
    Returns:
        str: Formatted ISO 8601 string
    """
    if isinstance(dt, datetime) and include_time:
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
            return datetime.fromisoformat(date_str)
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
                return datetime.strptime(date_str, fmt)
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