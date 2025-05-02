from datetime import datetime, timedelta

import pytest

"""
Standalone tests for utility functions in the Novamind Digital Twin platform.

These tests have no external dependencies and can run in complete isolation.
They test pure functions and business logic.
"""

# Import utilities to test
from app.core.utils.date_utils import format_date_iso, is_date_in_range
from app.core.utils.string_utils import sanitize_name, truncate_text


@pytest.mark.standalone()
def test_is_date_in_range():
    """Test date range validation logic."""
    # Base date
    base_date = datetime(2025, 1, 1)

    # Test dates within range
    assert is_date_in_range(
        base_date,
        base_date - timedelta(days=10),
        base_date + timedelta(days=10)
    )

    # Test date before range
    assert not is_date_in_range(
        base_date - timedelta(days=11),
        base_date,
        base_date + timedelta(days=10)
    )

    # Test date after range
    assert not is_date_in_range(
        base_date + timedelta(days=11),
        base_date - timedelta(days=10),
        base_date + timedelta(days=10)
    )

    # Test exact boundary (inclusive)
    assert is_date_in_range(
        base_date - timedelta(days=10),
        base_date - timedelta(days=10),
        base_date + timedelta(days=10)
    )
    assert is_date_in_range(
        base_date + timedelta(days=10),
        base_date - timedelta(days=10),
        base_date + timedelta(days=10)
    )


@pytest.mark.standalone()
def test_format_date_iso():
    """Test ISO date formatting."""
    test_date = datetime(2025, 1, 1, 12, 30, 45)
    formatted = format_date_iso(test_date)
    
    # Should be in ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
    assert formatted == "2025-01-01T12:30:45Z"
    
    # Test with microseconds
    test_date_with_micros = datetime(2025, 1, 1, 12, 30, 45, 123456)
    formatted = format_date_iso(test_date_with_micros)
    
    # Microseconds should be truncated in the ISO format
    assert formatted == "2025-01-01T12:30:45Z"


@pytest.mark.standalone()
def test_sanitize_name():
    """Test sanitization of user-provided names."""
    # Test basic sanitization
    assert sanitize_name("John Doe") == "john_doe"
    
    # Test with special characters
    assert sanitize_name("John D'Oe!@#") == "john_d_oe"
    
    # Test with multiple spaces
    assert sanitize_name("  John   Doe  ") == "john_doe"
    
    # Test with non-ASCII characters
    assert sanitize_name("Jöhn Døe") == "jhn_de"  # non-ASCII chars removed
    
    # Test with email-like input
    assert sanitize_name("john.doe@examplecom") == "john_doe_examplecom"


@pytest.mark.standalone()
def test_truncate_text():
    """Test text truncation with ellipsis."""
    # Test no truncation needed
    assert truncate_text("Short text", max_length=20) == "Short text"
    
    # Test exact length (no truncation)
    assert truncate_text("1234567890", max_length=10) == "1234567890"
    
    # Test truncation with default ellipsis
    long_text = "This is a very long text that needs to be truncated"
    assert truncate_text(long_text, max_length=20) == "This is a very lon..."
    
    # Test truncation with custom ellipsis
    assert truncate_text(long_text, max_length=20, ellipsis="[...]") == "This is a very [...]"
    
    # Test truncation with empty ellipsis
    assert truncate_text(long_text, max_length=20, ellipsis="") == "This is a very long "


if __name__ == "__main__":
    pytest.main(["-v", __file__])
