"""
Pytest hook to handle skipping specific items during collection.
"""

from typing import Any, Optional


def pytest_collect_file(path: Any, parent: Any) -> Optional[Any]:
    """Pytest hook to skip collection of specific files or patterns."""
    return None  # Let pytest handle it normally
