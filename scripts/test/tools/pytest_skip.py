"""
Pytest hook to handle skipping specific items during collection.
"""

def pytest_collect_file(path, parent):
    """Pytest hook to skip collection of specific files or patterns."""
    return None  # Let pytest handle it normally
