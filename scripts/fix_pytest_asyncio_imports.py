#!/usr/bin/env python3
"""
Script to fix missing pytest_asyncio imports in test files.

This script searches for test files that use pytest_asyncio decorators or fixtures
but are missing the import statement, and adds the import.
"""

import os
import re
import sys
from pathlib import Path

def find_test_files():
    """Find all Python test files in the app/tests directory."""
    test_dir = Path("app/tests")
    return list(test_dir.glob("**/*.py"))

def needs_pytest_asyncio_import(file_path):
    """Check if a file uses pytest_asyncio but doesn't import it."""
    content = file_path.read_text()
    
    # Check if the file uses pytest_asyncio
    uses_pytest_asyncio = (
        "@pytest_asyncio.fixture" in content or 
        "pytest_asyncio.fixture" in content
    )
    
    # Check if it already imports pytest_asyncio
    has_import = (
        "import pytest_asyncio" in content or
        "from pytest_asyncio" in content
    )
    
    return uses_pytest_asyncio and not has_import

def add_pytest_asyncio_import(file_path):
    """Add the pytest_asyncio import to a file."""
    content = file_path.read_text()
    
    # Look for the pytest import line to add pytest_asyncio after it
    if "import pytest" in content:
        content = content.replace(
            "import pytest",
            "import pytest\nimport pytest_asyncio",
            1
        )
    else:
        # If pytest is not imported, add both imports at the top
        # after any docstrings or comments
        lines = content.split("\n")
        insert_pos = 0
        for i, line in enumerate(lines):
            # Skip past docstrings and comments at the top
            if line.strip() and not line.strip().startswith('#') and not line.strip().startswith('"""') and not line.strip().startswith("'''"):
                insert_pos = i
                break
        
        lines.insert(insert_pos, "import pytest\nimport pytest_asyncio\n")
        content = "\n".join(lines)
    
    file_path.write_text(content)
    return True

def main():
    """Find and fix test files with missing pytest_asyncio imports."""
    test_files = find_test_files()
    fixed_count = 0
    
    for file_path in test_files:
        if needs_pytest_asyncio_import(file_path):
            print(f"Fixing {file_path}")
            add_pytest_asyncio_import(file_path)
            fixed_count += 1
    
    print(f"Fixed {fixed_count} file(s)")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 