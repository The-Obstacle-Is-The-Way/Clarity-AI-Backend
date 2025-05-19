#!/usr/bin/env python3
"""
Datetime Transformation Utility for Novamind Digital Twin.

This script transforms datetime imports across the codebase to use our
mathematically precise datetime_utils module rather than direct imports.
This ensures consistent behavior across all Python versions and computational contexts.

Following single responsibility principle, this script does one thing extremely well:
it refactors datetime imports to follow our clean architecture patterns.
"""

import os
import re
from pathlib import Path
from typing import List, Tuple, Set

# Define patterns for transformation with mathematical precision
UTC_IMPORT_PATTERN = re.compile(
    r"from\s+datetime\s+import\s+(.*?)(UTC)(.*?)$", re.MULTILINE
)
DATETIME_UTILS_IMPORT = "from app.domain.utils.datetime_utils import UTC"
REPLACEMENT_TEMPLATE = "from datetime import \\1\\3\n{}".format(DATETIME_UTILS_IMPORT)

# Define paths to search with architectural boundaries
ROOT_DIR = Path(__file__).parent.parent
SOURCE_DIRS = [
    ROOT_DIR / "app",
]
EXCLUSION_DIRS = [
    ROOT_DIR / "app" / "tests" / "fixtures",
    ROOT_DIR / "app" / "domain" / "utils",  # Don't transform our utilities module
]


def find_python_files(dirs: List[Path], exclusions: List[Path]) -> List[Path]:
    """
    Find all Python files in the specified directories, excluding certain paths.

    Args:
        dirs: Directories to search
        exclusions: Directories to exclude

    Returns:
        List of Python file paths
    """
    python_files = []
    for directory in dirs:
        if not directory.exists():
            continue

        for path in directory.glob("**/*.py"):
            # Skip excluded directories
            if any(str(path).startswith(str(excl)) for excl in exclusions):
                continue

            python_files.append(path)

    return python_files


def transform_file(file_path: Path) -> Tuple[bool, int]:
    """
    Transform datetime imports in a single file.

    Args:
        file_path: Path to the file to transform

    Returns:
        Tuple of (was_transformed, num_replacements)
    """
    # Read file content
    content = file_path.read_text()

    # Check if transformation is needed
    if "from datetime import" not in content or "UTC" not in content:
        return False, 0

    # Apply transformation with mathematical precision
    new_content, replacements = UTC_IMPORT_PATTERN.subn(REPLACEMENT_TEMPLATE, content)

    if replacements > 0:
        # Write transformed content
        file_path.write_text(new_content)
        return True, replacements

    return False, 0


def main():
    """Main function to transform datetime imports across the codebase."""
    # Find Python files
    python_files = find_python_files(SOURCE_DIRS, EXCLUSION_DIRS)

    print(f"Found {len(python_files)} Python files to analyze")

    # Track transformation statistics
    transformed_files = []
    total_replacements = 0

    # Process each file
    for file_path in python_files:
        was_transformed, replacements = transform_file(file_path)

        if was_transformed:
            transformed_files.append(file_path)
            total_replacements += replacements

    # Print summary
    print(f"\nTransformation complete:")
    print(f"  - Transformed {len(transformed_files)} files")
    print(f"  - Made {total_replacements} replacements")

    # Print list of transformed files
    if transformed_files:
        print("\nTransformed files:")
        for file_path in transformed_files:
            print(f"  - {file_path.relative_to(ROOT_DIR)}")


if __name__ == "__main__":
    main()
