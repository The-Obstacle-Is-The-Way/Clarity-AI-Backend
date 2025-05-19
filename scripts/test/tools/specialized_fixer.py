#!/usr/bin/env python
"""
Specialized script to fix common syntax errors in test files.
This script handles specific patterns of errors found in the codebase.
"""

import os
import sys
import re
import ast
import py_compile
from pathlib import Path
import logging
import tempfile
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Common error patterns and their fixes
FIXES = [
    # Fix empty import parentheses: from module import ()
    (
        r"from\s+(\S+)\s+import\s+\(\)",
        r"from \1 import object  # TODO: Replace with actual imports",
    ),
    # Fix function definition missing colon: def __init__()
    (r"def\s+(\w+)\s*\(\s*([^)]*)\s*\)(\s*$)", r"def \1(\2):\3    pass"),
    # Fix unmatched brackets in dict creation: dict({)
    (r"([^{]*\w+\s*=\s*)?(\w+)\(?\{(\s*$|\))", r"\1\2({})"),
    # Fix JSON dict with unmatched brackets: json.dumps({)
    (r"(json\.dumps)\s*\(\s*\{(\s*$|\))", r"\1({})"),
    # Fix invalid comma or syntax in function arguments
    (r"(\w+)\s*\(\s*$", r"\1()"),
    # Fix import statements with 'as' incorrectly placed
    (r"from\s+(\S+)\s+import\s+(\S+)\s*,\s*as\s+(\S+)", r"from \1 import \2 as \3"),
    # Fix timedelta with multiple parameters using comma
    (
        r"timedelta\(days=(\d+),\s*hours=(\d+)\)",
        r"timedelta(days=\1) + timedelta(hours=\2)",
    ),
]


def find_test_files(root_dir):
    """Find all test files in the given directory."""
    test_files = []
    for path in Path(root_dir).rglob("test_*.py"):
        test_files.append(str(path))
    return test_files


def check_syntax(file_path):
    """Check file for syntax errors."""
    try:
        py_compile.compile(file_path, doraise=True)
        return None
    except py_compile.PyCompileError as e:
        return str(e)
    except SyntaxError as e:
        return f"Line {e.lineno}, col {e.offset}: {e.msg}"
    except Exception as e:
        return str(e)


def fix_indentation_errors(content):
    """Fix common indentation errors by setting proper indentation."""
    lines = content.split("\n")
    fixed_lines = []

    indent_level = 0
    for i, line in enumerate(lines):
        # Reset indentation at class and function definitions
        stripped = line.strip()
        if stripped.startswith(("class ", "def ")) and stripped.endswith(":"):
            if stripped.startswith("class"):
                indent_level = 0
            else:
                # For nested functions inside classes
                if i > 0 and lines[i - 1].strip().startswith("class"):
                    indent_level = 1
                else:
                    indent_level = 0

        # Increase indentation after colons
        if stripped.endswith(":"):
            indent_level += 1

        # Decrease indentation for returns, etc.
        if stripped.startswith(("return", "break", "continue", "pass", "raise")):
            if indent_level > 0:
                indent_level -= 1

        # Apply indentation to current line
        if (
            stripped
            and not line.startswith(" " * (4 * indent_level))
            and not line.startswith("import ")
            and not line.startswith("from ")
        ):
            # Skip comments and imports
            if (
                not stripped.startswith("#")
                and not stripped.startswith("import ")
                and not stripped.startswith("from ")
            ):
                line = " " * (4 * indent_level) + stripped

        fixed_lines.append(line)

    return "\n".join(fixed_lines)


def apply_regex_fixes(content):
    """Apply regex-based fixes to content."""
    for pattern, replacement in FIXES:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
    return content


def add_missing_imports(content):
    """Add missing imports that are commonly used in tests."""
    # Look for common patterns that suggest missing imports
    imports_to_add = []

    if "MagicMock" in content and "from unittest.mock import " not in content:
        imports_to_add.append("from unittest.mock import MagicMock, patch, AsyncMock")

    if "json.dumps" in content and "import json" not in content:
        imports_to_add.append("import json")

    if (
        "datetime" in content
        and "import datetime" not in content
        and "from datetime import " not in content
    ):
        imports_to_add.append("from datetime import datetime, timedelta")

    if "pytest" in content and "import pytest" not in content:
        imports_to_add.append("import pytest")

    # Add the imports at the top of the file after existing imports
    if imports_to_add:
        lines = content.split("\n")
        import_section_end = 0

        # Find where the import section ends
        for i, line in enumerate(lines):
            if line.strip().startswith(("import ", "from ")):
                import_section_end = i + 1

        # Insert our imports
        for imp in imports_to_add:
            lines.insert(import_section_end, imp)
            import_section_end += 1

        content = "\n".join(lines)

    return content


def fix_file(file_path):
    """Apply all fixes to a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Store original content to check if changes were made
        original_content = content

        # Apply fixes
        content = apply_regex_fixes(content)
        content = fix_indentation_errors(content)
        content = add_missing_imports(content)

        # If changes were made, write back to file
        if content != original_content:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True

        return False
    except Exception as e:
        logger.error(f"Error fixing {file_path}: {e}")
        return False


def main():
    """Main function."""
    # Find the backend directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(script_dir)))

    # Parse command-line arguments
    import argparse

    parser = argparse.ArgumentParser(
        description="Fix specific syntax errors in Python test files"
    )
    parser.add_argument(
        "--file", help="Path to specific file to fix (relative to backend dir)"
    )
    args = parser.parse_args()

    if args.file:
        # Fix a specific file
        file_path = os.path.join(backend_dir, args.file)
        logger.info(f"Fixing specific file: {file_path}")

        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return

        before_error = check_syntax(file_path)
        fixed = fix_file(file_path)
        after_error = check_syntax(file_path)

        if not after_error:
            logger.info(f"Successfully fixed {args.file}")
        else:
            logger.warning(f"Failed to completely fix {args.file}")
            logger.warning(f"Before: {before_error}")
            logger.warning(f"After: {after_error}")

        return

    # Find all test files
    logger.info(f"Searching for test files in {backend_dir}")
    test_files = find_test_files(backend_dir)
    logger.info(f"Found {len(test_files)} test files")

    # Check each file for syntax errors and fix if possible
    files_with_errors = []
    fixed_files = []
    files_still_with_errors = []

    for file_path in test_files:
        rel_path = os.path.relpath(file_path, backend_dir)

        # Check for syntax errors
        error = check_syntax(file_path)
        if error:
            logger.info(f"Attempting to fix {rel_path}")
            files_with_errors.append(rel_path)

            # Try to fix
            fixed = fix_file(file_path)

            # Check if fixed
            new_error = check_syntax(file_path)
            if not new_error:
                logger.info(f"Successfully fixed {rel_path}")
                fixed_files.append(rel_path)
            else:
                logger.warning(f"Could not fix {rel_path}: {new_error}")
                files_still_with_errors.append((rel_path, new_error))

    # Report summary
    logger.info("\nRepair Summary:")
    logger.info(f"  Total test files: {len(test_files)}")
    logger.info(f"  Files with errors: {len(files_with_errors)}")
    logger.info(f"  Successfully fixed: {len(fixed_files)}")
    logger.info(f"  Failed to fix: {len(files_still_with_errors)}")

    if files_still_with_errors:
        logger.warning("Some files still need manual fixes. See above for details.")

        # Export list of files with errors to a text file for easy reference
        with open(os.path.join(backend_dir, "unfixed_syntax_errors.txt"), "w") as f:
            for rel_path, error in files_still_with_errors:
                f.write(f"{rel_path}: {error}\n")
    else:
        logger.info("All syntax errors have been fixed!")


if __name__ == "__main__":
    main()
