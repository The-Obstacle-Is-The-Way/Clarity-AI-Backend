#!/usr/bin/env python
"""
Script to find and fix syntax errors in test files.
This script will scan all test files in the backend directory,
check them for syntax errors, and provide information about each error.
"""

import os
import sys
import py_compile
import subprocess
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


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
        return str(e)
    except Exception as e:
        return str(e)


def verify_with_pytest(file_path):
    """Verify the file with pytest collect-only."""
    result = subprocess.run(
        ["python", "-m", "pytest", file_path, "--collect-only", "-q"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, result.stderr


def main():
    """Main function."""
    # Find the backend directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(script_dir)))

    # Find all test files
    logger.info(f"Searching for test files in {backend_dir}")
    test_files = find_test_files(backend_dir)
    logger.info(f"Found {len(test_files)} test files")

    # Check each file for syntax errors
    files_with_errors = []
    for file_path in test_files:
        rel_path = os.path.relpath(file_path, backend_dir)
        error = check_syntax(file_path)
        if error:
            logger.error(f"Syntax error in {rel_path}: {error}")
            files_with_errors.append((rel_path, error))
        else:
            # Double-check with pytest collect-only
            success, error_msg = verify_with_pytest(file_path)
            if not success:
                logger.error(f"Pytest collection error in {rel_path}: {error_msg}")
                files_with_errors.append((rel_path, error_msg))

    # Report summary
    logger.info("\nSummary:")
    logger.info(f"Total test files: {len(test_files)}")
    logger.info(f"Files with syntax errors: {len(files_with_errors)}")

    if files_with_errors:
        logger.info("\nFiles that need fixing:")
        for rel_path, error in files_with_errors:
            logger.info(f"- {rel_path}: {error}")

        # Export list of files with errors to a text file for easy reference
        with open(os.path.join(backend_dir, "syntax_error_files.txt"), "w") as f:
            for rel_path, error in files_with_errors:
                f.write(f"{rel_path}: {error}\n")
        logger.info(
            f"\nList of files with errors saved to {os.path.join(backend_dir, 'syntax_error_files.txt')}"
        )
    else:
        logger.info("All test files passed syntax check!")


if __name__ == "__main__":
    main()
