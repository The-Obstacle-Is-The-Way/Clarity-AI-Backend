#!/usr/bin/env python3
"""
Test runner script for Novamind Backend.

This script discovers and runs all tests in the project, with options to filter tests by category,
module, or specific test. It provides better error reporting and summary statistics.
"""

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


def get_project_root():
    """Return the project root directory."""
    script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    return script_dir.parent.parent


def discover_test_files(root_dir, pattern="_test.py"):
    """Discover all test files in the project."""
    test_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith(".py") and pattern in filename:
                test_files.append(os.path.join(dirpath, filename))
    return test_files


def run_syntax_check(test_files):
    """Run syntax check on all test files."""
    print(f"Running syntax check on {len(test_files)} test files...")
    valid_files = []
    invalid_files = []

    for test_file in test_files:
        try:
            subprocess.check_output(
                [sys.executable, "-m", "py_compile", test_file],
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            valid_files.append(test_file)
        except subprocess.CalledProcessError as e:
            invalid_files.append((test_file, str(e.output)))

    print(
        f"Syntax check complete: {len(valid_files)} valid, {len(invalid_files)} invalid"
    )
    if invalid_files:
        print("\nFiles with syntax errors:")
        for test_file, error in invalid_files:
            print(f"  {test_file}")
            print(f"    Error: {error}")

    return valid_files, invalid_files


def run_pytest(test_files, args):
    """Run pytest on all valid test files."""
    if not test_files:
        print("No valid test files to run.")
        return False

    print(f"Running tests on {len(test_files)} files...")
    start_time = time.time()

    # Build pytest command
    cmd = [sys.executable, "-m", "pytest"] + test_files

    # Add any additional pytest arguments
    if args.verbose:
        cmd.append("-v")
    if args.xvs:
        cmd.append("-xvs")

    # Run pytest
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Print output
    print(result.stdout)
    if result.stderr:
        print("Errors:", result.stderr)

    end_time = time.time()
    print(f"Tests completed in {end_time - start_time:.2f} seconds")

    return result.returncode == 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run Novamind Backend tests")
    parser.add_argument(
        "--pattern", default="_test.py", help="Pattern to match test files"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--xvs",
        action="store_true",
        help="Run with -xvs flags (exit first, verbose, no capture)",
    )
    parser.add_argument("--skip-syntax", action="store_true", help="Skip syntax check")
    parser.add_argument(
        "--module", help="Test module to run (e.g., 'unit' or 'security')"
    )
    args = parser.parse_args()

    project_root = get_project_root()
    app_tests_dir = os.path.join(project_root, "app", "tests")

    print("Novamind Backend Test Runner")
    print(f"Project root: {project_root}")
    print(f"Tests directory: {app_tests_dir}")

    # Discover test files
    if args.module:
        test_dir = os.path.join(app_tests_dir, args.module)
        test_files = discover_test_files(test_dir, args.pattern)
        print(f"Found {len(test_files)} test files in module '{args.module}'")
    else:
        test_files = discover_test_files(app_tests_dir, args.pattern)
        print(f"Found {len(test_files)} test files in all modules")

    # Run syntax check if not skipped
    if not args.skip_syntax:
        valid_files, invalid_files = run_syntax_check(test_files)
        if invalid_files:
            print("\nPlease fix syntax errors before running tests.")
            return 1
        test_files = valid_files

    # Run tests
    success = run_pytest(test_files, args)

    # Generate report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(project_root, "test-results")
    os.makedirs(report_dir, exist_ok=True)

    with open(os.path.join(report_dir, f"test_run_{timestamp}.log"), "w") as f:
        f.write(f"Test run at {datetime.now()}\n")
        f.write(f"Total test files: {len(test_files)}\n")
        f.write(f"Test result: {'Success' if success else 'Failure'}\n")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
