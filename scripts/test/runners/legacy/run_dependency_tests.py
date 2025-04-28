#!/usr/bin/env python3
"""
Run tests based on dependency level.

This script runs tests at different dependency levels:
1. Standalone tests - no external dependencies
2. VENV-only tests - require Python packages but no external services
3. DB-dependent tests - require database connections or external services

Usage:
    python -m backend.scripts.run_dependency_tests [--level LEVEL] [--verbose]

Options:
    --level LEVEL    The dependency level to run (standalone, venv, db, all). Default: all
    --verbose        Run with verbose output
    --markers        Show markers used for each level
    --dry-run        Show which tests would be run without actually running them
"""

import os
import sys
import argparse
from typing import List, Optional
import subprocess


def setup_parser() -> argparse.ArgumentParser:
    """Set up command line argument parser."""
    parser = argparse.ArgumentParser(description="Run tests based on dependency level")
    parser.add_argument(
        "--level",
        choices=["standalone", "venv", "db", "all"],
        default="all",
        help="The dependency level to run"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Run with verbose output"
    )
    parser.add_argument(
        "--markers",
        action="store_true",
        help="Show markers used for each level"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show which tests would be run without actually running them"
    )
    return parser


def get_marker_for_level(level: str) -> str:
    """Get the pytest marker for a dependency level."""
    markers = {
        "standalone": "standalone",
        "venv": "not db_required and not requires_db",
        "db": "db_required or requires_db",
    }
    return markers.get(level, "")


def build_pytest_command(level: str, verbose: bool, dry_run: bool) -> List[str]:
    """Build the pytest command based on arguments."""
    marker = get_marker_for_level(level)
    
    cmd = ["python", "-m", "pytest"]
    
    if marker:
        cmd.extend(["-m", marker])
    
    if verbose:
        cmd.append("-v")
    
    if dry_run:
        cmd.append("--collect-only")
    
    # Include test directory path
    cmd.append("backend/app/tests/")
    
    return cmd


def run_tests(level: str, verbose: bool, dry_run: bool) -> int:
    """Run tests for the specified dependency level."""
    cmd = build_pytest_command(level, verbose, dry_run)
    
    print(f"\n{'=' * 80}")
    print(f"Running {level} tests")
    print(f"{'=' * 80}")
    print(f"Command: {' '.join(cmd)}\n")
    
    return subprocess.call(cmd)


def run_all_levels(verbose: bool, dry_run: bool) -> None:
    """Run tests for all dependency levels in sequence."""
    results = {}
    
    for level in ["standalone", "venv", "db"]:
        exit_code = run_tests(level, verbose, dry_run)
        results[level] = exit_code
    
    print("\n\nTest Run Summary:")
    print(f"{'=' * 80}")
    for level, exit_code in results.items():
        status = "PASSED" if exit_code == 0 else "FAILED"
        print(f"{level.upper()} tests: {status} (exit code: {exit_code})")
    print(f"{'=' * 80}\n")
    
    # Exit with failure if any test suite failed
    if any(exit_code != 0 for exit_code in results.values()):
        sys.exit(1)


def show_markers() -> None:
    """Show the markers used for each level."""
    print("\nTest Level Markers:")
    print(f"{'=' * 80}")
    for level in ["standalone", "venv", "db"]:
        marker = get_marker_for_level(level)
        print(f"{level.upper()} tests: pytest -m \"{marker}\"")
    print(f"{'=' * 80}\n")


def main() -> None:
    """Run the main program."""
    parser = setup_parser()
    args = parser.parse_args()
    
    if args.markers:
        show_markers()
        return
    
    if args.level == "all":
        run_all_levels(args.verbose, args.dry_run)
    else:
        exit_code = run_tests(args.level, args.verbose, args.dry_run)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()