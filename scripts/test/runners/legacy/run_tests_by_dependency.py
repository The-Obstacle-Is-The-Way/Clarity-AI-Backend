#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Multi-stage Test Runner for Novamind Backend.

This script runs tests in dependency order:
1. Standalone tests (no dependencies)
2. VENV-only tests (require Python packages but no external services)
3. DB-required tests (require database connections)

Running tests in this order allows for faster feedback, as simpler
tests with fewer dependencies run first.

Usage:
    python run_tests_by_dependency.py [--stage STAGE] [--junit]
    
Options:
    --stage STAGE: Run only a specific stage (standalone, venv, db, all)
    --junit: Generate JUnit XML reports for CI systems
    
Example:
    # Run all test stages
    python run_tests_by_dependency.py
    
    # Run only standalone tests
    python run_tests_by_dependency.py --stage standalone
    
    # Run with JUnit report generation
    python run_tests_by_dependency.py --junit
"""

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Constants for dependency levels
class DependencyStage:
    STANDALONE = "standalone"
    VENV = "venv"
    DB = "db"
    ALL = "all"


# Configuration for each test stage
STAGE_CONFIG = {
    DependencyStage.STANDALONE: {
        "marker": "standalone",
        "description": "Standalone tests (no dependencies)",
        "report_file": "standalone-results.xml",
        "requires_db": False,
    },
    DependencyStage.VENV: {
        "marker": "venv_only",
        "description": "VENV-only tests (require Python packages)",
        "report_file": "venv-results.xml",
        "requires_db": False,
    },
    DependencyStage.DB: {
        "marker": "db_required",
        "description": "DB-required tests (require database connections)",
        "report_file": "db-results.xml",
        "requires_db": True,
    },
}


def ensure_backend_directory():
    """Ensure we're running from the backend directory."""
    current_dir = os.path.basename(os.getcwd())
    if current_dir != "backend":
        if os.path.exists("backend"):
            os.chdir("backend")
        else:
            print("Error: Script must be run from the backend directory or its parent")
            sys.exit(1)


def run_test_stage(stage: str, junit: bool = False) -> Tuple[int, float]:
    """
    Run tests for a specific dependency stage.

    Args:
        stage: The stage to run (standalone, venv, db)
        junit: Whether to generate JUnit XML reports

    Returns:
        Tuple of (exit_code, duration_in_seconds)
    """
    if stage not in STAGE_CONFIG:
        print(f"Error: Unknown stage '{stage}'")
        return 1, 0.0

    config = STAGE_CONFIG[stage]

    # Build the pytest command
    cmd = [
        "python",
        "-m",
        "pytest",
        f"-m={config['marker']}",
        "-v",
    ]

    # Add JUnit report generation if requested
    if junit:
        reports_dir = Path("test-results")
        reports_dir.mkdir(exist_ok=True)
        cmd.extend(
            [
                f"--junitxml=test-results/{config['report_file']}",
            ]
        )

    # Start the test run
    print(f"\n{'=' * 80}")
    print(f"Running {config['description']}")
    print(f"{'=' * 80}")

    start_time = time.time()
    process = subprocess.run(cmd)
    duration = time.time() - start_time

    print(f"\nTest stage '{stage}' completed in {duration:.2f} seconds")
    return process.returncode, duration


def ensure_db_available() -> bool:
    """
    Check if a database is available for DB-dependent tests.

    Returns:
        bool: True if DB is available, False otherwise
    """
    # First, check if a database container is running (Docker)
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=postgres", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
        )
        if "postgres" in result.stdout:
            return True
    except Exception:
        pass  # Docker might not be available

    # Next, check if DB_URL is set in environment
    if os.environ.get("DB_URL") or os.environ.get("DATABASE_URL"):
        return True

    # As a last resort, try to import asyncpg to see if we can connect
    try:
        import asyncpg

        return True
    except ImportError:
        pass

    return False


def run_tests(stage: str, junit: bool = False) -> int:
    """
    Run tests for the specified stage(s).

    Args:
        stage: Stage to run (standalone, venv, db, all)
        junit: Whether to generate JUnit XML reports

    Returns:
        int: 0 if all tests pass, non-zero otherwise
    """
    start_time = time.time()
    results = {}

    # Determine which stages to run
    stages_to_run = []
    if stage == DependencyStage.ALL:
        stages_to_run = [
            DependencyStage.STANDALONE,
            DependencyStage.VENV,
            DependencyStage.DB,
        ]
    else:
        stages_to_run = [stage]

    # Run each stage
    failed_stages = []
    all_passed = True

    for current_stage in stages_to_run:
        # Skip DB tests if no database is available
        if STAGE_CONFIG[current_stage]["requires_db"] and not ensure_db_available():
            print(
                f"\nWarning: Skipping {current_stage} tests because no database is available"
            )
            continue

        exit_code, duration = run_test_stage(current_stage, junit)
        results[current_stage] = {
            "exit_code": exit_code,
            "duration": duration,
        }

        if exit_code != 0:
            all_passed = False
            failed_stages.append(current_stage)
            if (
                current_stage != DependencyStage.DB
            ):  # Continue to DB tests even if earlier stages fail
                print(
                    f"\nError: {current_stage} tests failed, but continuing to next stage"
                )

    # Print summary
    total_duration = time.time() - start_time
    print("\n" + "=" * 80)
    print(f"Test Run Summary (total time: {total_duration:.2f}s)")
    print("=" * 80)

    for s, r in results.items():
        status = "PASSED" if r["exit_code"] == 0 else "FAILED"
        print(f"{s.ljust(10)} | {status.ljust(10)} | {r['duration']:.2f}s")

    if not all_passed:
        print(f"\nFailed stages: {', '.join(failed_stages)}")
        return 1

    print("\nAll tests passed!")
    return 0


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description="Run tests by dependency level")
    parser.add_argument(
        "--stage",
        choices=[
            DependencyStage.STANDALONE,
            DependencyStage.VENV,
            DependencyStage.DB,
            DependencyStage.ALL,
        ],
        default=DependencyStage.ALL,
        help="Test stage to run (default: all)",
    )
    parser.add_argument(
        "--junit", action="store_true", help="Generate JUnit XML reports"
    )
    args = parser.parse_args()

    # Ensure we're in the correct directory
    ensure_backend_directory()

    # Run the tests
    exit_code = run_tests(args.stage, args.junit)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
