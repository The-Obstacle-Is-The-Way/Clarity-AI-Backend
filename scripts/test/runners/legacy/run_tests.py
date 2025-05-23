#!/usr/bin/env python3
"""
Directory-Based Test Runner for Novamind Digital Twin

This script implements the directory SSOT approach for test execution.
Tests are organized by dependency level in directories:
  - standalone/ - No external dependencies (fastest)
  - venv/ - Python package dependencies (medium)
  - integration/ - External services required (slowest)

Usage:
    python scripts/run_tests.py --all               # Run all tests
    python scripts/run_tests.py --standalone        # Run standalone tests only
    python scripts/run_tests.py --coverage          # Generate coverage reports
"""

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


# ANSI color codes for terminal output
class Color:
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


def print_header(message: str) -> None:
    """Print a formatted header message."""
    print(f"\n{Color.BOLD}{Color.BLUE}{'=' * 80}{Color.ENDC}")
    print(f"{Color.BOLD}{Color.BLUE}{message.center(80)}{Color.ENDC}")
    print(f"{Color.BOLD}{Color.BLUE}{'=' * 80}{Color.ENDC}\n")


def print_section(message: str) -> None:
    """Print a formatted section header."""
    print(f"\n{Color.BOLD}{Color.YELLOW}{message}{Color.ENDC}")
    print(f"{Color.BOLD}{Color.YELLOW}{'-' * len(message)}{Color.ENDC}\n")


def run_command(cmd: list[str], env: dict[str, str] | None = None) -> tuple[bool, str, float]:
    """Run a command and return success status, output, and execution time."""
    print(f"Running: {' '.join(cmd)}")
    start_time = time.time()

    try:
        # Use provided environment or current environment
        env_vars = env or os.environ.copy()

        # Run the command
        result = subprocess.run(
            cmd,
            env=env_vars,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        # Check if the command succeeded
        success = result.returncode == 0
        output = result.stdout
    except Exception as e:
        success = False
        output = str(e)

    # Calculate execution time
    execution_time = time.time() - start_time
    return success, output, execution_time


def ensure_test_directories():
    """Ensure test directory structure exists."""
    tests_dir = Path("app/tests")
    for directory in ["standalone", "venv", "integration"]:
        dir_path = tests_dir / directory
        dir_path.mkdir(exist_ok=True, parents=True)

        # Create __init__.py files for Python imports
        init_file = dir_path / "__init__.py"
        if not init_file.exists():
            init_file.touch()


def run_test_directory(
    directory: str, coverage: bool, junit: bool, markers: str | None
) -> tuple[bool, float]:
    """Run tests in the specified directory."""
    print_section(f"Running {directory.capitalize()} Tests")

    # Base pytest command
    cmd = ["python", "-m", "pytest", f"app/tests/{directory}/", "-v"]

    # Add coverage options if requested
    if coverage:
        cmd.extend(
            [
                "--cov=app",
                f"--cov-report=html:coverage_html/{directory}_tests",
                "--cov-report=term",
            ]
        )

    # Add JUnit XML output if requested
    if junit:
        cmd.append(f"--junitxml=test-results/{directory}-results.xml")

    # Add markers if specified
    if markers:
        cmd.extend(["-m", markers])

    # Set up environment variables
    env = os.environ.copy()
    if directory == "integration":
        env.update(
            {
                "TESTING": "True",
                "DATABASE_URL": os.environ.get(
                    "DATABASE_URL",
                    "postgresql://postgres:postgres@localhost:5432/novamind_test",
                ),
            }
        )

    # Run the tests
    success, output, execution_time = run_command(cmd, env)

    # Print output and result
    print(output)
    status = f"{Color.GREEN}PASSED{Color.ENDC}" if success else f"{Color.RED}FAILED{Color.ENDC}"
    print(f"\n{directory.capitalize()} Tests: {status} in {execution_time:.2f}s\n")

    return success, execution_time


def generate_coverage_report() -> None:
    """Generate combined coverage report from all test runs."""
    print_section("Generating Combined Coverage Report")

    # Combine coverage data
    run_command(["python", "-m", "coverage", "combine"])

    # Generate reports
    run_command(["python", "-m", "coverage", "html", "-d", "coverage_html/combined"])

    # Show report
    success, output, _ = run_command(["python", "-m", "coverage", "report"])
    print(output)


def main() -> int:
    """Main function to parse arguments and run tests."""
    parser = argparse.ArgumentParser(description="Novamind Test Runner (Directory SSOT)")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--standalone", action="store_true", help="Run standalone tests")
    parser.add_argument("--venv", action="store_true", help="Run VENV tests")
    parser.add_argument("--integration", action="store_true", help="Run integration tests")
    parser.add_argument("--coverage", action="store_true", help="Generate coverage reports")
    parser.add_argument("--junit", action="store_true", help="Generate JUnit XML reports")
    parser.add_argument("--markers", type=str, help="Only run tests with specific markers")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Default to running all tests if no specific test type specified
    if not (args.standalone or args.venv or args.integration or args.all):
        args.all = True

    # Print banner
    print_header("Novamind Digital Twin Test Runner (Directory SSOT)")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Ensure directory structure exists
    ensure_test_directories()

    # Create results directory for JUnit reports
    if args.junit:
        Path("test-results").mkdir(exist_ok=True)

    results = {}
    execution_times = {}

    # Run standalone tests
    if args.standalone or args.all:
        results["standalone"], execution_times["standalone"] = run_test_directory(
            "standalone", args.coverage, args.junit, args.markers
        )

    # Run VENV tests only if standalone tests pass (when running all)
    if args.venv or args.all:
        if args.all and not results.get("standalone", True):
            print(f"{Color.YELLOW}Skipping VENV tests due to standalone test failures{Color.ENDC}")
            results["venv"] = False
        else:
            results["venv"], execution_times["venv"] = run_test_directory(
                "venv", args.coverage, args.junit, args.markers
            )

    # Run integration tests only if VENV tests pass (when running all)
    if args.integration or args.all:
        if args.all and not results.get("venv", True):
            print(f"{Color.YELLOW}Skipping integration tests due to VENV test failures{Color.ENDC}")
            results["integration"] = False
        else:
            results["integration"], execution_times["integration"] = run_test_directory(
                "integration", args.coverage, args.junit, args.markers
            )

    # Generate combined coverage report
    if args.coverage and any(results.values()):
        generate_coverage_report()

    # Print summary
    print_header("Test Summary")

    for test_type, success in results.items():
        status = f"{Color.GREEN}PASSED{Color.ENDC}" if success else f"{Color.RED}FAILED{Color.ENDC}"
        time_info = (
            f" ({execution_times.get(test_type, 0):.2f}s)" if test_type in execution_times else ""
        )
        print(f"{test_type.capitalize()} Tests: {status}{time_info}")

    # Return appropriate exit code
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
