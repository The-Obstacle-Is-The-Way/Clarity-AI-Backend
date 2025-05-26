#!/usr/bin/env python3
"""
Test Runner for Novamind Backend

This script runs tests based on directory structure rather than markers:
1. Standalone tests (app/tests/standalone) - No dependencies beyond Python
2. VENV tests (app/tests/unit) - Requires Python packages but no external services
3. Integration tests (app/tests/integration) - Requires database and external services

This is an industry-standard approach that uses convention over configuration.
"""

import argparse
import os
import subprocess
import sys
from typing import Optional


# ANSI colors for terminal output
class Colors:
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    RED = "\033[0;31m"
    BLUE = "\033[0;34m"
    BOLD = "\033[1m"
    NC = "\033[0m"  # No Color


# Test levels in order of dependency (least dependent first)
TEST_LEVELS = [
    {
        "name": "Standalone Tests",
        "path": "app/tests/standalone/",
        "description": "Tests with no external dependencies",
        "skip_flag": "--skip-standalone",
    },
    {
        "name": "VENV Tests",
        "path": "app/tests/unit/",
        "description": "Tests requiring Python packages but no external services",
        "skip_flag": "--skip-venv",
    },
    {
        "name": "Integration Tests",
        "path": "app/tests/integration/",
        "description": "Tests requiring database and external services",
        "skip_flag": "--skip-db",
    },
]


def get_project_root() -> str:
    """Get the project root directory."""
    # Assuming this script is in the backend/scripts directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(script_dir)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Run tests in dependency order based on directory structure."
    )
    for level in TEST_LEVELS:
        parser.add_argument(
            level["skip_flag"],
            action="store_true",
            help=f"Skip {level['name']}",
        )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Run tests with verbose output"
    )
    parser.add_argument("--failfast", action="store_true", help="Stop on first failure")
    parser.add_argument("--ci-mode", action="store_true", help="Generate reports for CI/CD")
    return parser.parse_args()


def run_tests(
    test_directory: str,
    verbose: bool = False,
    failfast: bool = False,
    ci_mode: bool = False,
    report_name: Optional[str] = None,
    coverage_dir: Optional[str] = None,
) -> int:
    """Run tests in the specified directory."""
    project_root = get_project_root()
    test_path = os.path.join(project_root, test_directory)

    # Prepare the pytest command
    cmd = ["python", "-m", "pytest"]

    # Add verbose flag if requested
    if verbose:
        cmd.append("-v")

    # Add failfast flag if requested
    if failfast:
        cmd.append("--exitfirst")

    # Add JUnit XML report output if in CI mode
    if ci_mode and report_name:
        report_dir = os.path.join(project_root, "test-results")
        os.makedirs(report_dir, exist_ok=True)
        cmd.append(f"--junitxml={os.path.join(report_dir, f'{report_name}-results.xml')}")

    # Add coverage reporting
    if coverage_dir:
        coverage_path = os.path.join(project_root, "coverage_html", coverage_dir)
        os.makedirs(coverage_path, exist_ok=True)
        cmd.extend(["--cov=app", "--cov-report=term", f"--cov-report=html:{coverage_path}"])

    # Add the test directory
    cmd.append(test_path)

    # Print the command to be executed
    print(f"{Colors.YELLOW}Running command: {' '.join(cmd)}{Colors.NC}")

    # Execute the pytest command
    result = subprocess.run(cmd, cwd=project_root)
    return result.returncode


def main() -> int:
    """Main function."""
    args = parse_args()
    results: list[tuple[str, Optional[int]]] = []

    print(f"\n{Colors.BLUE}{'=' * 80}{Colors.NC}")
    print(f"{Colors.BLUE}{Colors.BOLD}Novamind Backend Test Runner{Colors.NC}")
    print(f"{Colors.BLUE}{'=' * 80}{Colors.NC}")

    for level in TEST_LEVELS:
        skip_arg = level["skip_flag"].replace("--", "").replace("-", "_")
        if getattr(args, skip_arg, False):
            print(f"\n{Colors.YELLOW}Skipping {level['name']}{Colors.NC}")
            results.append((level["name"], None))
            continue

        print(f"\n{Colors.BLUE}{'=' * 60}{Colors.NC}")
        print(f"{Colors.BLUE}{Colors.BOLD}Running {level['name']}{Colors.NC}")
        print(f"{Colors.BLUE}{level['description']}{Colors.NC}")
        print(f"{Colors.BLUE}{'=' * 60}{Colors.NC}")

        result = run_tests(
            level["path"],
            verbose=args.verbose,
            failfast=args.failfast,
            ci_mode=args.ci_mode,
            report_name=level["name"].lower().replace(" ", "_"),
            coverage_dir=level["name"].lower().replace(" ", "_"),
        )

        results.append((level["name"], result))

        # If the tests failed and --failfast is specified, stop
        if result != 0 and args.failfast:
            print(
                f"\n{Colors.RED}Tests failed with exit code {result}. Stopping as requested by --failfast{Colors.NC}"
            )
            break

    # Print summary
    print(f"\n{Colors.BLUE}{'=' * 60}{Colors.NC}")
    print(f"{Colors.BLUE}{Colors.BOLD}Test Summary{Colors.NC}")
    print(f"{Colors.BLUE}{'=' * 60}{Colors.NC}")

    for name, exit_code in results:
        if exit_code is None:
            print(f"{Colors.YELLOW}• {name}: SKIPPED{Colors.NC}")
        elif exit_code == 0:
            print(f"{Colors.GREEN}✓ {name}: PASSED{Colors.NC}")
        else:
            print(f"{Colors.RED}✗ {name}: FAILED{Colors.NC}")

    # Return non-zero status if any test suite failed
    failed_suites = [exit_code for _, exit_code in results if exit_code is not None and exit_code != 0]
    return 1 if failed_suites else 0


if __name__ == "__main__":
    sys.exit(main())
