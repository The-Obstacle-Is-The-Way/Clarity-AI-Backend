#!/usr/bin/env python3
"""
Strategic Linting Coordinator for Clarity-AI-Backend.

This script orchestrates the systematic resolution of linting issues across the codebase.
It follows a phased approach to ensure high-quality fixes while maintaining HIPAA compliance
and code functionality.

Phases:
1. Assessment - Evaluate current state and generate detailed reports
2. Critical Fixes - Address security and potential runtime issues
3. Code Organization - Fix imports and structure
4. Type System - Improve type annotations
5. Style Consistency - Apply consistent formatting
6. Verification - Ensure all tests still pass

"""

import argparse
import json
import subprocess
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict

# Configure paths
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
APP_DIR = PROJECT_ROOT / "app"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"


class Phase(str, Enum):
    """Phases for the linting strategy."""

    ASSESSMENT = "assessment"
    CRITICAL = "critical"
    ORGANIZATION = "organization"
    TYPES = "types"
    STYLE = "style"
    VERIFICATION = "verification"
    ALL = "all"


def run_command(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command and return returncode, stdout, stderr."""
    if cwd is None:
        cwd = PROJECT_ROOT

    result = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    return result.returncode, result.stdout, result.stderr


def run_tests() -> tuple[int, str]:
    """Run the test suite to verify fixes haven't broken functionality."""
    print("Running tests to verify fixes...")
    cmd = ["python", "-m", "pytest"]
    returncode, stdout, stderr = run_command(cmd)
    return returncode, stdout + stderr


def print_header(title: str) -> None:
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f" {title} ".center(80, "="))
    print("=" * 80 + "\n")


def print_subheader(title: str) -> None:
    """Print a formatted subheader."""
    print("\n" + "-" * 60)
    print(f" {title} ".center(60, "-"))
    print("-" * 60 + "\n")


def assessment_phase() -> None:
    """
    Assessment Phase:
    - Generate reports on current linting state
    - Identify critical issues
    - Create prioritized fix plan
    """
    print_header("PHASE 1: ASSESSMENT")

    # Generate ruff report
    print_subheader("Running Ruff Analysis")
    fix_script = SCRIPTS_DIR / "fix_linting_issues.py"
    cmd = ["python", str(fix_script), "--report"]
    returncode, stdout, stderr = run_command(cmd)
    print(stdout + stderr)

    # Generate mypy report
    print_subheader("Running Type Checking Analysis")
    type_script = SCRIPTS_DIR / "fix_mypy_issues.py"
    cmd = ["python", str(type_script), "--report-only"]
    returncode, stdout, stderr = run_command(cmd)
    print(stdout + stderr)

    # Check formatting with black
    print_subheader("Checking Code Formatting")
    cmd = ["python", "-m", "black", "--check", "app"]
    returncode, stdout, stderr = run_command(cmd)
    print(stdout + stderr)

    # Generate assessment summary
    print_subheader("Assessment Summary")

    # Load reports if they exist
    lint_report_path = PROJECT_ROOT / "lint_report.json"
    typing_report_path = PROJECT_ROOT / "typing_report.json"

    summary: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "linting": {},
        "typing": {},
        "formatting": {},
    }

    if lint_report_path.exists():
        with open(lint_report_path) as f:
            lint_data = json.load(f)
            if "ruff" in lint_data and "stats" in lint_data["ruff"]:
                total_issues = sum(int(count) for count in lint_data["ruff"]["stats"].values())
                summary["linting"] = {
                    "total_issues": total_issues,
                    "categories": lint_data["ruff"]["stats"],
                }

    if typing_report_path.exists():
        with open(typing_report_path) as f:
            typing_data = json.load(f)
            if "analysis" in typing_data:
                summary["typing"] = {
                    "total_issues": typing_data["analysis"]["total_issues"],
                    "total_files": typing_data["analysis"]["total_files"],
                    "common_patterns": typing_data["analysis"]["common_patterns"],
                }

    # Create recommendation plan
    recommendations = []

    if summary.get("linting", {}).get("total_issues", 0) > 0:
        security_issues = int(summary.get("linting", {}).get("categories", {}).get("S", 0))
        if security_issues > 0:
            recommendations.append(f"CRITICAL: Fix {security_issues} security issues first")

        recommendations.append("Fix import and structural issues")
        recommendations.append("Address unused code and variables")

    if summary.get("typing", {}).get("total_issues", 0) > 0:
        recommendations.append(
            f"Add type annotations to {summary.get('typing', {}).get('total_files', 0)} files"
        )

    # Save assessment summary
    summary["recommendations"] = recommendations
    summary_path = PROJECT_ROOT / "linting_assessment.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"Assessment summary saved to {summary_path}")
    print("\nRecommendations:")
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec}")


def critical_phase() -> None:
    """
    Critical Phase:
    - Fix security issues (S)
    - Fix exception handling (B)
    """
    print_header("PHASE 2: CRITICAL FIXES")

    # Fix security issues
    print_subheader("Fixing Security Issues")
    fix_script = SCRIPTS_DIR / "fix_linting_issues.py"
    cmd = ["python", str(fix_script), "--phase", "security"]
    returncode, stdout, stderr = run_command(cmd)
    print(stdout + stderr)

    # Fix exception handling
    print_subheader("Fixing Exception Handling")
    cmd = ["python", str(fix_script), "--phase", "exceptions"]
    returncode, stdout, stderr = run_command(cmd)
    print(stdout + stderr)

    # Verify with tests
    print_subheader("Verifying Fixes with Tests")
    returncode, output = run_tests()
    if returncode != 0:
        print("WARNING: Tests are failing after critical fixes. Review changes!")
    else:
        print("Tests passed successfully after critical fixes.")


def organization_phase() -> None:
    """
    Organization Phase:
    - Fix imports
    - Fix unused code
    """
    print_header("PHASE 3: CODE ORGANIZATION")

    # Fix imports
    print_subheader("Fixing Import Issues")
    fix_script = SCRIPTS_DIR / "fix_linting_issues.py"
    cmd = ["python", str(fix_script), "--phase", "imports"]
    returncode, stdout, stderr = run_command(cmd)
    print(stdout + stderr)

    # Fix unused code
    print_subheader("Fixing Unused Code")
    cmd = ["python", str(fix_script), "--phase", "unused"]
    returncode, stdout, stderr = run_command(cmd)
    print(stdout + stderr)

    # Verify with tests
    print_subheader("Verifying Fixes with Tests")
    returncode, output = run_tests()
    if returncode != 0:
        print("WARNING: Tests are failing after organization fixes. Review changes!")
    else:
        print("Tests passed successfully after organization fixes.")


def types_phase() -> None:
    """
    Types Phase:
    - Fix missing return types
    - Fix missing parameter types
    """
    print_header("PHASE 4: TYPE SYSTEM")

    # Fix return types
    print_subheader("Fixing Return Type Annotations")
    type_script = SCRIPTS_DIR / "fix_mypy_issues.py"
    cmd = ["python", str(type_script), "--fix-returns"]
    returncode, stdout, stderr = run_command(cmd)
    print(stdout + stderr)

    # Fix parameter types
    print_subheader("Fixing Parameter Type Annotations")
    cmd = ["python", str(type_script), "--fix-params"]
    returncode, stdout, stderr = run_command(cmd)
    print(stdout + stderr)

    # Fix other type annotations with ruff
    print_subheader("Fixing Other Type Issues")
    fix_script = SCRIPTS_DIR / "fix_linting_issues.py"
    cmd = ["python", str(fix_script), "--phase", "types"]
    returncode, stdout, stderr = run_command(cmd)
    print(stdout + stderr)

    # Verify with tests
    print_subheader("Verifying Fixes with Tests")
    returncode, output = run_tests()
    if returncode != 0:
        print("WARNING: Tests are failing after type fixes. Review changes!")
    else:
        print("Tests passed successfully after type fixes.")


def style_phase() -> None:
    """
    Style Phase:
    - Apply consistent formatting with black
    - Fix remaining style issues
    """
    print_header("PHASE 5: STYLE CONSISTENCY")

    # Apply black formatting
    print_subheader("Applying Black Formatting")
    fix_script = SCRIPTS_DIR / "fix_linting_issues.py"
    cmd = ["python", str(fix_script), "--phase", "formatting"]
    returncode, stdout, stderr = run_command(cmd)
    print(stdout + stderr)

    # Verify with tests
    print_subheader("Verifying Fixes with Tests")
    returncode, output = run_tests()
    if returncode != 0:
        print("WARNING: Tests are failing after style fixes. Review changes!")
    else:
        print("Tests passed successfully after style fixes.")


def verification_phase() -> None:
    """
    Verification Phase:
    - Run all linters to confirm issues are fixed
    - Run tests to ensure functionality
    """
    print_header("PHASE 6: VERIFICATION")

    # Check ruff
    print_subheader("Verifying Ruff Linting")
    cmd = ["python", "-m", "ruff", "check", "app"]
    returncode, stdout, stderr = run_command(cmd)
    if returncode == 0:
        print("✅ No ruff issues found!")
    else:
        print("⚠️ Some ruff issues remain:")
        print(stdout + stderr)

    # Check mypy
    print_subheader("Verifying Type Checking")
    cmd = ["python", "-m", "mypy", "app"]
    returncode, stdout, stderr = run_command(cmd)
    if returncode == 0:
        print("✅ No type issues found!")
    else:
        print("⚠️ Some type issues remain:")
        print(stdout + stderr)

    # Check black
    print_subheader("Verifying Formatting")
    cmd = ["python", "-m", "black", "--check", "app"]
    returncode, stdout, stderr = run_command(cmd)
    if returncode == 0:
        print("✅ Formatting is consistent!")
    else:
        print("⚠️ Some formatting issues remain:")
        print(stdout + stderr)

    # Run tests
    print_subheader("Running Full Test Suite")
    returncode, output = run_tests()
    if returncode == 0:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests are failing:")
        print(output)

    # Generate final report
    print_subheader("Generating Final Report")
    assessment_phase()


def main():
    """Main function to orchestrate the linting strategy."""
    parser = argparse.ArgumentParser(
        description="Strategic approach to fixing linting issues in Clarity-AI-Backend."
    )
    parser.add_argument(
        "--phase",
        type=str,
        choices=[p.value for p in Phase],
        default=Phase.ASSESSMENT.value,
        help="Phase to run (default: assessment)",
    )
    parser.add_argument("--all", action="store_true", help="Run all phases in sequence")
    args = parser.parse_args()

    if args.all:
        # Run all phases in order
        assessment_phase()
        critical_phase()
        organization_phase()
        types_phase()
        style_phase()
        verification_phase()
        return

    # Run specific phase
    if args.phase == Phase.ASSESSMENT.value:
        assessment_phase()
    elif args.phase == Phase.CRITICAL.value:
        critical_phase()
    elif args.phase == Phase.ORGANIZATION.value:
        organization_phase()
    elif args.phase == Phase.TYPES.value:
        types_phase()
    elif args.phase == Phase.STYLE.value:
        style_phase()
    elif args.phase == Phase.VERIFICATION.value:
        verification_phase()
    elif args.phase == Phase.ALL.value:
        # Same as --all flag
        assessment_phase()
        critical_phase()
        organization_phase()
        types_phase()
        style_phase()
        verification_phase()


if __name__ == "__main__":
    main()
