#!/usr/bin/env python3
"""
Generate Coverage Report

This script generates a coverage report from existing coverage data
without running the tests again. This is useful when tests might hang
or take too long to run.

Usage:
    python -m backend.scripts.generate_coverage_report
"""

import subprocess
import sys
from pathlib import Path


def generate_coverage_report():
    """Generate coverage report from existing coverage data."""
    base_dir = Path(__file__).resolve().parent.parent
    print(f"Base directory: {base_dir}")

    # Check if .coverage file exists
    coverage_file = base_dir / ".coverage"
    if not coverage_file.exists():
        # Try to find any .coverage files
        potential_files = list(base_dir.glob("**/.coverage"))
        if potential_files:
            coverage_file = potential_files[0]
            print(f"Found .coverage file at: {coverage_file}")
        else:
            print(
                "No .coverage file found. Running a quick test to generate coverage data..."
            )
            # Run a quick test to generate coverage data
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    str(base_dir / "app" / "tests" / "core" / "services" / "ml"),
                    "--cov=app.core.services.ml",
                    "--cov-report=term-missing",
                ],
                cwd=base_dir,
            )

    # Generate the coverage report
    print("\nGenerating coverage report...")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "coverage",
            "report",
            "--include=app/**/*.py",
            "--omit=app/tests/**/*",
        ],
        cwd=base_dir,
        capture_output=True,
        text=True,
    )

    print(result.stdout)

    if result.stderr:
        print("Errors:", result.stderr)

    # Generate HTML report
    print("\nGenerating HTML coverage report...")
    html_dir = base_dir / "coverage_html"
    html_dir.mkdir(exist_ok=True)

    subprocess.run(
        [
            sys.executable,
            "-m",
            "coverage",
            "html",
            "--include=app/**/*.py",
            "--omit=app/tests/**/*",
            "-d",
            str(html_dir),
        ],
        cwd=base_dir,
    )

    print(f"\nHTML coverage report generated at: {html_dir}")
    print(f"You can view it by opening: file://{html_dir}/index.html")

    # Parse overall coverage percentage
    coverage_percentage = 0
    for line in result.stdout.split("\n"):
        if "TOTAL" in line and "%" in line:
            parts = line.split()
            for part in parts:
                if "%" in part:
                    try:
                        coverage_percentage = float(part.strip("%"))
                    except:
                        pass

    print(f"\nOverall coverage: {coverage_percentage:.2f}%")
    if coverage_percentage >= 80:
        print("✅ Coverage meets the 80% target!")
    else:
        print(f"❌ Coverage is below the 80% target by {80 - coverage_percentage:.2f}%")

    # Generate a JSON report for CI pipelines
    json_report = base_dir / "coverage.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "coverage",
            "json",
            "--include=app/**/*.py",
            "--omit=app/tests/**/*",
            "-o",
            str(json_report),
        ],
        cwd=base_dir,
    )

    print(f"\nJSON coverage report generated at: {json_report}")

    return True


if __name__ == "__main__":
    generate_coverage_report()
