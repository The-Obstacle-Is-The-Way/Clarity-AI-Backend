#!/usr/bin/env python
"""
NovaMind Digital Twin Security Test Runner

This script executes the comprehensive security test suite for the
NovaMind Digital Twin backend with HIPAA-compliant reporting.
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List

# Add the root directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))


def run_quantum_security_tests():
    """
    Main function to run all security tests.
    This is designed to be run directly, not as a pytest test case.
    """
    test_runner = SecurityTestRunner()
    test_runner.run_all_tests()
    return test_runner.results


class SecurityTestRunner:
    """Quantum-grade test collector and runner for NovaMind security tests."""

    def __init__(self, output_path: str | None = None):
        """Initialize test runner with output path.

        Args:
            output_path: Path to save test reports
        """
        self.base_dir: str = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.output_path: str = output_path or os.path.join(self.base_dir, "test_results")

        # Ensure output directory exists
        os.makedirs(self.output_path, exist_ok=True)

        # Test categories in priority order
        self.test_categories: List[Dict[str, str]] = [
            {"name": "Core Encryption", "pattern": "**/encryption/test_*.py"},
            {"name": "PHI Handling", "pattern": "**/phi/test_*.py"},
            {"name": "JWT Authentication", "pattern": "**/jwt/test_*.py"},
            {"name": "HIPAA Compliance", "pattern": "**/hipaa/test_*.py"},
            {"name": "PHI Protection", "pattern": "**/phi/test_*.py"},
            {"name": "Security Patterns", "pattern": "**/test_*security*.py"},
            {"name": "Audit Logging", "pattern": "**/audit/test_*.py"},
            {"name": "API Security", "pattern": "**/api/test_*.py"},
            {"name": "Database Security", "pattern": "**/db/test_*.py"},
        ]

        # Test results collection
        self.results: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "errors": 0,
            },
            "categories": {},
        }

    def find_test_files(self, pattern: str) -> List[str]:
        """Find test files matching the pattern.

        Args:
            pattern: Glob pattern to match test files

        Returns:
            List of matching file paths
        """
        import glob

        # Handle both relative and absolute patterns
        search_pattern: str = ""
        if os.path.isabs(pattern):
            search_pattern = pattern
        else:
            search_pattern = os.path.join(self.base_dir, pattern)

        print(f"Searching for files with pattern: {search_pattern}")
        matching_files: List[str] = glob.glob(search_pattern, recursive=True)
        print(f"Found {len(matching_files)} files")
        return matching_files

    def run_pytest(self, test_file: str) -> Dict[str, Any]:
        """Run pytest on a specific test file.

        Args:
            test_file: Path to test file

        Returns:
            Dictionary with test results
        """
        import json
        import os
        import uuid

        # Ensure test_results directory exists in scripts folder
        results_dir: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_results")
        os.makedirs(results_dir, exist_ok=True)

        # Create a unique report filename based on the test file
        test_filename: str = os.path.basename(test_file).replace(".py", "")
        report_file: str = os.path.join(
            results_dir, f"report_{test_filename}_{uuid.uuid4().hex[:8]}.json"
        )

        # Construct pytest command with coverage
        cmd: str = (
            f"{sys.executable} -m pytest "
            f"{test_file} "
            f"--json-report --no-header --no-summary "
            f"--json-report-file {report_file}"
        )

        print(f"Running: {cmd}")
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                check=False,
                capture_output=True,
                text=True,
            )

            print(f"pytest stdout: {result.stdout}")
            print(f"pytest stderr: {result.stderr}")

            # Read the JSON report
            if os.path.exists(report_file):
                with open(report_file) as f:
                    loaded_data: Dict[str, Any] = json.load(f)
                    return loaded_data
            else:
                return {
                    "success": False,
                    "error": f"Report file not found: {report_file}",
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
        except Exception as e:
            return {"success": False, "error": f"Error running test {test_file}: {e!s}"}

    def parse_test_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Parse pytest JSON report into a simplified format.

        Args:
            results: Pytest JSON report

            Returns:
                Simplified test results
        """
        # Extract summary statistics
        summary: Dict[str, int] = {
            "total": int(results.get("summary", {}).get("total", 0)),
            "passed": int(results.get("summary", {}).get("passed", 0)),
            "failed": int(results.get("summary", {}).get("failed", 0)),
            "skipped": int(results.get("summary", {}).get("skipped", 0)),
            "errors": int(results.get("summary", {}).get("errors", 0)),
        }

        # Extract individual test results
        tests: List[Dict[str, Any]] = []
        test_list: List[Dict[str, Any]] = results.get("tests", [])
        for test_data in test_list:
            test_result: Dict[str, Any] = {
                "name": test_data.get("name", ""),
                "outcome": test_data.get("outcome", ""),
                "duration": test_data.get("duration", 0),
                "message": test_data.get("call", {}).get("longrepr", ""),
            }
            tests.append(test_result)

        return {"summary": summary, "tests": tests}

    def run_category(self, cat: Dict[str, str]) -> None:
        """Run tests for a specific category.

        Args:
            cat: Dictionary with category name and file pattern
        """
        category_name: str = cat["name"]
        pattern: str = cat["pattern"]

        print("\n" + "=" * 60)
        print(f"RUNNING TESTS: {category_name}")
        print("=" * 60)

        # Find test files for this category
        test_files: List[str] = self.find_test_files(pattern)

        # Initialize category results
        category_results: Dict[str, Any] = {
            "files_found": len(test_files),
            "files": [],
            "tests": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "errors": 0,
            },
        }

        # Run tests for each file in the category
        for test_file in test_files:
            print(f"\nRunning tests in {test_file}...")
            raw_results: Dict[str, Any] = self.run_pytest(test_file)
            parsed_results: Dict[str, Any] = self.parse_test_results(raw_results)

            # Store file results
            files_list: List[Dict[str, Any]] = category_results["files"]
            files_list.append(
                {
                    "file": test_file,
                    "summary": parsed_results["summary"],
                    "tests": parsed_results["tests"],
                }
            )

            # Accumulate category summary
            test_keys: List[str] = ["total", "passed", "failed", "skipped", "errors"]
            for key in test_keys:
                category_results["tests"][key] = int(category_results["tests"][key]) + int(parsed_results["summary"][key])
                self.results["summary"][key] = int(self.results["summary"][key]) + int(parsed_results["summary"][key])  # Accumulate overall results here

        # Store category results (moved outside the inner loop)
        self.results["categories"][category_name] = category_results

        # Print category summary (moved outside the inner loop)
        print(f"\nSummary for {category_name}:")
        print(f"Files found: {category_results['files_found']}")
        print(
            f"Tests passed: {category_results['tests']['passed']}/{category_results['tests']['total']}"
        )
        if int(category_results["tests"]["failed"]) > 0:
            print(f"Tests failed: {category_results['tests']['failed']}")
        if int(category_results["tests"]["errors"]) > 0:
            print(f"Test errors: {category_results['tests']['errors']}")
        if int(category_results["tests"]["skipped"]) > 0:
            print(f"Tests skipped: {category_results['tests']['skipped']}")

    def run_all_tests(self) -> None:
        """Run all security tests by category."""
        print("Starting NovaMind Digital Twin Security Test Suite...")
        start_time: datetime = datetime.now()
        self.results["start_time"] = start_time.isoformat()

        # Run tests by category
        for cat in self.test_categories:
            category_name: str = cat["name"]
            if category_name not in self.results["categories"]:
                self.results["categories"][category_name] = {}
            print(f"Running {category_name} tests...")
            self.run_category(cat)

        end_time: datetime = datetime.now()
        self.results["end_time"] = end_time.isoformat()
        duration: float = (end_time - start_time).total_seconds()
        self.results["duration"] = duration

        print("\n" + "=" * 60)
        print("TEST SUITE COMPLETE")
        print("=" * 60)
        print(f"Total duration: {duration:.2f} seconds")
        print(
            f"Overall results: {self.results['summary']['passed']}/{self.results['summary']['total']} tests passed"
        )
        if int(self.results["summary"]["failed"]) > 0:
            print(f"Failed tests: {self.results['summary']['failed']}")
        if int(self.results["summary"]["errors"]) > 0:
            print(f"Test errors: {self.results['summary']['errors']}")
        if int(self.results["summary"]["skipped"]) > 0:
            print(f"Skipped tests: {self.results['summary']['skipped']}")

        # Save results to file
        results_file: str = os.path.join(
            self.output_path,
            f"security_test_results_{start_time.strftime('%Y%m%d_%H%M%S')}.json",
        )
        with open(results_file, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"Detailed results saved to: {results_file}")

        try:
            from dashboard.dashboard import generate_dashboard

            dashboard_file: str = os.path.join(
                self.output_path,
                f"security_dashboard_{start_time.strftime('%Y%m%d_%H%M%S')}.html",
            )
            generate_dashboard(self.results, dashboard_file)
            print(f"Dashboard generated at: {dashboard_file}")
        except ImportError:
            print("Dashboard generation module not available.")


if __name__ == "__main__":
    run_quantum_security_tests()
