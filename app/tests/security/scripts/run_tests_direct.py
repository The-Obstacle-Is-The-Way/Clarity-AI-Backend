#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
NovaMind Digital Twin Security Test Runner (Direct Mode)

This script executes the complete security test suite for the NovaMind Digital Twin backend
without requiring extra dependencies, collecting and analyzing results directly from pytest.
"""

import os
import sys
import subprocess
import json
import re
from datetime import datetime
from typing import Dict, List, Any, Tuple

# Add the root directory to Python path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
)


class DirectSecurityTestRunner:
    """Directly run and collect security test results."""

    def __init__(self, output_path: str = None):
        """Initialize test runner with output path.

        Args:
            output_path: Path to save test reports
        """
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.output_path = output_path or os.path.join(
            self.base_dir, "test_results")

        # Ensure output directory exists
        os.makedirs(self.output_path, exist_ok=True)

        # Define all test modules to run in priority order
        self.tests = [
            # Core encryption tests
            {
                "name": "Core Encryption",
                "path": os.path.join(self.base_dir, "test_ml_encryption.py"),
            },
            # PHI field handling
            {
                "name": "PHI Field Handling",
                "path": os.path.join(self.base_dir, "test_address_helper.py"),
            },
            # Enhanced encryption infrastructure
            {
                "name": "Enhanced Encryption",
                "path": os.path.join(self.base_dir, "../unit/infrastructure/security/test_encryption_enhanced.py"),
            },
        ]

        # Results storage
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "tests": {},
            "summary": {"total": 0, "passed": 0, "failed": 0, "errors": 0},
        }

    def run_test(self, test_info: Dict[str, str]) -> Dict[str, Any]:
        """Run a specific test module.

        Args:
            test_info: Dictionary with test name and path

        Returns:
            Test results dictionary
        """
        name = test_info["name"]
        path = test_info["path"]

        print(f"\n{'=' * 60}")
        print(f"RUNNING: {name}")
        print(f"{'=' * 60}")

        # Build the pytest command
        cmd = [sys.executable, "-m", "pytest", path, "-v"]

        # Run the test and capture output
        process = subprocess.run(cmd, capture_output=True, text=True)
        output = process.stdout

        # Parse test results from output
        test_results = self._parse_pytest_output(output)

        # Print summary
        print(f"Tests found: {test_results['total']}")
        print(f"Tests passed: {test_results['passed']}")
        print(f"Tests failed: {test_results['failed']}")
        print(f"Tests with errors: {test_results['errors']}")

        # Update overall counts
        self.results["summary"]["total"] += test_results["total"]
        self.results["summary"]["passed"] += test_results["passed"]
        self.results["summary"]["failed"] += test_results["failed"]
        self.results["summary"]["errors"] += test_results["errors"]

        # Store detailed results
        self.results["tests"][name] = {
            "path": path,
            "results": test_results,
            "output": output,
        }

        return test_results

    def _parse_pytest_output(self, output: str) -> Dict[str, Any]:
        """Parse pytest output to extract test counts and details.

        Args:
            output: Raw pytest output

        Returns:
            Dictionary with test counts and details
        """
        results = {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "details": []
        }

        # Parse each line looking for test results
        for line in output.split("\n"):
            # Skip empty lines
            if not line.strip():
                continue

            # Look for test result lines but handle safely
            if (
                " PASSED " in line
                or " FAILED " in line
                or " ERROR " in line
                or " SKIPPED " in line
            ):
                try:
                    # Extract test name safely
                    parts = line.split("::")
                    if len(parts) >= 2:
                        # Handle full test path with class and method
                        test_name = parts[-1].split()[
                            0
                        ]  # Get the last part and remove status
                    else:
                        # Simplified naming
                        test_name = line.split()[0]

                    # Determine status
                    if " PASSED " in line:
                        status = "passed"
                        results["passed"] += 1
                    elif " FAILED " in line:
                        status = "failed"
                        results["failed"] += 1
                    elif " ERROR " in line:
                        status = "error"
                        results["errors"] += 1
                    else:  # SKIPPED
                        status = "skipped"

                    # Only count as a test if it's an actual test result
                    results["total"] += 1

                    # Add to details
                    results["details"].append(
                        {"name": test_name, "status": status, "full_line": line.strip()}
                    )
                except Exception as e:
                    # If parsing fails, just continue to the next line
                    print(f"Error parsing line: {line} - {str(e)}")
                    continue

        # If we couldn't parse any tests, try the summary line
        if results["total"] == 0:
            # Look for the summary line (e.g., "5 passed, 2 failed in 0.23s")
            summary_pattern = (
                r"(\d+) passed(, (\d+) failed)?(, (\d+) error)?(, (\d+) skipped)? in"
            )
            match = re.search(summary_pattern, output)
            if match:
                try:
                    results["passed"] = int(match.group(1) or 0)
                    results["failed"] = int(match.group(3) or 0)
                    results["errors"] = int(match.group(5) or 0)
                    results["total"] = (
                        results["passed"] + results["failed"] + results["errors"]
                    )
                except (ValueError, IndexError):
                    # If summary parsing fails, keep zeros
                    pass

        return results

    def run_all_tests(self) -> Dict[str, Any]:
        """Run all defined tests.

        Returns:
            Complete test results
        """
        start_time = datetime.now()
        self.results["start_time"] = start_time.isoformat()

        # Run each test module
        for test_info in self.tests:
            self.run_test(test_info)

        end_time = datetime.now()
        self.results["end_time"] = end_time.isoformat()
        self.results["duration_seconds"] = (end_time - start_time).total_seconds()

        # Calculate success percentage
        total = self.results["summary"]["total"]
        if total > 0:
            success_rate = 100 * self.results["summary"]["passed"] / total
            self.results["success_rate"] = success_rate
        else:
            self.results["success_rate"] = 0

        # Print final summary
        print(f"\n{'=' * 60}")
        print("FINAL TEST SUMMARY")
        print(f"{'=' * 60}")
        print(f"Total tests: {self.results['summary']['total']}")
        print(f"Tests passed: {self.results['summary']['passed']}")
        print(f"Tests failed: {self.results['summary']['failed']}")
        print(f"Tests with errors: {self.results['summary']['errors']}")
        if "success_rate" in self.results:
            print(f"Success rate: {self.results['success_rate']:.2f}%")
        print(f"Duration: {self.results['duration_seconds']:.2f} seconds")

        # Save results to file
        report_filename = (
            f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        report_path = os.path.join(self.output_path, report_filename)
        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2)

        print(f"\nDetailed report saved to: {report_path}")

        # Generate simple HTML report
        self._generate_html_report(report_path.replace(".json", ".html"))

        return self.results

    def _generate_html_report(self, output_path: str) -> None:
        """Generate a simple HTML report from test results.

        Args:
            output_path: Path to save the HTML report
        """
        # Calculate success rate for each test category
        for name, test_data in self.results["tests"].items():
            results = test_data["results"]
            if results["total"] > 0:
                results["success_rate"] = 100 * results["passed"] / results["total"]
            else:
                results["success_rate"] = 0

        # Determine overall status
        overall_success_rate = self.results.get("success_rate", 0)
        if overall_success_rate >= 95:
            status_class = "success"
            status_text = "COMPLIANT"
        elif overall_success_rate >= 75:
            status_class = "warning"
            status_text = "PARTIALLY COMPLIANT"
        else:
            status_class = "danger"
            status_text = "NON-COMPLIANT"

        # Generate HTML content
        html = f"""<!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NovaMind Security Test Report</title>
        <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 0; }}
        .container {{ width: 90%; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #343a40; color: white; padding: 20px 0; text-align: center; }}
        .summary {{ margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 5px; }}
        .test-category {{ margin-bottom: 30px; }}
        .category-header {{ padding: 10px; background: #e9ecef; border-radius: 5px 5px 0 0; }}
        .category-results {{ margin-top: 10px; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #dee2e6; padding: 12px; text-align: left; }}
        th {{ background-color: #343a40; color: white; }}
        .success {{ background-color: #d4edda; }}
        .warning {{ background-color: #fff3cd; }}
        .danger {{ background-color: #f8d7da; }}
        .status-badge {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-weight: bold; }}
        .footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; }}
        </style>
        </head>
        <body>
        <div class="header">
        <div class="container">
        <h1>NovaMind Digital Twin</h1>
        <h2>HIPAA Security Compliance Report</h2>
        <p>Generated: {datetime.fromisoformat(self.results['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}</p>
        <div class="status-badge {status_class}">{status_text}</div>
        </div>
        </div>

        <div class="container">
        <div class="summary">
        <h2>Summary</h2>
        <table>
        <tr>
        <th>Total Tests</th>
        <th>Passed</th>
        <th>Failed</th>
        <th>Errors</th>
        <th>Success Rate</th>
        </tr>
        <tr>
        <td>{self.results['summary']['total']}</td>
        <td>{self.results['summary']['passed']}</td>
        <td>{self.results['summary']['failed']}</td>
        <td>{self.results['summary']['errors']}</td>
        <td>{self.results.get('success_rate', 0):.2f}%</td>
        </tr>
        </table>
        </div>

        <h2>Test Categories</h2>
        """

        # Add each test category
        for name, test_data in self.results["tests"].items():
            results = test_data["results"]
            success_rate = results.get("success_rate", 0)

            if success_rate >= 95:
                category_class = "success"
            elif success_rate >= 75:
                category_class = "warning"
            else:
                category_class = "danger"

            html += f"""
            <div class="test-category">
            <div class="category-header">
            <h3>{name}</h3>
            <p>Path: {test_data['path']}</p>
            </div>
            <div class="category-results">
            <table>
            <tr>
            <th>Total Tests</th>
            <th>Passed</th>
            <th>Failed</th>
            <th>Errors</th>
            <th>Success Rate</th>
            </tr>
            <tr class="{category_class}">
            <td>{results['total']}</td>
            <td>{results['passed']}</td>
            <td>{results['failed']}</td>
            <td>{results['errors']}</td>
            <td>{success_rate:.2f}%</td>
            </tr>
            </table>
            </div>
            """

            # Add test details if available
            if results["details"]:
                html += f"""
                <h4>Test Details</h4>
                <table>
                <tr>
                <th>Test</th>
                <th>Status</th>
                </tr>
                """

                for test in results["details"]:
                    test_class = {
                        "passed": "success",
                        "failed": "danger",
                        "error": "danger",
                        "skipped": "warning",
                    }.get(test["status"], "")

                    html += f"""
                    <tr class="{test_class}">
                    <td>{test['name']}</td>
                    <td>{test['status']}</td>
                    </tr>"""

                html += """
                </table>
                """

            html += """
            </div>
            """

        # Close the HTML
        html += f"""
        <div class="footer">
        <p>&copy; {datetime.now().year} NovaMind Digital Twin</p>
        <p>HIPAA Compliance Report</p>
        </div>
        </div>
        </body>
        </html>
        """

        # Write the HTML file
        with open(output_path, "w") as f:
            f.write(html)

        print(f"HTML report generated at: {output_path}")


def run_security_tests():
    """Run security tests with direct output."""
    runner = DirectSecurityTestRunner()
    return runner.run_all_tests()


if __name__ == "__main__":
    run_security_tests()
