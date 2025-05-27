#!/usr/bin/env python
"""
Script to fix syntax errors in test files and then run the tests.
This script combines the syntax fixer with pytest execution to make 
sure the tests not only compile but also run successfully.
"""

import argparse
import datetime
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class TestRunner:
    """Class to manage fixing and running tests."""

    def __init__(self, backend_dir, specific_files=None):
        """Initialize with backend directory."""
        self.backend_dir = backend_dir
        self.specific_files = specific_files
        self.auto_fix_script = os.path.join(
            backend_dir, "scripts", "test", "tools", "auto_fix_syntax.py"
        )
        self.results: Dict[str, List[str]] = {
            "fixed_files": [],
            "passing_tests": [],
            "failing_tests": [],
            "syntax_error_files": [],
        }

    def find_test_files(self):
        """Find all test files or use the specific files provided."""
        if self.specific_files:
            return [os.path.join(self.backend_dir, f) for f in self.specific_files]

        test_files = []
        for path in Path(self.backend_dir).rglob("test_*.py"):
            test_files.append(str(path))
        return test_files

    def run_syntax_fixer(self):
        """Run the syntax fixer script."""
        logger.info("Running syntax fixer...")

        # Execute the auto_fix_syntax.py script
        process = subprocess.run(
            [sys.executable, self.auto_fix_script],
            cwd=self.backend_dir,
            capture_output=True,
            text=True,
        )

        logger.info("Syntax fixer output:\n" + process.stdout)
        if process.stderr:
            logger.warning("Syntax fixer errors:\n" + process.stderr)

        # Check if unfixed_syntax_errors.txt was created
        unfixed_errors_path = os.path.join(self.backend_dir, "unfixed_syntax_errors.txt")
        if os.path.exists(unfixed_errors_path):
            with open(unfixed_errors_path) as f:
                error_files = [line.split(":")[0].strip() for line in f.readlines()]
                self.results["syntax_error_files"] = error_files

        return process.returncode == 0

    def run_test(self, test_file):
        """Run a single test file with pytest."""
        rel_path = os.path.relpath(test_file, self.backend_dir)
        logger.info(f"Running test: {rel_path}")

        # Execute pytest on the file
        process = subprocess.run(
            [sys.executable, "-m", "pytest", test_file, "-v"],
            cwd=self.backend_dir,
            capture_output=True,
            text=True,
        )

        # Check result
        if process.returncode == 0:
            logger.info(f"✅ Test passed: {rel_path}")
            self.results["passing_tests"].append(rel_path)
            return True
        else:
            logger.warning(f"❌ Test failed: {rel_path}")
            self.results["failing_tests"].append(
                {"file": rel_path, "output": process.stdout, "error": process.stderr}
            )
            return False

    def run_all_tests(self):
        """Run all tests that don't have syntax errors."""
        test_files = self.find_test_files()
        logger.info(f"Found {len(test_files)} test files")

        # Skip files with known syntax errors
        syntax_error_files_full = [
            os.path.join(self.backend_dir, f) for f in self.results["syntax_error_files"]
        ]
        test_files = [f for f in test_files if f not in syntax_error_files_full]

        logger.info(
            f"Running {len(test_files)} tests (excluding {len(syntax_error_files_full)} with syntax errors)"
        )

        for test_file in test_files:
            self.run_test(test_file)

    def generate_report(self):
        """Generate a report of test results."""
        report = {
            "timestamp": datetime.datetime.now().isoformat(),
            "total_tests": len(self.find_test_files()),
            "syntax_errors": len(self.results["syntax_error_files"]),
            "passing": len(self.results["passing_tests"]),
            "failing": len(self.results["failing_tests"]),
            "details": self.results,
        }

        # Write report to file
        report_path = os.path.join(self.backend_dir, "test_fix_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Report saved to {report_path}")

        # Print summary
        logger.info("\n===== Test Fix Summary =====")
        logger.info(f"Total test files: {report['total_tests']}")
        logger.info(f"Files with syntax errors: {report['syntax_errors']}")
        logger.info(f"Passing tests: {report['passing']}")
        logger.info(f"Failing tests: {report['failing']}")
        logger.info("============================")

    def run(self):
        """Run the complete process."""
        # First run the syntax fixer
        self.run_syntax_fixer()

        # Then run all tests
        self.run_all_tests()

        # Generate the report
        self.generate_report()


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Fix and run tests")
    parser.add_argument("--files", nargs="+", help="Specific test files to run")
    args = parser.parse_args()

    # Find the backend directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(script_dir)))

    # Create and run the test runner
    runner = TestRunner(backend_dir, args.files)
    runner.run()


if __name__ == "__main__":
    main()
