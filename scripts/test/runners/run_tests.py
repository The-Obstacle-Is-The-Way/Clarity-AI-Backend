#!/usr/bin/env python
"""
Novamind Digital Twin Test Runner

This is the canonical test runner for the Novamind Digital Twin project.
It provides a unified interface for running tests at different dependency levels,
with appropriate test discovery and reporting.

Usage:
    python run_tests.py --standalone  # Run standalone tests only
    python run_tests.py --venv        # Run standalone and venv tests
    python run_tests.py --all         # Run all tests
    python run_tests.py --security    # Run security-focused tests
    python run_tests.py --coverage    # Generate coverage report
"""

import argparse
import os
import subprocess
import sys
from enum import Enum
from pathlib import Path
from typing import List, Optional


class Colors:
    """Terminal colors for output formatting."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class TestLevel(Enum):
    """Dependency levels for tests."""
    STANDALONE = "standalone"
    VENV = "venv"
    INTEGRATION = "integration"


class TestRunner:
    """
    Test runner for the Novamind Digital Twin project.
    
    This class handles test discovery, execution, and reporting
    based on the specified dependency level and test markers.
    """
    
    def __init__(self, project_root: Optional[Path] = None):
        """
        Initialize the test runner.
        
        Args:
            project_root: Root directory of the project
        """
        self.project_root = project_root or Path(__file__).resolve().parents[3]
        self.tests_dir = self.project_root / "app" / "tests"
        
    def run_tests(self, 
                  level: TestLevel = TestLevel.STANDALONE,
                  security: bool = False,
                  coverage: bool = False,
                  verbose: bool = False,
                  html_report: bool = False,
                  xml_report: bool = False,
                  progressive: bool = False) -> bool:
        """
        Run tests at the specified dependency level.
        
        Args:
            level: The highest dependency level to run
            security: Whether to run security-focused tests
            coverage: Whether to generate a coverage report
            verbose: Whether to show verbose output
            html_report: Whether to generate an HTML coverage report
            xml_report: Whether to generate an XML coverage report
            progressive: Whether to stop if tests at a lower level fail
            
        Returns:
            bool: True if all tests passed, False otherwise
        """
        print(f"{Colors.HEADER}Running Novamind Digital Twin tests...{Colors.ENDC}")
        
        # Determine which test levels to run
        levels_to_run = []
        if level == TestLevel.STANDALONE:
            levels_to_run = [TestLevel.STANDALONE]
        elif level == TestLevel.VENV:
            levels_to_run = [TestLevel.STANDALONE, TestLevel.VENV]
        else:  # INTEGRATION or ALL
            levels_to_run = [TestLevel.STANDALONE, TestLevel.VENV, TestLevel.INTEGRATION]
        
        # Run tests for each level
        success = True
        for test_level in levels_to_run:
            level_success = self._run_level_tests(
                test_level,
                security=security,
                coverage=coverage,
                verbose=verbose,
                html_report=(html_report and test_level == levels_to_run[-1]),
                xml_report=(xml_report and test_level == levels_to_run[-1])
            )
            
            if not level_success:
                print(f"{Colors.RED}Tests failed at {test_level.value} level.{Colors.ENDC}")
                success = False
                if progressive:
                    break
        
        return success
    
    def _run_level_tests(self,
                         level: TestLevel,
                         security: bool = False,
                         coverage: bool = False,
                         verbose: bool = False,
                         html_report: bool = False,
                         xml_report: bool = False) -> bool:
        """
        Run tests for a specific dependency level.
        
        Args:
            level: The dependency level to run
            security: Whether to run security-focused tests
            coverage: Whether to generate a coverage report
            verbose: Whether to show verbose output
            html_report: Whether to generate an HTML coverage report
            xml_report: Whether to generate an XML coverage report
            
        Returns:
            bool: True if all tests passed, False otherwise
        """
        print(f"{Colors.BLUE}Running {level.value} tests...{Colors.ENDC}")
        
        # Construct the pytest command
        pytest_args = [
            sys.executable, "-m", "pytest",
            str(self.tests_dir / level.value),
            "-v" if verbose else "-q"
        ]
        
        # Add markers if needed
        if security:
            pytest_args.extend(["-m", "security"])
        
        # Add coverage options if requested
        if coverage:
            pytest_args.extend(["--cov=app", f"--cov-report=term-missing"])
            if html_report:
                pytest_args.append("--cov-report=html")
            if xml_report:
                pytest_args.append("--cov-report=xml")
        
        # Run the tests
        try:
            result = subprocess.run(
                pytest_args,
                cwd=str(self.project_root),
                check=False,
                capture_output=not verbose
            )
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}All {level.value} tests passed!{Colors.ENDC}")
                return True
            else:
                print(f"{Colors.RED}Some {level.value} tests failed.{Colors.ENDC}")
                if not verbose and hasattr(result, 'stdout'):
                    print(result.stdout.decode('utf-8'))
                return False
        except Exception as e:
            print(f"{Colors.RED}Error running {level.value} tests: {str(e)}{Colors.ENDC}")
            return False


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Novamind Digital Twin Test Runner")
    
    # Test level options
    level_group = parser.add_mutually_exclusive_group(required=True)
    level_group.add_argument(
        "--standalone", 
        action="store_true", 
        help="Run standalone tests only"
    )
    level_group.add_argument(
        "--venv", 
        action="store_true", 
        help="Run standalone and venv tests"
    )
    level_group.add_argument(
        "--integration", 
        action="store_true", 
        help="Run integration tests only"
    )
    level_group.add_argument(
        "--all", 
        action="store_true", 
        help="Run all tests"
    )
    
    # Marker options
    parser.add_argument(
        "--security", 
        action="store_true", 
        help="Run security-focused tests"
    )
    
    # Coverage options
    parser.add_argument(
        "--coverage", 
        action="store_true", 
        help="Generate coverage report"
    )
    parser.add_argument(
        "--html", 
        action="store_true", 
        help="Generate HTML coverage report"
    )
    parser.add_argument(
        "--xml", 
        action="store_true", 
        help="Generate XML coverage report"
    )
    
    # Execution options
    parser.add_argument(
        "--verbose", 
        action="store_true", 
        help="Show verbose output"
    )
    parser.add_argument(
        "--progressive", 
        action="store_true", 
        help="Stop if tests at a lower level fail"
    )
    
    return parser.parse_args()


def main():
    """Main entry point for the test runner."""
    args = parse_args()
    
    # Determine the test level
    level = TestLevel.STANDALONE
    if args.venv:
        level = TestLevel.VENV
    elif args.integration:
        level = TestLevel.INTEGRATION
    elif args.all:
        level = TestLevel.INTEGRATION  # Run all tests
    
    # Run the tests
    runner = TestRunner()
    success = runner.run_tests(
        level=level,
        security=args.security,
        coverage=args.coverage,
        verbose=args.verbose,
        html_report=args.html,
        xml_report=args.xml,
        progressive=args.progressive
    )
    
    # Exit with the appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()