#!/usr/bin/env python
"""
Novamind Digital Twin Test Analyzer

This script analyzes the test suite to categorize tests by dependency level,
identify syntax errors, and generate a migration plan.

Usage:
    python test_analyzer.py --output-file test_analysis_results.json
"""

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TestFileInfo:
    """Information about a test file."""

    file_path: str
    relative_path: str
    module_name: str
    dependency_level: str = "unknown"
    has_syntax_error: bool = False
    error_message: str | None = None
    markers: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    fixtures: list[str] = field(default_factory=list)
    test_count: int = 0
    destination_path: str | None = None


class TestAnalyzer:
    """
    Analyzes test files to determine their dependency level and other characteristics.
    """

    def __init__(self, project_root: Path | None = None):
        """
        Initialize the test analyzer.

        Args:
            project_root: Root directory of the project
        """
        self.project_root = project_root or Path(__file__).resolve().parents[4]
        self.tests_dir = self.project_root / "backend" / "app" / "tests"
        print(f"Project root: {self.project_root}")
        print(f"Tests directory: {self.tests_dir}")

        # Patterns for identifying dependency levels
        self.standalone_patterns = [
            re.compile(r"@\s*pytest\.mark\.standalone", re.IGNORECASE),
            re.compile(r"standalone", re.IGNORECASE),
        ]

        self.venv_patterns = [
            re.compile(r"@\s*pytest\.mark\.venv", re.IGNORECASE),
            re.compile(r"venv", re.IGNORECASE),
        ]

        self.integration_patterns = [
            re.compile(r"@\s*pytest\.mark\.integration", re.IGNORECASE),
            re.compile(r"integration", re.IGNORECASE),
            re.compile(r"@\s*pytest\.mark\.dependency\(depends=", re.IGNORECASE),
        ]

        # External dependency imports that indicate higher dependency level
        self.external_deps = {
            # Database dependencies
            "sqlalchemy",
            "pymongo",
            "psycopg2",
            "motor",
            "databases",
            # Network dependencies
            "requests",
            "httpx",
            "aiohttp",
            "boto3",
            "fastapi.testclient",
            # External services
            "redis",
            "kafka",
            "elasticsearch",
            "cassandra",
        }

    def analyze_all_tests(self) -> list[TestFileInfo]:
        """
        Analyze all test files in the project.

        Returns:
            List of TestFileInfo objects with analysis results
        """
        test_files = []

        # Walk through the tests directory
        for root, _, files in os.walk(str(self.tests_dir)):
            for file in files:
                if file.startswith("test_") and file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, str(self.project_root))
                    test_files.append(self._analyze_test_file(file_path, relative_path))

        # Determine destination paths based on analysis
        for test_file in test_files:
            if test_file.dependency_level == "standalone":
                # Extract component from path
                components = self._extract_component(test_file.relative_path)
                test_file.destination_path = f"backend/app/tests/standalone/{components}/{os.path.basename(test_file.file_path)}"
            elif test_file.dependency_level == "venv":
                components = self._extract_component(test_file.relative_path)
                test_file.destination_path = f"backend/app/tests/venv/{components}/{os.path.basename(test_file.file_path)}"
            elif test_file.dependency_level == "integration":
                components = self._extract_component(test_file.relative_path)
                test_file.destination_path = f"backend/app/tests/integration/{components}/{os.path.basename(test_file.file_path)}"

        return test_files

    def _extract_component(self, relative_path: str) -> str:
        """
        Extract the component (domain, application, etc.) from a file path.

        Args:
            relative_path: Relative path to the test file

        Returns:
            Component name (domain, application, etc.)
        """
        path_parts = relative_path.split(os.path.sep)

        # Look for known components
        components = ["domain", "application", "infrastructure", "api", "core"]
        for component in components:
            if component in path_parts:
                return component

        # Default to the directory structure after 'tests'
        try:
            tests_index = path_parts.index("tests")
            if (
                tests_index + 1 < len(path_parts) - 1
            ):  # There's at least one directory between 'tests' and the file
                return path_parts[tests_index + 1]
        except ValueError:
            pass

        # Fallback to 'core' if no component can be determined
        return "core"

    def _analyze_test_file(self, file_path: str, relative_path: str) -> TestFileInfo:
        """
        Analyze a single test file to determine its characteristics.

        Args:
            file_path: Path to the test file
            relative_path: Path relative to project root

        Returns:
            TestFileInfo object with analysis results
        """
        module_name = os.path.splitext(os.path.basename(file_path))[0]
        test_info = TestFileInfo(
            file_path=file_path, relative_path=relative_path, module_name=module_name
        )

        # Try to parse the file
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            # Extract markers from content using regex
            for pattern in self.standalone_patterns:
                if pattern.search(content):
                    test_info.dependency_level = "standalone"
                    if "standalone" not in test_info.markers:
                        test_info.markers.append("standalone")

            for pattern in self.venv_patterns:
                if pattern.search(content):
                    # Only upgrade to venv if it's not already marked as integration
                    if test_info.dependency_level != "integration":
                        test_info.dependency_level = "venv"
                        if "venv" not in test_info.markers:
                            test_info.markers.append("venv")

            for pattern in self.integration_patterns:
                if pattern.search(content):
                    test_info.dependency_level = "integration"
                    if "integration" not in test_info.markers:
                        test_info.markers.append("integration")

            # Parse AST for deeper analysis
            tree = ast.parse(content)

            # Extract imports
            imports = self._extract_imports(tree)
            test_info.imports = imports

            # Count tests
            test_info.test_count = self._count_tests(tree)

            # Extract fixtures
            test_info.fixtures = self._extract_fixtures(tree)

            # Determine dependency level based on imports if not already determined
            if test_info.dependency_level == "unknown":
                test_info.dependency_level = self._determine_dependency_from_imports(
                    imports
                )

            # If still unknown, check path hints
            if test_info.dependency_level == "unknown":
                test_info.dependency_level = self._determine_dependency_from_path(
                    relative_path
                )

        except SyntaxError as e:
            test_info.has_syntax_error = True
            test_info.error_message = f"Syntax error: {e!s}"
        except Exception as e:
            test_info.has_syntax_error = True
            test_info.error_message = f"Error analyzing file: {e!s}"

        return test_info

    def _extract_imports(self, tree: ast.AST) -> list[str]:
        """
        Extract all imports from an AST.

        Args:
            tree: AST of a Python file

        Returns:
            List of imported module names
        """
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.append(name.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)

        return imports

    def _count_tests(self, tree: ast.AST) -> int:
        """
        Count the number of test functions in an AST.

        Args:
            tree: AST of a Python file

        Returns:
            Number of test functions
        """
        count = 0

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and (
                node.name.startswith("test_")
                or any(
                    decorator.id == "pytest.mark.parametrize"
                    for decorator in node.decorator_list
                    if isinstance(decorator, ast.Attribute)
                )
            ):
                count += 1

        return count

    def _extract_fixtures(self, tree: ast.AST) -> list[str]:
        """
        Extract fixture names defined in the file.

        Args:
            tree: AST of a Python file

        Returns:
            List of fixture names
        """
        fixtures = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for decorator in node.decorator_list:
                    if (
                        isinstance(decorator, ast.Call)
                        and isinstance(decorator.func, ast.Name)
                        and decorator.func.id == "pytest.fixture"
                    ):
                        fixtures.append(node.name)

        return fixtures

    def _determine_dependency_from_imports(self, imports: list[str]) -> str:
        """
        Determine dependency level based on imports.

        Args:
            imports: List of imported module names

        Returns:
            Dependency level (standalone, venv, integration)
        """
        # Check for integration-level dependencies
        for dep in self.external_deps:
            if any(imp.startswith(dep) for imp in imports):
                return "integration"

        # Check for venv-level dependencies
        venv_deps = ["os", "sys", "io", "tempfile", "shutil"]
        if any(imp in venv_deps for imp in imports):
            return "venv"

        # Default to standalone if no other imports suggest higher level
        return "standalone"

    def _determine_dependency_from_path(self, relative_path: str) -> str:
        """
        Determine dependency level based on file path.

        Args:
            relative_path: Path relative to project root

        Returns:
            Dependency level (standalone, venv, integration)
        """
        path_lower = relative_path.lower()

        if "integration" in path_lower:
            return "integration"

        if "standalone" in path_lower:
            return "standalone"

        if "venv" in path_lower:
            return "venv"

        # Some common patterns
        if "unit" in path_lower:
            return "standalone"

        if "e2e" in path_lower:
            return "integration"

        # Default to venv as a safer middle ground
        return "venv"

    def generate_report(self, tests: list[TestFileInfo]) -> dict[str, Any]:
        """
        Generate a report of test analysis.

        Args:
            tests: List of TestFileInfo objects

        Returns:
            Report as a dictionary
        """
        # Count by dependency level
        dependency_counts = {"standalone": 0, "venv": 0, "integration": 0, "unknown": 0}

        for test in tests:
            dependency_counts[test.dependency_level] += 1

        # Count syntax errors
        syntax_error_count = sum(1 for test in tests if test.has_syntax_error)

        return {
            "total_tests": len(tests),
            "dependency_counts": dependency_counts,
            "syntax_errors": syntax_error_count,
            "tests": [asdict(test) for test in tests],
        }


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Novamind Digital Twin Test Analyzer")

    parser.add_argument(
        "--output-file",
        type=str,
        help="Path to save analysis results",
        default="test_analysis_results.json",
    )

    return parser.parse_args()


def main():
    """Main entry point for the test analyzer."""
    args = parse_args()

    # Analyze tests
    analyzer = TestAnalyzer()
    test_results = analyzer.analyze_all_tests()
    report = analyzer.generate_report(test_results)

    # Save report to file
    with open(args.output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Print summary to console
    print(f"Total tests analyzed: {report['total_tests']}")
    print("Dependency counts:")
    for level, count in report["dependency_counts"].items():
        print(f"  {level}: {count}")
    print(f"Syntax errors: {report['syntax_errors']}")
    print(f"Report saved to {args.output_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
