#!/usr/bin/env python3
"""
Test Coverage Improvement Script

This script analyzes test coverage, identifies areas for improvement,
and helps increase overall test coverage for the Novamind Digital Twin platform.

Usage:
    python scripts/improve_test_coverage.py [--analyze] [--identify-untested] [--generate-stubs]
"""

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any


class CoverageAnalyzer:
    """Analyzes and improves test coverage for the project."""

    def __init__(self):
        """Initialize the analyzer with project paths."""
        self.project_root = Path.cwd()
        self.app_dir = self.project_root / "app"
        self.tests_dir = self.app_dir / "tests"
        self.coverage_file = self.project_root / ".coverage"
        self.coverage_json = self.project_root / "coverage.json"

        # Ensure all directories exist
        for directory in [
            self.tests_dir / "standalone",
            self.tests_dir / "venv",
            self.tests_dir / "integration",
        ]:
            directory.mkdir(exist_ok=True, parents=True)

    def run_coverage(self, test_type: str = None) -> bool:
        """Run test coverage for the specified test type."""
        cmd = ["python", "-m", "pytest"]

        if test_type:
            if test_type == "standalone":
                cmd.extend(["app/tests/standalone/"])
            elif test_type == "venv":
                cmd.extend(["app/tests/venv/"])
            elif test_type == "integration":
                cmd.extend(["app/tests/integration/"])

        cmd.extend(["--cov=app", "--cov-report=json", "--cov-report=term"])

        try:
            print(f"Running coverage for {test_type or 'all'} tests...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(result.stdout)
            return result.returncode == 0
        except Exception as e:
            print(f"Error running coverage: {e}")
            return False

    def analyze_coverage(self) -> dict[str, Any]:
        """Analyze coverage report and provide statistics."""
        if not self.coverage_json.exists():
            print("No coverage data found. Run tests with coverage first.")
            return {}

        try:
            with open(self.coverage_json) as f:
                coverage_data = json.load(f)

            # Extract overall statistics
            total_statements = 0
            total_missing = 0
            module_coverage = {}

            for file_path, data in coverage_data["files"].items():
                if not file_path.startswith("app/"):
                    continue

                statements = data.get("summary", {}).get("num_statements", 0)
                missing = data.get("summary", {}).get("missing_lines", 0)

                if statements > 0:
                    coverage_pct = (statements - missing) / statements * 100
                else:
                    coverage_pct = 0

                # Organize by module
                module_path = self._get_module_path(file_path)
                if module_path not in module_coverage:
                    module_coverage[module_path] = {
                        "statements": 0,
                        "missing": 0,
                        "files": 0,
                        "coverage": 0,
                    }

                module_coverage[module_path]["statements"] += statements
                module_coverage[module_path]["missing"] += missing
                module_coverage[module_path]["files"] += 1

                total_statements += statements
                total_missing += missing

            # Calculate coverage percentage for each module
            for module, data in module_coverage.items():
                if data["statements"] > 0:
                    data["coverage"] = (
                        (data["statements"] - data["missing"])
                        / data["statements"]
                        * 100
                    )
                else:
                    data["coverage"] = 0

            # Calculate overall coverage
            overall_coverage = 0
            if total_statements > 0:
                overall_coverage = (
                    (total_statements - total_missing) / total_statements * 100
                )

            return {
                "overall": {
                    "statements": total_statements,
                    "missing": total_missing,
                    "coverage": overall_coverage,
                },
                "modules": module_coverage,
            }

        except Exception as e:
            print(f"Error analyzing coverage data: {e}")
            return {}

    def _get_module_path(self, file_path: str) -> str:
        """Convert file path to module path for grouping."""
        parts = file_path.split("/")
        if parts[0] == "app":
            if len(parts) > 2:
                return f"app.{parts[1]}"
            return "app"
        return file_path

    def identify_untested_code(self, min_statements: int = 5) -> list[dict[str, Any]]:
        """Identify modules with low or no test coverage."""
        coverage_data = self.analyze_coverage()
        if not coverage_data:
            return []

        untested_modules = []
        for module, data in coverage_data.get("modules", {}).items():
            if data["coverage"] < 50 and data["statements"] >= min_statements:
                untested_modules.append(
                    {
                        "module": module,
                        "statements": data["statements"],
                        "missing": data["missing"],
                        "coverage": data["coverage"],
                        "priority": self._calculate_priority(module, data),
                    }
                )

        # Sort by priority (higher is more important)
        return sorted(untested_modules, key=lambda x: x["priority"], reverse=True)

    def _calculate_priority(self, module: str, data: dict[str, Any]) -> float:
        """Calculate priority for testing a module based on importance and current coverage."""
        # Base priority on number of statements (larger modules = higher priority)
        priority = data["statements"] * 0.1

        # Increase priority for critical modules
        critical_modules = [
            "app.domain",
            "app.core",
            "app.application",
            "app.core.security",
            "app.domain.entities",
        ]

        for critical in critical_modules:
            if module.startswith(critical):
                priority *= 1.5
                break

        # Higher priority for security/HIPAA related modules
        security_keywords = ["security", "auth", "hipaa", "phi", "privacy", "encrypt"]
        for keyword in security_keywords:
            if keyword in module.lower():
                priority *= 2
                break

        # Modules with very low coverage get higher priority
        if data["coverage"] < 10:
            priority *= 1.5

        return priority

    def generate_test_stubs(
        self, untested_modules: list[dict[str, Any]], max_stubs: int = 5
    ) -> None:
        """Generate stub test files for untested modules."""
        if not untested_modules:
            print("No untested modules found.")
            return

        print("\nGenerating test stubs for top untested modules:")

        for i, module_data in enumerate(untested_modules[:max_stubs]):
            module = module_data["module"]
            module_path = module.replace(".", "/")

            # Find Python files in this module
            module_dir = self.project_root / module_path
            if not module_dir.exists() or not module_dir.is_dir():
                continue

            python_files = list(module_dir.glob("**/*.py"))
            if not python_files:
                continue

            # Create a test file for the most important untested file
            for py_file in python_files:
                relative_path = py_file.relative_to(self.project_root)
                test_path = self._get_test_path_for_file(relative_path)

                if not test_path.exists():
                    self._create_test_stub(py_file, test_path)
                    print(f"Created test stub: {test_path}")
                    break

    def _get_test_path_for_file(self, file_path: Path) -> Path:
        """Determine the appropriate test path for a source file."""
        # Extract the module and filename
        parts = list(file_path.parts)
        if parts[0] == "app":
            # Remove 'app' from the start
            parts = parts[1:]

        filename = parts[-1]
        test_filename = f"test_{filename}"

        # Determine the appropriate test directory based on the file's dependencies
        test_dir = "standalone"
        file_content = file_path.read_text()

        # Check for database dependencies
        db_patterns = [
            r"from\s+sqlalchemy",
            r"import\s+sqlalchemy",
            r"\.session",
            r"\.query",
            r"\.commit\(",
        ]
        for pattern in db_patterns:
            if re.search(pattern, file_content):
                test_dir = "integration"
                break

        # Check for external service dependencies if not already flagged as integration
        if test_dir != "integration":
            external_patterns = [
                r"import\s+requests",
                r"from\s+requests",
                r"import\s+boto3",
                r"from\s+boto3",
                r"import\s+redis",
                r"from\s+redis",
            ]
            for pattern in external_patterns:
                if re.search(pattern, file_content):
                    test_dir = "venv"
                    break

        return self.tests_dir / test_dir / test_filename

    def _create_test_stub(self, source_file: Path, test_file: Path) -> None:
        """Create a test stub file based on the source file."""
        # Ensure the directory exists
        test_file.parent.mkdir(parents=True, exist_ok=True)

        # Parse the source file to extract classes and functions
        source_content = source_file.read_text()

        # Extract class names
        class_pattern = r"class\s+(\w+)"
        classes = re.findall(class_pattern, source_content)

        # Extract function names (not inside classes)
        function_pattern = r"def\s+(\w+)\s*\("
        functions = re.findall(function_pattern, source_content)

        # Generate the test file content
        module_path = str(source_file).replace("/", ".").replace(".py", "")
        if module_path.startswith("app."):
            module_path = module_path[4:]  # Remove 'app.' prefix

        test_content = [
            "import pytest",
            f"from app.{module_path} import {', '.join(classes + functions) or 'None'}",
            "",
            "# Add fixtures here as needed",
            "",
        ]

        # Generate test classes for each class
        for class_name in classes:
            test_content.extend(
                [
                    f"class Test{class_name}:",
                    f'    """Test suite for {class_name}."""',
                    "",
                    "    @pytest.fixture",
                    f"    def {class_name.lower()}_instance(self):",
                    f'        """Create a {class_name} instance for testing."""',
                    "        # TODO: Initialize with appropriate test data",
                    f"        return {class_name}()",
                    "",
                    f"    def test_{class_name.lower()}_initialization(self, {class_name.lower()}_instance):",
                    f'        """Test {class_name} initialization."""',
                    f"        assert {class_name.lower()}_instance is not None",
                    "        # TODO: Add assertions for expected attributes",
                    "",
                    "    # TODO: Add more test methods for each method in the class",
                    "",
                ]
            )

        # Generate test functions for each function
        for function_name in functions:
            if function_name.startswith("_"):
                continue  # Skip private functions

            test_content.extend(
                [
                    f"def test_{function_name}():",
                    f'    """Test {function_name} function."""',
                    "    # TODO: Add test implementation",
                    f"    # result = {function_name}(...)",
                    "    # assert result is not None",
                    "",
                ]
            )

        # Write the test file
        test_file.write_text("\n".join(test_content))

    def generate_coverage_report(self) -> str:
        """Generate a Markdown coverage report."""
        coverage_data = self.analyze_coverage()
        if not coverage_data:
            return "No coverage data available."

        overall = coverage_data.get("overall", {})
        modules = coverage_data.get("modules", {})

        lines = [
            "# Novamind Digital Twin Test Coverage Report",
            "",
            f"Overall coverage: **{overall.get('coverage', 0):.2f}%**",
            "",
            "## Coverage by Module",
            "",
            "| Module | Statements | Missing | Coverage |",
            "|--------|------------|---------|----------|",
        ]

        # Sort modules by coverage (ascending)
        sorted_modules = sorted(modules.items(), key=lambda x: x[1]["coverage"])

        for module, data in sorted_modules:
            lines.append(
                f"| {module} | {data['statements']} | {data['missing']} | "
                f"{data['coverage']:.2f}% |"
            )

        lines.extend(
            [
                "",
                "## Coverage Goals",
                "",
                "- **Domain layer**: 90% coverage",
                "- **Application layer**: 85% coverage",
                "- **Infrastructure layer**: 75% coverage",
                "- **Overall coverage target**: 80%",
                "",
                "## Improvement Areas",
                "",
            ]
        )

        # Identify modules below target
        below_target = []
        for module, data in modules.items():
            target = 0
            if module.startswith("app.domain"):
                target = 90
            elif module.startswith("app.application"):
                target = 85
            elif module.startswith("app.infrastructure"):
                target = 75
            else:
                target = 80

            if data["coverage"] < target:
                gap = target - data["coverage"]
                below_target.append((module, data["coverage"], gap))

        # Sort by gap (descending)
        below_target.sort(key=lambda x: x[2], reverse=True)

        for module, current, gap in below_target[:10]:
            lines.append(f"- **{module}**: Current {current:.2f}% (Gap: {gap:.2f}%)")

        return "\n".join(lines)


def main():
    """Main function to parse arguments and run the coverage analyzer."""
    parser = argparse.ArgumentParser(description="Analyze and improve test coverage")
    parser.add_argument(
        "--analyze", action="store_true", help="Analyze existing coverage data"
    )
    parser.add_argument("--run", action="store_true", help="Run tests with coverage")
    parser.add_argument(
        "--identify-untested", action="store_true", help="Identify untested code"
    )
    parser.add_argument(
        "--generate-stubs",
        action="store_true",
        help="Generate test stubs for untested modules",
    )
    parser.add_argument(
        "--report", action="store_true", help="Generate coverage report"
    )
    parser.add_argument(
        "--test-type",
        choices=["standalone", "venv", "integration"],
        help="Type of tests to run",
    )

    args = parser.parse_args()
    analyzer = CoverageAnalyzer()

    # Default to all actions if none specified
    if not (
        args.analyze
        or args.run
        or args.identify_untested
        or args.generate_stubs
        or args.report
    ):
        args.analyze = args.run = args.identify_untested = args.report = True

    if args.run:
        analyzer.run_coverage(args.test_type)

    if args.analyze:
        coverage_data = analyzer.analyze_coverage()
        if coverage_data:
            overall = coverage_data.get("overall", {})
            print(f"\nOverall coverage: {overall.get('coverage', 0):.2f}%")
            print(f"Total statements: {overall.get('statements', 0)}")
            print(f"Missing statements: {overall.get('missing', 0)}\n")

            print("Coverage by module:")
            for module, data in sorted(
                coverage_data.get("modules", {}).items(), key=lambda x: x[1]["coverage"]
            ):
                print(
                    f"  {module}: {data['coverage']:.2f}% ({data['statements']} statements)"
                )

    if args.identify_untested:
        untested = analyzer.identify_untested_code()
        if untested:
            print("\nTop modules with low coverage:")
            for i, module in enumerate(untested[:10], 1):
                print(
                    f"{i}. {module['module']}: {module['coverage']:.2f}% coverage "
                    f"({module['missing']} of {module['statements']} statements missing)"
                )
        else:
            print("\nNo significant untested modules found.")

    if args.generate_stubs:
        untested = analyzer.identify_untested_code()
        analyzer.generate_test_stubs(untested)

    if args.report:
        report = analyzer.generate_coverage_report()
        report_path = Path("coverage-report.md")
        report_path.write_text(report)
        print(f"\nCoverage report generated: {report_path}")


if __name__ == "__main__":
    main()
