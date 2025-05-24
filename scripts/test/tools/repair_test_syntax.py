#!/usr/bin/env python3
"""
Test Syntax Repair Tool

This script helps identify and fix common syntax errors in test files.
It can automatically fix many simple issues and provide detailed reports
for files that need manual intervention.

Usage:
    python repair_test_syntax.py [--dry-run] [--path PATH]
"""

import argparse
import ast
import os
import re
from pathlib import Path


class Colors:
    """ANSI color codes for terminal output."""

    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class TestSyntaxRepair:
    """
    Tool for repairing common syntax errors in test files.
    """

    def __init__(self, project_root: Path | None = None):
        """
        Initialize the test repair tool.

        Args:
            project_root: Root directory of the project
        """
        self.project_root = project_root or Path(__file__).resolve().parents[4]
        self.tests_dir = self.project_root / "backend" / "app" / "tests"
        self.fixed_files = 0
        self.error_files = 0
        self.skipped_files = 0
        self.error_types: dict[str, int] = {}

        print(f"Project root: {self.project_root}")
        print(f"Tests directory: {self.tests_dir}")

    def find_test_files(self, start_dir: Path = None) -> list[Path]:
        """
        Find all Python test files in the given directory.

        Args:
            start_dir: Starting directory to search from (default: tests_dir)

        Returns:
            List of paths to test files
        """
        start_dir = start_dir or self.tests_dir
        test_files = []

        for root, _, files in os.walk(start_dir):
            for file in files:
                if file.startswith("test_") and file.endswith(".py"):
                    test_files.append(Path(root) / file)

        return test_files

    def check_syntax(self, file_path: Path) -> SyntaxError | None:
        """
        Check if a Python file has syntax errors.

        Args:
            file_path: Path to the Python file

        Returns:
            SyntaxError if there's an error, None otherwise
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                ast.parse(f.read(), filename=str(file_path))
            return None
        except SyntaxError as e:
            return e

    def fix_missing_colons(self, content: str) -> str:
        """
        Fix missing colons after function and class definitions.

        Args:
            content: File content

        Returns:
            Fixed content
        """
        # Function definition missing colon pattern
        # Matches "def function_name(params)" not followed by a colon
        pattern = r"(def\s+[a-zA-Z0-9_]+\s*\([^)]*\))\s*(?!\s*:)"
        fixed = re.sub(pattern, r"\1:", content)

        # Class definition missing colon pattern
        pattern = r"(class\s+[a-zA-Z0-9_]+(?:\s*\([^)]*\))?)\s*(?!\s*:)"
        fixed = re.sub(pattern, r"\1:", fixed)

        return fixed

    def fix_indentation(self, content: str) -> str:
        """
        Fix common indentation issues.

        Args:
            content: File content

        Returns:
            Fixed content
        """
        lines = content.split("\n")
        fixed_lines = []
        in_func_or_class = False
        expected_indent = 0

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Skip empty lines
            if not stripped:
                fixed_lines.append(line)
                continue

            # Check for function or class definition
            if re.match(r"(def|class)\s+[a-zA-Z0-9_]+", stripped):
                if not stripped.endswith(":"):
                    stripped += ":"

                # Get the indent of this line
                indent = len(line) - len(line.lstrip())
                expected_indent = indent + 4
                in_func_or_class = True
                fixed_lines.append(" " * indent + stripped)
                continue

            if in_func_or_class:
                # Check if this should be indented
                if i > 0 and lines[i - 1].endswith(":"):
                    indent = len(line) - len(line.lstrip())
                    if indent < expected_indent and not re.match(
                        r"(def|class|return|pass|else|elif|except|finally)", stripped
                    ):
                        fixed_lines.append(" " * expected_indent + stripped)
                        continue

            fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def fix_common_imports(self, content: str) -> str:
        """
        Add common missing imports for test files.

        Args:
            content: File content

        Returns:
            Fixed content with added imports
        """
        # Check if file contains certain test-related features without imports
        needs_unittest_mock = any(x in content for x in ["Mock(", "MagicMock(", "patch(", "@patch"])
        needs_pytest = any(x in content for x in ["pytest.", "@pytest."])
        needs_fixture = "@fixture" in content or "pytest.fixture" in content

        # List of import lines to add if needed
        import_lines = []

        if needs_unittest_mock and "from unittest.mock import" not in content:
            import_lines.append("from unittest.mock import Mock, MagicMock, patch")

        if needs_pytest and "import pytest" not in content:
            import_lines.append("import pytest")

        if needs_fixture and "fixture" not in content:
            if "from pytest import" in content:
                # Add fixture to existing pytest import
                content = re.sub(
                    r"from pytest import ([^(\n]*)",
                    r"from pytest import \1, fixture",
                    content,
                )
            elif "import pytest" in content:
                pass  # Can use pytest.fixture
            else:
                import_lines.append("from pytest import fixture")

        if import_lines:
            # Add imports after any docstring if present
            if '"""' in content:
                doc_end = content.find('"""', content.find('"""') + 3) + 3
                pre_content = content[:doc_end]
                post_content = content[doc_end:]
                return pre_content + "\n" + "\n".join(import_lines) + "\n" + post_content
            else:
                # Just add to the top
                return "\n".join(import_lines) + "\n\n" + content

        return content

    def fix_syntax_errors(self, file_path: Path, dry_run: bool = False) -> bool:
        """
        Attempt to fix common syntax errors in a file.

        Args:
            file_path: Path to the file
            dry_run: If True, don't write changes to disk

        Returns:
            True if fixed successfully, False otherwise
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            # Apply fixes
            fixed_content = content
            fixed_content = self.fix_missing_colons(fixed_content)
            fixed_content = self.fix_indentation(fixed_content)
            fixed_content = self.fix_common_imports(fixed_content)

            # Check if we fixed it
            if content == fixed_content:
                print(f"{Colors.WARNING}No automatic fixes available for {file_path}{Colors.ENDC}")
                self.skipped_files += 1
                return False

            # Validate the fixed content
            try:
                ast.parse(fixed_content)
            except SyntaxError:
                print(
                    f"{Colors.FAIL}Failed to fix {file_path} - still has syntax errors{Colors.ENDC}"
                )
                self.error_files += 1
                return False

            # Write fixed content
            if not dry_run:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(fixed_content)
                print(f"{Colors.GREEN}Fixed {file_path}{Colors.ENDC}")
                self.fixed_files += 1
            else:
                print(f"{Colors.BLUE}Would fix {file_path} (dry run){Colors.ENDC}")

            return True

        except Exception as e:
            print(f"{Colors.FAIL}Error processing {file_path}: {e!s}{Colors.ENDC}")
            self.error_files += 1
            return False

    def categorize_error(self, error: SyntaxError) -> str:
        """
        Categorize a syntax error for reporting.

        Args:
            error: SyntaxError instance

        Returns:
            Category name
        """
        msg = str(error)
        if "expected ':'" in msg:
            return "missing_colon"
        elif "unexpected indent" in msg:
            return "indent_error"
        elif "unexpected unindent" in msg:
            return "indent_error"
        elif "expected an indented block" in msg:
            return "missing_indent"
        else:
            return "other"

    def repair_all(self, start_dir: Path = None, dry_run: bool = False) -> None:
        """
        Find and repair syntax errors in all test files.

        Args:
            start_dir: Starting directory to search from (default: tests_dir)
            dry_run: If True, don't write changes to disk
        """
        test_files = self.find_test_files(start_dir)
        print(f"Found {len(test_files)} test files")

        files_with_errors = []
        categorized_errors: dict[str, list[Path]] = {
            "missing_colon": [],
            "indent_error": [],
            "missing_indent": [],
            "other": [],
        }

        # First pass: check and categorize errors
        for file_path in test_files:
            error = self.check_syntax(file_path)
            if error:
                files_with_errors.append(file_path)
                category = self.categorize_error(error)
                categorized_errors[category].append(file_path)
                if category in self.error_types:
                    self.error_types[category] += 1
                else:
                    self.error_types[category] = 1

        print(f"\nFound {len(files_with_errors)} files with syntax errors")
        for category, files in categorized_errors.items():
            if files:
                print(f"  {category}: {len(files)} files")

        # Second pass: try to fix errors
        for file_path in files_with_errors:
            self.fix_syntax_errors(file_path, dry_run)

        # Print summary
        print(f"\n{Colors.HEADER}Repair Summary:{Colors.ENDC}")
        print(f"  {Colors.GREEN}Fixed: {self.fixed_files}{Colors.ENDC}")
        print(f"  {Colors.WARNING}Skipped: {self.skipped_files}{Colors.ENDC}")
        print(f"  {Colors.FAIL}Failed: {self.error_files}{Colors.ENDC}")

        if not dry_run and self.fixed_files > 0:
            print(f"\n{Colors.GREEN}Successfully fixed {self.fixed_files} files!{Colors.ENDC}")
        if self.error_files > 0:
            print(
                f"\n{Colors.WARNING}Some files still need manual fixes. See above for details.{Colors.ENDC}"
            )


def main():
    parser = argparse.ArgumentParser(description="Repair syntax errors in test files")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be fixed without making changes",
    )
    parser.add_argument("--path", type=str, help="Specific path to check and fix")

    args = parser.parse_args()

    repair_tool = TestSyntaxRepair()

    if args.path:
        path = Path(args.path)
        if path.is_file():
            error = repair_tool.check_syntax(path)
            if error:
                print(f"Found syntax error in {path}: {error}")
                repair_tool.fix_syntax_errors(path, args.dry_run)
            else:
                print(f"No syntax errors found in {path}")
        else:
            repair_tool.repair_all(path, args.dry_run)
    else:
        repair_tool.repair_all(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
