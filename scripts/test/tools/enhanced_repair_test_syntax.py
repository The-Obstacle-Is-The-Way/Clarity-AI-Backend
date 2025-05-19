#!/usr/bin/env python3
"""
Enhanced Test Syntax Repair Tool

This script identifies and fixes common syntax errors in test files.
It has improved detection and repair capabilities for various syntax issues.

Usage:
    python enhanced_repair_test_syntax.py [--dry-run] [--path PATH] [--verbose]
"""

import os
import re
import ast
import sys
import argparse
import tokenize
import io
import traceback
from typing import Dict, List, Tuple, Optional, Set, Any
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


class EnhancedSyntaxRepair:
    """
    Enhanced tool for repairing common syntax errors in test files.
    """

    def __init__(self, project_root: Optional[Path] = None, verbose: bool = False):
        """
        Initialize the test repair tool.

        Args:
            project_root: Root directory of the project
            verbose: Enable verbose output
        """
        self.project_root = project_root or Path(__file__).resolve().parents[4]
        self.tests_dir = self.project_root / "backend" / "app" / "tests"
        self.fixed_files = 0
        self.error_files = 0
        self.skipped_files = 0
        self.error_types: Dict[str, int] = {}
        self.verbose = verbose

        print(f"Project root: {self.project_root}")
        print(f"Tests directory: {self.tests_dir}")

    def find_test_files(self, start_dir: Path = None) -> List[Path]:
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

    def check_syntax(
        self, file_path: Path
    ) -> Tuple[Optional[SyntaxError], Optional[int], Optional[int]]:
        """
        Check if a Python file has syntax errors and return detailed information.

        Args:
            file_path: Path to the Python file

        Returns:
            Tuple of (SyntaxError, line_number, column_offset) if there's an error,
            (None, None, None) otherwise
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                ast.parse(content, filename=str(file_path))
            return None, None, None
        except SyntaxError as e:
            return e, e.lineno, e.offset

    def get_line_content(self, file_path: Path, line_number: int) -> str:
        """
        Get the content of a specific line in a file.

        Args:
            file_path: Path to the file
            line_number: Line number (1-based)

        Returns:
            Content of the line
        """
        with open(file_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if i == line_number:
                    return line.rstrip("\n")
        return ""

    def fix_missing_colons(self, content: str) -> str:
        """
        Fix missing colons after function and class definitions with improved pattern matching.

        Args:
            content: File content

        Returns:
            Fixed content
        """
        # Function definition missing colon pattern - more precise
        pattern = r"(def\s+[a-zA-Z0-9_]+\s*\([^)]*\))\s*(?!\s*:)"
        fixed = re.sub(pattern, r"\1:", content)

        # Another pattern for async functions
        pattern = r"(async\s+def\s+[a-zA-Z0-9_]+\s*\([^)]*\))\s*(?!\s*:)"
        fixed = re.sub(pattern, r"\1:", fixed)

        # Class definition missing colon pattern - more precise
        pattern = r"(class\s+[a-zA-Z0-9_]+(?:\s*\([^)]*\))?)\s*(?!\s*:)"
        fixed = re.sub(pattern, r"\1:", fixed)

        # Fix methods in classes that are missing colons
        pattern = r"(\s+def\s+[a-zA-Z0-9_]+\s*\([^)]*\))\s*(?!\s*:)"
        fixed = re.sub(pattern, r"\1:", fixed)

        # Fix async methods in classes
        pattern = r"(\s+async\s+def\s+[a-zA-Z0-9_]+\s*\([^)]*\))\s*(?!\s*:)"
        fixed = re.sub(pattern, r"\1:", fixed)

        # Fix test methods in pytest classes
        pattern = r"(\s+def\s+test_[a-zA-Z0-9_]+\s*\([^)]*\))\s*(?!\s*:)"
        fixed = re.sub(pattern, r"\1:", fixed)

        # Fix fixture methods
        pattern = r"(\s*@pytest\.fixture(?:\s*\([^)]*\))?\s*\n\s*def\s+[a-zA-Z0-9_]+\s*\([^)]*\))\s*(?!\s*:)"
        fixed = re.sub(pattern, r"\1:", fixed)

        return fixed

    def fix_indentation(self, content: str) -> str:
        """
        Fix common indentation issues with improved detection.

        Args:
            content: File content

        Returns:
            Fixed content
        """
        lines = content.split("\n")
        fixed_lines = []
        in_func_or_class = False
        expected_indent = 0
        current_indent_level = 0
        indent_stack = [0]  # Stack to track indentation levels

        for i, line in enumerate(lines):
            # Skip empty lines or comment-only lines
            if not line.strip() or line.strip().startswith("#"):
                fixed_lines.append(line)
                continue

            # Get current line indentation
            current_indent = len(line) - len(line.lstrip())
            line_content = line.strip()

            # Check if line ends with colon (start of a new block)
            if line_content.endswith(":"):
                fixed_lines.append(line)
                indent_stack.append(
                    current_indent + 4
                )  # Push expected indent for next line
                continue

            # Check if this is a block ending line
            if line_content in (
                "return",
                "pass",
                "break",
                "continue",
            ) or line_content.startswith(("else:", "elif ", "except:", "finally:")):
                # This might change indentation
                if len(indent_stack) > 1 and current_indent < indent_stack[-1]:
                    indent_stack.pop()  # Pop indentation level

            # Check if current indentation matches expected
            if len(indent_stack) > 1:
                expected_indent = indent_stack[-1]
                if current_indent != expected_indent and current_indent == 0:
                    # Line should be indented but isn't - fix it
                    fixed_lines.append(" " * expected_indent + line_content)
                    continue

            # Default: keep the line as is
            fixed_lines.append(line)

            # Update indentation tracking based on line content
            if line_content.startswith(("def ", "class ")) and i < len(lines) - 1:
                # Look ahead to next non-empty line to see if indentation starts
                next_index = i + 1
                while next_index < len(lines) and not lines[next_index].strip():
                    next_index += 1

                if next_index < len(lines):
                    next_line = lines[next_index]
                    next_indent = len(next_line) - len(next_line.lstrip())
                    if next_indent <= current_indent:
                        # Missing indentation in next line
                        indent_stack.append(current_indent + 4)

        return "\n".join(fixed_lines)

    def fix_missing_block_after_colon(self, content: str) -> str:
        """
        Fix missing indented blocks after lines ending with colon.

        Args:
            content: File content

        Returns:
            Fixed content
        """
        lines = content.split("\n")
        fixed_lines = []
        i = 0

        while i < len(lines):
            line = lines[i]
            line_content = line.strip()

            # Add the current line
            fixed_lines.append(line)

            if line_content.endswith(":") and not line_content.startswith("#"):
                current_indent = len(line) - len(line.lstrip())
                expected_indent = current_indent + 4

                # Check if next line exists and has proper indentation
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    if not next_line.strip():  # Empty line
                        i += 1
                        continue

                    next_indent = len(next_line) - len(next_line.lstrip())
                    if next_indent <= current_indent:
                        # Missing indentation - add pass statement
                        fixed_lines.append(" " * expected_indent + "pass")

            i += 1

        return "\n".join(fixed_lines)

    def fix_common_imports(self, content: str) -> str:
        """
        Add common missing imports for test files with improved detection.

        Args:
            content: File content

        Returns:
            Fixed content with added imports
        """
        # Check if file contains certain test-related features without imports
        needs_unittest_mock = any(
            x in content
            for x in ["Mock(", "MagicMock(", "patch(", "@patch", "AsyncMock("]
        )
        needs_pytest = any(
            x in content for x in ["pytest.", "@pytest.", "pytest.fixture"]
        )
        needs_fixture = "@fixture" in content or "pytest.fixture" in content
        needs_pytest_raises = "pytest.raises" in content or "with raises(" in content

        # List of import lines to add if needed
        import_lines = []

        if needs_unittest_mock and "from unittest.mock import" not in content:
            import_lines.append(
                "from unittest.mock import Mock, MagicMock, patch, AsyncMock"
            )

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

        if needs_pytest_raises and "raises" not in content:
            if "from pytest import" in content:
                # Add raises to existing pytest import
                content = re.sub(
                    r"from pytest import ([^(\n]*)",
                    r"from pytest import \1, raises",
                    content,
                )
            elif "import pytest" in content:
                pass  # Can use pytest.raises
            else:
                import_lines.append("from pytest import raises")

        if import_lines:
            # Add imports after any docstring if present
            if '"""' in content:
                doc_end = content.find('"""', content.find('"""') + 3) + 3
                pre_content = content[:doc_end]
                post_content = content[doc_end:]
                return (
                    pre_content + "\n" + "\n".join(import_lines) + "\n" + post_content
                )
            else:
                # Just add to the top
                return "\n".join(import_lines) + "\n\n" + content

        return content

    def fix_line_with_specific_error(
        self, file_path: Path, line_number: int, error_msg: str, content: str
    ) -> str:
        """
        Apply targeted fixes for specific errors at specific lines.

        Args:
            file_path: Path to the file
            line_number: Line number with the error
            error_msg: Error message
            content: Full file content

        Returns:
            Fixed content
        """
        lines = content.split("\n")
        if line_number <= 0 or line_number > len(lines):
            return content

        # Get the problematic line and surrounding context
        problem_line = lines[line_number - 1]
        indent = len(problem_line) - len(problem_line.lstrip())
        line_content = problem_line.strip()

        # Handle expected colon errors
        if "expected ':'" in error_msg:
            if re.search(r"(def|class)\s+[a-zA-Z0-9_]+.*\)?\s*$", line_content):
                lines[line_number - 1] = problem_line + ":"
                return "\n".join(lines)

        # Handle indentation errors
        if "unexpected indent" in error_msg:
            # Reduce indentation by 4 spaces
            if indent >= 4:
                lines[line_number - 1] = " " * (indent - 4) + line_content
                return "\n".join(lines)

        if "unexpected unindent" in error_msg:
            # Increase indentation by 4 spaces
            lines[line_number - 1] = " " * (indent + 4) + line_content
            return "\n".join(lines)

        # Handle expected indented block
        if "expected an indented block" in error_msg:
            # Add a pass statement with proper indentation
            lines.insert(line_number, " " * (indent + 4) + "pass")
            return "\n".join(lines)

        # Handle common syntax errors in test files
        if "invalid syntax" in error_msg:
            # Check for common test-specific errors
            if line_content.startswith("@pytest.fixture") and not line_content.endswith(
                ")"
            ):
                # Fix incomplete fixture decorator
                lines[line_number - 1] = problem_line + ")"
                return "\n".join(lines)

            # Fix missing self parameter in class methods
            if re.search(r"def\s+test_[a-zA-Z0-9_]+\(\s*\):", line_content):
                fixed_line = re.sub(
                    r"def\s+(test_[a-zA-Z0-9_]+)\(\s*\)", r"def \1(self)", line_content
                )
                lines[line_number - 1] = " " * indent + fixed_line
                return "\n".join(lines)

        # Return original content if no specific fix applied
        return content

    def fix_syntax_errors(self, file_path: Path, dry_run: bool = False) -> bool:
        """
        Attempt to fix common syntax errors in a file with enhanced strategies.

        Args:
            file_path: Path to the file
            dry_run: If True, don't write changes to disk

        Returns:
            True if fixed successfully, False otherwise
        """
        try:
            error, line_num, col_offset = self.check_syntax(file_path)
            if not error:
                if self.verbose:
                    print(f"{Colors.GREEN}No syntax errors in {file_path}{Colors.ENDC}")
                return True

            error_msg = str(error)
            if self.verbose:
                print(
                    f"Attempting to fix {file_path} (line {line_num}, col {col_offset}): {error_msg}"
                )

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Try targeted fix for the specific error first
            if line_num:
                fixed_content = self.fix_line_with_specific_error(
                    file_path, line_num, error_msg, content
                )

                # Validate if targeted fix worked
                try:
                    ast.parse(fixed_content)
                    if not dry_run:
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(fixed_content)
                        print(
                            f"{Colors.GREEN}Fixed {file_path} with targeted fix{Colors.ENDC}"
                        )
                        self.fixed_files += 1
                    else:
                        print(
                            f"{Colors.BLUE}Would fix {file_path} with targeted fix (dry run){Colors.ENDC}"
                        )
                    return True
                except SyntaxError:
                    # Targeted fix didn't work, continue with general fixes
                    if self.verbose:
                        print(f"Targeted fix didn't work, trying general fixes...")

            # Apply general fixes
            fixed_content = content
            fixed_content = self.fix_missing_colons(fixed_content)
            fixed_content = self.fix_indentation(fixed_content)
            fixed_content = self.fix_missing_block_after_colon(fixed_content)
            fixed_content = self.fix_common_imports(fixed_content)

            # Check if we fixed it
            if content == fixed_content:
                print(
                    f"{Colors.WARNING}No automatic fixes available for {file_path}{Colors.ENDC}"
                )
                self.skipped_files += 1
                return False

            # Validate the fixed content
            try:
                ast.parse(fixed_content)
                if not dry_run:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(fixed_content)
                    print(
                        f"{Colors.GREEN}Fixed {file_path} with general fixes{Colors.ENDC}"
                    )
                    self.fixed_files += 1
                else:
                    print(
                        f"{Colors.BLUE}Would fix {file_path} with general fixes (dry run){Colors.ENDC}"
                    )
                return True
            except SyntaxError as e:
                print(
                    f"{Colors.FAIL}Failed to fix {file_path} - still has syntax errors: {str(e)}{Colors.ENDC}"
                )
                self.error_files += 1
                return False

        except Exception as e:
            print(f"{Colors.FAIL}Error processing {file_path}: {str(e)}{Colors.ENDC}")
            if self.verbose:
                traceback.print_exc()
            self.error_files += 1
            return False

    def categorize_error(self, error: SyntaxError) -> str:
        """
        Categorize a syntax error for reporting with more detailed categories.

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
        elif "invalid syntax" in msg:
            return "invalid_syntax"
        elif "invalid token" in msg:
            return "invalid_token"
        elif "EOF while scanning" in msg:
            return "incomplete_structure"
        else:
            return "other"

    def repair_all(self, start_dir: Path = None, dry_run: bool = False) -> None:
        """
        Find and repair syntax errors in all test files with enhanced reporting.

        Args:
            start_dir: Starting directory to search from (default: tests_dir)
            dry_run: If True, don't write changes to disk
        """
        test_files = self.find_test_files(start_dir)
        print(f"Found {len(test_files)} test files")

        files_with_errors = []
        categorized_errors: Dict[str, List[Path]] = {
            "missing_colon": [],
            "indent_error": [],
            "missing_indent": [],
            "invalid_syntax": [],
            "invalid_token": [],
            "incomplete_structure": [],
            "other": [],
        }

        # First pass: check and categorize errors
        for file_path in test_files:
            error, line_num, col_offset = self.check_syntax(file_path)
            if error:
                files_with_errors.append((file_path, error, line_num, col_offset))
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
        for file_path, error, line_num, col_offset in files_with_errors:
            if self.verbose:
                print(f"\nAttempting to fix {file_path}")
                print(f"Error: {error} at line {line_num}, column {col_offset}")
            self.fix_syntax_errors(file_path, dry_run)

        # Print summary
        print(f"\n{Colors.HEADER}Repair Summary:{Colors.ENDC}")
        print(f"  {Colors.GREEN}Fixed: {self.fixed_files}{Colors.ENDC}")
        print(f"  {Colors.WARNING}Skipped: {self.skipped_files}{Colors.ENDC}")
        print(f"  {Colors.FAIL}Failed: {self.error_files}{Colors.ENDC}")

        if not dry_run and self.fixed_files > 0:
            print(
                f"\n{Colors.GREEN}Successfully fixed {self.fixed_files} files!{Colors.ENDC}"
            )
        if self.error_files > 0:
            print(
                f"\n{Colors.WARNING}Some files still need manual fixes. See above for details.{Colors.ENDC}"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced repair tool for syntax errors in test files"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be fixed without making changes",
    )
    parser.add_argument("--path", type=str, help="Specific path to check and fix")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    repair_tool = EnhancedSyntaxRepair(verbose=args.verbose)

    if args.path:
        path = Path(args.path)
        if path.is_file():
            error, line_num, col_offset = repair_tool.check_syntax(path)
            if error:
                print(
                    f"Found syntax error in {path} at line {line_num}, column {col_offset}: {error}"
                )
                repair_tool.fix_syntax_errors(path, args.dry_run)
            else:
                print(f"No syntax errors found in {path}")
        else:
            repair_tool.repair_all(path, args.dry_run)
    else:
        repair_tool.repair_all(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
