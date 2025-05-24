#!/usr/bin/env python3
"""
Advanced Test Repair Script

This script scans for Python test files with syntax errors and attempts to 
fix them using advanced parsing and repair techniques.
"""
import ast
import os
import re
import subprocess
import tempfile
from pathlib import Path


class TestRepairTool:
    """Advanced test repair tool for fixing syntax errors in Python test files."""

    def __init__(self, project_root: str, tests_dir: str):
        """Initialize the test repair tool.

        Args:
            project_root: Path to the project root directory
            tests_dir: Path to the tests directory
        """
        self.project_root = Path(project_root)
        self.tests_dir = Path(tests_dir)
        self.fixed_files: list[str] = []
        self.failed_files: list[str] = []
        self.skipped_files: list[str] = []

    def find_test_files(self) -> list[Path]:
        """Find all Python test files in the tests directory.

        Returns:
            List of paths to test files
        """
        test_files = []
        for root, _, files in os.walk(self.tests_dir):
            for file in files:
                if file.startswith("test_") and file.endswith(".py"):
                    test_files.append(Path(root) / file)

        print(f"Found {len(test_files)} test files")
        return test_files

    def check_syntax(self, file_path: Path) -> tuple[bool, str | None, str | None]:
        """Check if file has syntax errors.

        Args:
            file_path: Path to the file to check

        Returns:
            Tuple of (has_error, error_message, error_type)
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                source = f.read()

            # Try to parse the file
            ast.parse(source)
            return False, None, None
        except SyntaxError as e:
            return True, str(e), type(e).__name__
        except Exception as e:
            return True, str(e), type(e).__name__

    def fix_missing_closing_parenthesis(self, content: str) -> str:
        """Fix missing closing parentheses in code.

        Args:
            content: Source code content

        Returns:
            Fixed content
        """
        # Count opening and closing parentheses
        open_count = content.count("(")
        close_count = content.count(")")

        # Add missing closing parentheses
        if open_count > close_count:
            missing = open_count - close_count
            lines = content.split("\n")

            # Find the last non-empty line
            last_line_idx = len(lines) - 1
            while last_line_idx >= 0 and not lines[last_line_idx].strip():
                last_line_idx -= 1

            if last_line_idx >= 0:
                lines[last_line_idx] += ")" * missing
                return "\n".join(lines)

        return content

    def fix_missing_closing_brackets(self, content: str) -> str:
        """Fix missing closing brackets in code.

        Args:
            content: Source code content

        Returns:
            Fixed content
        """
        # Similar approach for square brackets
        open_count = content.count("[")
        close_count = content.count("]")

        # Add missing closing brackets
        if open_count > close_count:
            missing = open_count - close_count
            lines = content.split("\n")

            # Find the last non-empty line
            last_line_idx = len(lines) - 1
            while last_line_idx >= 0 and not lines[last_line_idx].strip():
                last_line_idx -= 1

            if last_line_idx >= 0:
                lines[last_line_idx] += "]" * missing
                return "\n".join(lines)

        return content

    def fix_missing_closing_braces(self, content: str) -> str:
        """Fix missing closing braces in code.

        Args:
            content: Source code content

        Returns:
            Fixed content
        """
        # Similar approach for curly braces
        open_count = content.count("{")
        close_count = content.count("}")

        # Add missing closing braces
        if open_count > close_count:
            missing = open_count - close_count
            lines = content.split("\n")

            # Find the last non-empty line
            last_line_idx = len(lines) - 1
            while last_line_idx >= 0 and not lines[last_line_idx].strip():
                last_line_idx -= 1

            if last_line_idx >= 0:
                lines[last_line_idx] += "}" * missing
                return "\n".join(lines)

        return content

    def fix_indentation_errors(self, content: str) -> str:
        """Fix indentation errors in code.

        Args:
            content: Source code content

        Returns:
            Fixed content
        """
        lines = content.split("\n")
        fixed_lines = []
        indentation_level = 0

        # Process line by line to fix indentation
        for line in lines:
            stripped = line.strip()

            # Skip empty lines
            if not stripped:
                fixed_lines.append("")
                continue

            # Check for blocks that increase indentation
            if stripped.endswith(":"):
                fixed_lines.append("    " * indentation_level + stripped)
                indentation_level += 1
                continue

            # Check for blocks that decrease indentation
            if any(
                stripped.startswith(kw) for kw in ["return", "break", "continue", "raise", "pass"]
            ):
                indentation_level = max(0, indentation_level - 1)

            # Apply current indentation
            fixed_lines.append("    " * indentation_level + stripped)

        return "\n".join(fixed_lines)

    def fix_trailing_commas(self, content: str) -> str:
        """Fix trailing commas in function calls and data structures.

        Args:
            content: Source code content

        Returns:
            Fixed content
        """
        # Fix trailing commas in tuples, lists, and dicts
        patterns = [
            (r",\s*\)", ")"),  # Remove trailing comma before closing parenthesis
            (r",\s*\]", "]"),  # Remove trailing comma before closing bracket
            (r",\s*\}", "}"),  # Remove trailing comma before closing brace
        ]

        fixed_content = content
        for pattern, replacement in patterns:
            fixed_content = re.sub(pattern, replacement, fixed_content)

        return fixed_content

    def fix_invalid_escape_sequences(self, content: str) -> str:
        """Fix invalid escape sequences in strings.

        Args:
            content: Source code content

        Returns:
            Fixed content
        """
        # Find all strings with potentially invalid escape sequences
        string_pattern = r'(["\'])(.*?(?<!\\)(?:\\\\)*)\1'

        def replace_invalid_escapes(match):
            quote = match.group(1)
            string_content = match.group(2)

            # Replace invalid escape sequences
            fixed_string = re.sub(r'\\([^nrtbfvx0-7\\\'"])', r"\\\\\1", string_content)

            return quote + fixed_string + quote

        return re.sub(string_pattern, replace_invalid_escapes, content)

    def fix_missing_colons(self, content: str) -> str:
        """Fix missing colons after control flow statements.

        Args:
            content: Source code content

        Returns:
            Fixed content
        """
        lines = content.split("\n")
        fixed_lines = []

        for line in lines:
            stripped = line.strip()

            # Check for control flow statements that should end with a colon
            if any(
                stripped.startswith(kw)
                for kw in [
                    "if ",
                    "elif ",
                    "else",
                    "for ",
                    "while ",
                    "try",
                    "except ",
                    "finally",
                    "def ",
                    "class ",
                ]
            ):
                # If it doesn't end with a colon, add one
                if not stripped.endswith(":"):
                    if stripped.endswith(")") or " in " in stripped:
                        line = line + ":"

            fixed_lines.append(line)

        return "\n".join(fixed_lines)

    def fix_file(self, file_path: Path) -> bool:
        """Attempt to fix syntax errors in a file.

        Args:
            file_path: Path to the file to fix

        Returns:
            True if the file was fixed successfully, False otherwise
        """
        print(f"Attempting to fix {file_path}")

        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            # Apply various fixes
            fixed_content = content
            fixed_content = self.fix_missing_closing_parenthesis(fixed_content)
            fixed_content = self.fix_missing_closing_brackets(fixed_content)
            fixed_content = self.fix_missing_closing_braces(fixed_content)
            fixed_content = self.fix_trailing_commas(fixed_content)
            fixed_content = self.fix_invalid_escape_sequences(fixed_content)
            fixed_content = self.fix_missing_colons(fixed_content)

            # Write fixed content to a temporary file
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as temp:
                temp.write(fixed_content)
                temp_path = temp.name

            # Try to compile the fixed file
            try:
                subprocess.check_output(
                    ["python", "-m", "py_compile", temp_path], stderr=subprocess.STDOUT
                )
                os.unlink(temp_path)

                # If we got here, the fix worked, so write it back to the original file
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(fixed_content)

                print(f"Successfully fixed {file_path}")
                return True
            except subprocess.CalledProcessError:
                os.unlink(temp_path)
                print(f"Failed to fix {file_path} - still has syntax errors")
                return False

        except Exception as e:
            print(f"Error fixing {file_path}: {e}")
            return False

    def fix_syntax_errors(self, test_files: list[Path]) -> dict[str, int]:
        """Fix syntax errors in test files.

        Args:
            test_files: List of paths to test files

        Returns:
            Dictionary with counts of fixed, failed, and skipped files
        """
        files_with_errors = []
        error_types = {}

        # First pass: Identify files with syntax errors
        for file_path in test_files:
            has_error, error_message, error_type = self.check_syntax(file_path)

            if has_error:
                files_with_errors.append(file_path)
                error_types[error_type] = error_types.get(error_type, 0) + 1
                print(f"Found error in {file_path}: {error_message}")

        print(f"\nFound {len(files_with_errors)} files with syntax errors")
        print("Error types:")
        for error_type, count in error_types.items():
            print(f"  {error_type}: {count} files")

        # Second pass: Fix files with errors
        for file_path in files_with_errors:
            if self.fix_file(file_path):
                self.fixed_files.append(str(file_path))
            else:
                self.failed_files.append(str(file_path))

        # Final pass: Check if the fixes worked
        for file_path in [Path(path) for path in self.fixed_files]:
            has_error, _, _ = self.check_syntax(file_path)

            if has_error:
                # If still has error, move from fixed to failed
                self.fixed_files.remove(str(file_path))
                self.failed_files.append(str(file_path))
                print(f"Failed to fix {file_path} - still has syntax errors")

        return {
            "total": len(test_files),
            "with_errors": len(files_with_errors),
            "fixed": len(self.fixed_files),
            "failed": len(self.failed_files),
            "skipped": len(self.skipped_files),
        }

    def print_report(self, stats: dict[str, int]) -> None:
        """Print report of repair statistics.

        Args:
            stats: Dictionary with counts of fixed, failed, and skipped files
        """
        print("\nRepair Summary:")
        print(f"  Total test files: {stats['total']}")
        print(f"  Files with errors: {stats['with_errors']}")
        print(f"  Successfully fixed: {stats['fixed']}")
        print(f"  Failed to fix: {stats['failed']}")
        print(f"  Skipped: {stats['skipped']}")

        if self.failed_files:
            print("\nFiles that still need manual fixes:")
            for file in self.failed_files:
                print(f"  {file}")

        if self.fixed_files:
            print("\nSuccessfully fixed files:")
            for file in self.fixed_files:
                print(f"  {file}")


def main():
    """Main function."""
    # Determine the project root
    if os.environ.get("PROJECT_ROOT"):
        project_root = os.environ.get("PROJECT_ROOT")
    else:
        # Try to determine project root from current directory
        current_dir = Path.cwd()
        if "backend" in str(current_dir):
            project_root = (
                str(current_dir.parents[0]) if "backend" == current_dir.name else str(current_dir)
            )
        else:
            project_root = str(current_dir)

    # Determine the tests directory
    tests_dir = os.path.join(project_root, "backend", "app", "tests")

    print(f"Project root: {project_root}")
    print(f"Tests directory: {tests_dir}")

    # Initialize the repair tool
    repair_tool = TestRepairTool(project_root, tests_dir)

    # Find test files
    test_files = repair_tool.find_test_files()

    # Fix syntax errors
    stats = repair_tool.fix_syntax_errors(test_files)

    # Print report
    repair_tool.print_report(stats)


if __name__ == "__main__":
    main()
