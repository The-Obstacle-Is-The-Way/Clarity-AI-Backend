#!/usr/bin/env python3
"""
Indentation Fixer for Novamind Backend Test Files

This script fixes common indentation issues in test files, including:
1. Missing indentation after control statements (if, for, with, try)
2. Unexpected indentation
3. Unmatched brackets and parentheses
4. Unindent does not match any outer indentation level

Usage:
    python indentation_fixer.py [--dry-run] [--verbose] [--fix-file PATH]
"""

import argparse
import re
import sys
from pathlib import Path


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


class IndentationFixer:
    def __init__(self, project_root: Path, dry_run: bool = False, verbose: bool = False):
        self.project_root = project_root
        self.tests_dir = project_root / "app" / "tests"
        self.dry_run = dry_run
        self.verbose = verbose
        self.fixed_files = []
        self.failed_files = []

        # Control statements that require indented blocks
        self.control_statements = [
            r"^\s*if\s+.*:$",
            r"^\s*elif\s+.*:$",
            r"^\s*else\s*:$",
            r"^\s*for\s+.*:$",
            r"^\s*while\s+.*:$",
            r"^\s*try\s*:$",
            r"^\s*except\s+.*:$",
            r"^\s*except\s*:$",
            r"^\s*finally\s*:$",
            r"^\s*with\s+.*:$",
            r"^\s*def\s+.*:$",
            r"^\s*class\s+.*:$",
        ]

        # Known patterns for fixing
        self.fix_patterns = [
            # Fix return outside function - wrap in a function
            (r"return\s+\{([^}]*)\}", self._fix_return_outside_function),
            # Fix unmatched brackets and parentheses
            (r"\)\s*$", self._fix_unmatched_parenthesis),
            (r"\}\s*$", self._fix_unmatched_brace),
        ]

    def find_test_files(self) -> list[Path]:
        """Find all test files in the test directory."""
        test_files = []
        for path in self.tests_dir.glob("**/*.py"):
            if path.name.startswith("test_"):
                test_files.append(path)
        return test_files

    def fix_file(self, file_path: Path) -> bool:
        """
        Fix issues in a test file.

        Returns:
            bool: True if fixes were applied successfully, False otherwise
        """
        try:
            if self.verbose:
                print(f"Examining {file_path}")

            with open(file_path, encoding="utf-8") as f:
                lines = f.readlines()

            # Store original lines for comparison
            original_lines = lines.copy()

            # Fix indentation issues
            lines = self.fix_indentation(lines)

            # Fix bracket matching
            lines = self.fix_bracket_matching(lines)

            # Apply regex-based fixes
            for line_idx in range(len(lines)):
                for pattern, fix_func in self.fix_patterns:
                    if re.search(pattern, lines[line_idx]):
                        lines = fix_func(lines, line_idx)

            # Only write to file if content changed and we're not in dry run mode
            if lines != original_lines:
                if not self.dry_run:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.writelines(lines)

                print(f"{Colors.GREEN}Fixed {file_path}{Colors.ENDC}")
                self.fixed_files.append(file_path)
                return True
            elif self.verbose:
                print(f"{Colors.BLUE}No indentation issues found in {file_path}{Colors.ENDC}")

            return True

        except Exception as e:
            print(f"{Colors.RED}Error fixing {file_path}: {e!s}{Colors.ENDC}")
            self.failed_files.append((file_path, str(e)))
            return False

    def fix_indentation(self, lines: list[str]) -> list[str]:
        """Fix indentation issues in the file."""
        fixed_lines = []

        # Track indentation level and blocks
        current_indent = 0
        expecting_indent = False
        indent_stack = []

        for i, line in enumerate(lines):
            line_stripped = line.strip()

            # Skip empty lines
            if not line_stripped:
                fixed_lines.append(line)
                continue

            # Calculate current line indentation
            line_indent = len(line) - len(line.lstrip())

            # Check if previous line is a control statement requiring indentation
            if (
                expecting_indent
                and line_indent <= current_indent
                and line_stripped
                and line_stripped[0] != "#"
            ):
                # Line needs more indentation
                if not (
                    line_stripped.startswith("except")
                    or line_stripped.startswith("elif")
                    or line_stripped.startswith("else")
                    or line_stripped.startswith("finally")
                ):
                    line = " " * (current_indent + 4) + line_stripped + "\n"

            # Check for control statements that require indented blocks
            for pattern in self.control_statements:
                if re.match(pattern, line):
                    indent_stack.append(line_indent)
                    current_indent = line_indent
                    expecting_indent = True
                    break

            # Check for block endings (dedent)
            if (
                indent_stack
                and line_indent <= indent_stack[-1]
                and not line_stripped.startswith(("#", ")", "}", "]"))
            ):
                if not (
                    line_stripped.startswith("except")
                    or line_stripped.startswith("elif")
                    or line_stripped.startswith("else")
                    or line_stripped.startswith("finally")
                ):
                    indent_stack.pop()
                    if indent_stack:
                        current_indent = indent_stack[-1]
                    else:
                        current_indent = 0
                    expecting_indent = False

            fixed_lines.append(line)

        return fixed_lines

    def fix_bracket_matching(self, lines: list[str]) -> list[str]:
        """Fix bracket matching issues by identifying and correcting unmatched brackets."""
        # Count brackets across the file
        bracket_counts = {"(": 0, ")": 0, "{": 0, "}": 0, "[": 0, "]": 0}

        # First pass - count brackets
        for line in lines:
            for char in line:
                if char in bracket_counts:
                    bracket_counts[char] += 1

        # Check for mismatches
        if bracket_counts["("] != bracket_counts[")"]:
            # Parentheses mismatch
            diff = bracket_counts["("] - bracket_counts[")"]
            if diff > 0:
                # Missing closing parentheses
                last_line = lines[-1].rstrip()
                lines[-1] = last_line + ")" * diff + "\n"
            elif diff < 0:
                # Too many closing parentheses, remove from appropriate lines
                for i in range(len(lines) - 1, -1, -1):
                    if ")" in lines[i] and diff < 0:
                        # Count and remove excess closing parentheses
                        count = min(lines[i].count(")"), abs(diff))
                        if count > 0:
                            # Replace the closing paren with nothing
                            for _ in range(count):
                                pos = lines[i].rfind(")")
                                if pos >= 0:
                                    lines[i] = lines[i][:pos] + lines[i][pos + 1 :]
                                    diff += 1

        if bracket_counts["{"] != bracket_counts["}"]:
            # Braces mismatch
            diff = bracket_counts["{"] - bracket_counts["}"]
            if diff > 0:
                # Missing closing braces
                last_line = lines[-1].rstrip()
                lines[-1] = last_line + "}" * diff + "\n"
            elif diff < 0:
                # Too many closing braces, remove from appropriate lines
                for i in range(len(lines) - 1, -1, -1):
                    if "}" in lines[i] and diff < 0:
                        # Count and remove excess closing braces
                        count = min(lines[i].count("}"), abs(diff))
                        if count > 0:
                            # Replace the closing brace with nothing
                            for _ in range(count):
                                pos = lines[i].rfind("}")
                                if pos >= 0:
                                    lines[i] = lines[i][:pos] + lines[i][pos + 1 :]
                                    diff += 1

        if bracket_counts["["] != bracket_counts["]"]:
            # Square brackets mismatch
            diff = bracket_counts["["] - bracket_counts["]"]
            if diff > 0:
                # Missing closing brackets
                last_line = lines[-1].rstrip()
                lines[-1] = last_line + "]" * diff + "\n"
            elif diff < 0:
                # Too many closing brackets, remove from appropriate lines
                for i in range(len(lines) - 1, -1, -1):
                    if "]" in lines[i] and diff < 0:
                        # Count and remove excess closing brackets
                        count = min(lines[i].count("]"), abs(diff))
                        if count > 0:
                            # Replace the closing bracket with nothing
                            for _ in range(count):
                                pos = lines[i].rfind("]")
                                if pos >= 0:
                                    lines[i] = lines[i][:pos] + lines[i][pos + 1 :]
                                    diff += 1

        return lines

    def _fix_return_outside_function(self, lines: list[str], line_idx: int) -> list[str]:
        """Fix 'return' outside function by wrapping it in a function."""
        # Find the indentation of the return statement
        line = lines[line_idx]
        indent = len(line) - len(line.lstrip())

        # Create a helper function to wrap the return
        function_def = " " * indent + "def _helper_function():\n"
        return_line = " " * (indent + 4) + line.lstrip()
        function_call = " " * indent + "result = _helper_function()\n"

        # Insert the new lines
        new_lines = lines[:line_idx]
        new_lines.append(function_def)
        new_lines.append(return_line)
        new_lines.append(function_call)
        new_lines.extend(lines[line_idx + 1 :])

        return new_lines

    def _fix_unmatched_parenthesis(self, lines: list[str], line_idx: int) -> list[str]:
        """Fix unmatched parenthesis by counting and matching them."""
        line = lines[line_idx]

        # Count open and close parentheses
        open_count = line.count("(")
        close_count = line.count(")")

        if close_count > open_count:
            # Too many closing parentheses, remove extras
            diff = close_count - open_count
            for _ in range(diff):
                pos = line.rfind(")")
                if pos >= 0:
                    line = line[:pos] + line[pos + 1 :]

            lines[line_idx] = line

        return lines

    def _fix_unmatched_brace(self, lines: list[str], line_idx: int) -> list[str]:
        """Fix unmatched brace by counting and matching them."""
        line = lines[line_idx]

        # Count open and close braces
        open_count = line.count("{")
        close_count = line.count("}")

        if close_count > open_count:
            # Too many closing braces, remove extras
            diff = close_count - open_count
            for _ in range(diff):
                pos = line.rfind("}")
                if pos >= 0:
                    line = line[:pos] + line[pos + 1 :]

            lines[line_idx] = line

        return lines

    def run(self) -> bool:
        """
        Run the fixer on all test files.

        Returns:
            bool: True if all files were fixed successfully, False otherwise
        """
        print(f"{Colors.HEADER}Running Indentation Fixer...{Colors.ENDC}")
        print(f"Project root: {self.project_root}")
        print(f"Tests directory: {self.tests_dir}")

        if self.dry_run:
            print(f"{Colors.YELLOW}DRY RUN MODE: No files will be modified{Colors.ENDC}")

        test_files = self.find_test_files()
        print(f"Found {len(test_files)} test files")

        for file_path in test_files:
            self.fix_file(file_path)

        # Print summary
        print("\nSummary:")
        print(f"  - Fixed {len(self.fixed_files)} files")
        print(f"  - Failed to fix {len(self.failed_files)} files")

        if self.failed_files:
            print(f"\n{Colors.RED}Files with errors:{Colors.ENDC}")
            for file_path, error in self.failed_files:
                print(f"  - {file_path}: {error}")

        return len(self.failed_files) == 0

    def fix_specific_file(self, file_path: Path) -> bool:
        """Fix a specific file."""
        return self.fix_file(file_path)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Indentation Fixer for Novamind Backend Test Files"
    )
    parser.add_argument("--dry-run", action="store_true", help="Don't write any changes to files")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--fix-file", type=str, help="Fix a specific file")
    return parser.parse_args()


def main():
    args = parse_args()

    # Determine project root
    current_dir = Path(__file__).resolve().parent
    project_root = current_dir
    while project_root.name != "backend" and project_root != project_root.parent:
        project_root = project_root.parent

    fixer = IndentationFixer(project_root, dry_run=args.dry_run, verbose=args.verbose)

    if args.fix_file:
        file_path = Path(args.fix_file)
        if not file_path.is_absolute():
            file_path = project_root / file_path

        success = fixer.fix_specific_file(file_path)
    else:
        success = fixer.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
