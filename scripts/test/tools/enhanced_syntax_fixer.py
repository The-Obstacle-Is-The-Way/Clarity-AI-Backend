#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Test Suite Syntax Fixer Script

This script analyzes test files with syntax errors and automatically fixes common issues:
1. Missing colons after function/class declarations
2. Indentation issues
3. Other common syntax errors that prevent compilation

Usage:
    python scripts/test/tools/enhanced_syntax_fixer.py [--test-path PATH]
"""

import os
import re
import sys
import ast
import tokenize
import io
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Set, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("enhanced_syntax_fixer")

# Root path for test files
DEFAULT_TEST_PATH = os.path.join("app", "tests")

# Common patterns for fixes
CLASS_DEF_PATTERN = re.compile(r'^(\s*)(class\s+\w+[\w\s(),]*)')
FUNCTION_DEF_PATTERN = re.compile(r'^(\s*)(def\s+\w+[\w\s(),=\[\]\'\"*]*)')
FIXTURE_PATTERN = re.compile(r'^(\s*)@pytest\.fixture')
MISSING_COLON_PATTERN = re.compile(r'^(\s*)(class|def)\s+\w+[\w\s(),=\[\]\'\"*]*$')
UNEXPECTED_INDENT_PATTERN = re.compile(r'^\s*[^\s]+.*$')

class SyntaxFixResult:
    """Results of a syntax fix attempt"""
    def __init__(self):
        self.fixed = False
        self.errors = []
        self.fixed_issues = []

    def add_error(self, line_num: int, message: str):
        self.errors.append(f"Line {line_num}: {message}")

    def add_fixed_issue(self, line_num: int, message: str):
        self.fixed_issues.append(f"Line {line_num}: {message}")
        self.fixed = True


class PythonSyntaxFixer:
    """Class to fix common Python syntax errors in test files"""
    
    def __init__(self):
        self.project_root = self._find_project_root()
        
    def _find_project_root(self) -> str:
        """Find the root directory of the project"""
        current_dir = os.getcwd()
        while current_dir != os.path.dirname(current_dir):  # Stop at the root directory
            if os.path.exists(os.path.join(current_dir, "backend")):
                return os.path.join(current_dir, "backend")
            current_dir = os.path.dirname(current_dir)
        # Fallback to current directory if backend not found
        return os.getcwd()
        
    def find_test_files(self, test_path: str) -> List[str]:
        """Find all Python test files in the given directory"""
        test_dir = os.path.join(self.project_root, test_path)
        test_files = []
        
        for root, _, files in os.walk(test_dir):
            for file in files:
                if file.endswith(".py") and file.startswith("test_"):
                    test_files.append(os.path.join(root, file))
                    
        return test_files
    
    def check_syntax(self, file_path: str) -> Tuple[bool, str]:
        """Check if a file has syntax errors"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            ast.parse(content)
            return True, ""
        except SyntaxError as e:
            return False, f"Line {e.lineno}, col {e.offset}: {e.msg}"
        except Exception as e:
            return False, str(e)
    
    def fix_syntax_errors(self, file_path: str) -> SyntaxFixResult:
        """Attempt to fix common syntax errors in a file"""
        result = SyntaxFixResult()
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            fixed_lines = []
            line_num = 0
            
            # Process each line
            while line_num < len(lines):
                line = lines[line_num]
                next_line = lines[line_num + 1] if line_num + 1 < len(lines) else ""
                
                # Fix 1: Missing colon after function/class declaration
                if self._is_missing_colon(line):
                    fixed_line = line.rstrip() + ":\n"
                    fixed_lines.append(fixed_line)
                    result.add_fixed_issue(line_num + 1, "Added missing colon after declaration")
                
                # Fix 2: Missing indentation after function/class declaration
                elif (line.strip().endswith(":") and 
                      next_line and
                      not next_line.startswith(" ") and
                      not next_line.strip().startswith("#") and
                      not next_line.strip() == ""):
                    fixed_lines.append(line)
                    if line_num + 1 < len(lines):
                        fixed_lines.append("    " + next_line)
                        result.add_fixed_issue(line_num + 2, "Fixed missing indentation")
                        line_num += 1  # Skip the next line since we've handled it
                
                # Fix 3: Check for unindented docstring after class/function declaration
                elif (line.strip().endswith(":") and 
                      next_line and
                      (next_line.strip().startswith('"""') or next_line.strip().startswith("'''"))) and \
                      not next_line.startswith(" "):
                    fixed_lines.append(line)
                    if line_num + 1 < len(lines):
                        fixed_lines.append("    " + next_line)
                        result.add_fixed_issue(line_num + 2, "Fixed docstring indentation")
                        line_num += 1  # Skip the next line since we've handled it
                
                # No fixes needed for this line
                else:
                    fixed_lines.append(line)
                
                line_num += 1
            
            # If we made any fixes, write the changes back to the file
            if result.fixed:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.writelines(fixed_lines)
                
                # Check if our fixes resolved the syntax errors
                is_valid, error = self.check_syntax(file_path)
                if not is_valid:
                    result.add_error(0, f"Failed to fix syntax errors. Remaining error: {error}")
            
        except Exception as e:
            result.add_error(0, f"Error fixing file: {str(e)}")
            
        return result
    
    def _is_missing_colon(self, line: str) -> bool:
        """Check if a line is a function or class declaration missing a colon"""
        # Ignore lines that already have a colon
        if ":" in line:
            return False
        
        # Check if it's a function or class declaration
        is_func_def = FUNCTION_DEF_PATTERN.match(line) is not None
        is_class_def = CLASS_DEF_PATTERN.match(line) is not None
        
        # Look for fixtures followed by function definitions
        prev_fixture = FIXTURE_PATTERN.match(line) is not None
        
        return (is_func_def or is_class_def) and not prev_fixture and line.strip() != ""
    
    def repair_all_test_files(self, test_path: str) -> Dict[str, int]:
        """Attempt to repair all test files in the given directory"""
        test_files = self.find_test_files(test_path)
        logger.info(f"Found {len(test_files)} test files")
        
        results = {
            "total": len(test_files),
            "checked": 0,
            "with_errors": 0,
            "fixed": 0,
            "failed": 0,
            "skipped": 0
        }
        
        files_with_errors = []
        
        # First, identify files with syntax errors
        for file_path in test_files:
            results["checked"] += 1
            is_valid, error = self.check_syntax(file_path)
            
            if not is_valid:
                rel_path = os.path.relpath(file_path, self.project_root)
                files_with_errors.append((file_path, error))
                results["with_errors"] += 1
                
        logger.info(f"Found {len(files_with_errors)} files with syntax errors")
        
        # Now attempt to fix the files with errors
        for file_path, error in files_with_errors:
            rel_path = os.path.relpath(file_path, self.project_root)
            logger.info(f"Attempting to fix {rel_path}")
            
            fix_result = self.fix_syntax_errors(file_path)
            
            if fix_result.fixed:
                is_valid, remaining_error = self.check_syntax(file_path)
                if is_valid:
                    logger.info(f"Successfully fixed {rel_path}")
                    for fix in fix_result.fixed_issues:
                        logger.info(f"  {fix}")
                    results["fixed"] += 1
                else:
                    logger.warning(f"Partially fixed {rel_path}, but still has errors: {remaining_error}")
                    results["failed"] += 1
            else:
                logger.warning(f"Could not fix {rel_path}: {error}")
                results["failed"] += 1
        
        return results


def main():
    """Main function to run the script"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Fix common syntax errors in test files")
    parser.add_argument("--test-path", default=DEFAULT_TEST_PATH, help="Path to the test directory (relative to project root)")
    args = parser.parse_args()
    
    fixer = PythonSyntaxFixer()
    results = fixer.repair_all_test_files(args.test_path)
    
    logger.info("\nRepair Summary:")
    logger.info(f"  Total test files: {results['total']}")
    logger.info(f"  Files with errors: {results['with_errors']}")
    logger.info(f"  Successfully fixed: {results['fixed']}")
    logger.info(f"  Failed to fix: {results['failed']}")
    
    # Return a non-zero exit code if we failed to fix any files
    if results['failed'] > 0:
        logger.warning("Some files still need manual fixes. See above for details.")
        sys.exit(1)
    else:
        logger.info("All fixable files were successfully repaired.")
        sys.exit(0)


if __name__ == "__main__":
    main()