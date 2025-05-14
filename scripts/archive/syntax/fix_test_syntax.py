#!/usr/bin/env python3
"""
Test Syntax Repair Tool for NovaMind Digital Twin Backend

This script identifies and fixes common syntax errors in test files:
1. Indentation issues in docstrings
2. Missing/extra parentheses in method and patch calls 
3. Indentation problems in test methods and classes
4. Missing colons after method definitions

Usage:
  python fix_test_syntax.py [--file FILE_PATH] [--verbose]
"""

import os
import re
import ast
import sys
import argparse
import logging
from typing import List, Dict, Optional, Tuple, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Root project directory
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
TESTS_DIR = os.path.join(PROJECT_ROOT, "app/tests")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Fix syntax errors in test files")
    parser.add_argument("--file", help="Path to a specific file to fix")
    parser.add_argument("--dir", default=TESTS_DIR, help="Directory containing test files to fix")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--check-only", action="store_true", help="Only check for errors, don't fix them")
    return parser.parse_args()


def find_test_files(base_dir: str) -> List[str]:
    """Find all Python test files."""
    test_files = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.py'):
                test_files.append(os.path.join(root, file))
    logger.info(f"Found {len(test_files)} Python files in {base_dir}")
    return test_files


def check_syntax(file_path: str) -> Optional[Tuple[int, int, str]]:
    """Check if a file has syntax errors and return error details if found."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        ast.parse(content)
        return None
    except SyntaxError as e:
        return (e.lineno, e.offset, str(e))
    except Exception as e:
        return (0, 0, str(e))


def fix_docstring_indentation(content: str) -> str:
    """Fix indentation of docstrings in Python files."""
    # Pattern 1: Class docstring not indented
    # class ClassName:
    # """Docstring."""
    content = re.sub(
        r'(class\s+\w+(?:\([^)]*\))?:)\s*\n(\s*)?"""',
        r'\1\n\2    """',
        content
    )
    
    # Pattern 2: Function/method docstring not indented
    # def function_name():
    # """Docstring."""
    content = re.sub(
        r'(def\s+\w+\([^)]*\):)\s*\n(\s*)?"""',
        r'\1\n\2    """',
        content
    )
    
    # Pattern 3: Fixture docstring not indented
    # @pytest.fixture
    # def fixture_name():
    # """Docstring."""
    content = re.sub(
        r'(@pytest\.fixture(?:\([^)]*\))?\s*\n\s*def\s+\w+\([^)]*\):)\s*\n(\s*)?"""',
        r'\1\n\2    """',
        content
    )
    
    return content


def fix_parentheses_issues(content: str) -> str:
    """Fix common parentheses issues in patch calls and other code."""
    # Fix missing closing parenthesis in patch calls
    content = re.sub(
        r'(with\s+patch\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*[^)]+)(\s*\n)',
        r'\1)\2',
        content
    )
    
    # Fix extra closing parenthesis at the end of a line
    content = re.sub(
        r'(\)\s*\))\)(\s*:)',
        r'\1\2',
        content
    )
    
    # Fix patch.object with missing closing parenthesis
    content = re.sub(
        r'(with\s+patch\.object\s*\([^)]+)(\s*\n)',
        r'\1)\2',
        content
    )
    
    # Fix patch with missing return_value parameter parenthesis
    content = re.sub(
        r'(return_value\s*=\s*[^,)]+)(\s*\))',
        r'\1)\2',
        content
    )
    
    # Fix side_effect with missing parenthesis
    content = re.sub(
        r'(side_effect\s*=\s*[^,)]+)(\s*\))',
        r'\1)\2',
        content
    )
    
    return content


def fix_indentation_issues(content: str) -> str:
    """Fix common indentation issues in test files."""
    lines = content.split('\n')
    fixed_lines = []
    in_class = False
    in_method = False
    class_indent = ""
    method_indent = ""
    expected_indent = ""
    
    for i, line in enumerate(lines):
        if re.match(r'^\s*class\s+\w+', line):
            in_class = True
            in_method = False
            class_indent = re.match(r'^(\s*)', line).group(1)
            expected_indent = class_indent + "    "
            fixed_lines.append(line)
        elif in_class and re.match(r'^\s*def\s+\w+', line):
            in_method = True
            method_match = re.match(r'^(\s*)', line)
            method_indent = method_match.group(1) if method_match else expected_indent
            
            # Fix method indentation if needed
            if method_indent != expected_indent:
                line = expected_indent + line.lstrip()
                method_indent = expected_indent
            
            expected_indent = method_indent + "    "
            fixed_lines.append(line)
        elif in_method and line.strip() and not line.strip().startswith(('#', '@', 'class', 'def')):
            indent_match = re.match(r'^(\s*)', line)
            current_indent = indent_match.group(1) if indent_match else ""
            
            # Check if indentation is correct
            if current_indent != expected_indent and line.strip():
                line = expected_indent + line.lstrip()
            
            fixed_lines.append(line)
        else:
            fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)


def fix_missing_colons(content: str) -> str:
    """Fix missing colons after method definitions."""
    # Find method definitions without colons
    pattern = r'(def\s+\w+\([^)]*\))\s*\n'
    return re.sub(pattern, r'\1:\n', content)


def fix_file(file_path: str, verbose: bool = False) -> bool:
    """Fix syntax errors in a specific file by addressing common issues."""
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        # Get error info before fixing
        original_error = check_syntax(file_path)
        if original_error:
            lineno, offset, msg = original_error
            if verbose:
                logger.info(f"Found syntax error in {file_path} at line {lineno}, col {offset}: {msg}")
        else:
            if verbose:
                logger.info(f"No syntax errors found in {file_path}")
            return True
        
        # Read file content
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        # Apply fixes in sequence
        content = original_content
        content = fix_docstring_indentation(content)
        content = fix_parentheses_issues(content)
        content = fix_indentation_issues(content)
        content = fix_missing_colons(content)
        
        # Only write changes if something was modified
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Check if syntax errors were fixed
            new_error = check_syntax(file_path)
            if new_error is None:
                logger.info(f"✅ Successfully fixed {file_path}")
                return True
            else:
                lineno, offset, msg = new_error
                logger.warning(f"⚠️ Applied fixes to {file_path}, but errors remain at line {lineno}, col {offset}: {msg}")
                return False
        else:
            if verbose:
                logger.info(f"No changes needed for {file_path}")
            return False
    
    except Exception as e:
        logger.error(f"Error processing {file_path}: {e}")
        return False


def check_files_with_errors(files: List[str]) -> Dict[str, Tuple[int, int, str]]:
    """Check all files and return those with syntax errors."""
    files_with_errors = {}
    
    for file_path in files:
        error = check_syntax(file_path)
        if error:
            files_with_errors[file_path] = error
    
    return files_with_errors


def categorize_errors(files_with_errors: Dict[str, Tuple[int, int, str]]) -> Dict[str, Set[str]]:
    """Categorize errors by type."""
    error_categories = {
        "missing_colon": set(),
        "indentation": set(),
        "parentheses": set(),
        "other": set()
    }
    
    for file_path, (_, _, error_msg) in files_with_errors.items():
        if "expected ':'" in error_msg:
            error_categories["missing_colon"].add(file_path)
        elif "indentation" in error_msg.lower() or "unindent" in error_msg.lower() or "indent" in error_msg.lower():
            error_categories["indentation"].add(file_path)
        elif "parenthesis" in error_msg.lower() or "parentheses" in error_msg.lower() or ")" in error_msg or "(" in error_msg:
            error_categories["parentheses"].add(file_path)
        else:
            error_categories["other"].add(file_path)
    
    return error_categories


def main():
    """Main function to fix syntax errors in test files."""
    args = parse_args()
    
    if args.file:
        # Fix a specific file
        files_to_check = [args.file]
    else:
        # Find all test files
        all_files = find_test_files(args.dir)
        
        # Check which files have syntax errors
        files_with_errors = check_files_with_errors(all_files)
        files_to_check = list(files_with_errors.keys())
        
        # Categorize errors
        error_categories = categorize_errors(files_with_errors)
        
        logger.info(f"Found {len(files_to_check)} files with syntax errors")
        for category, files in error_categories.items():
            if files:
                logger.info(f"  {category}: {len(files)} files")
    
    if args.check_only:
        return 0
    
    # Fix each file
    fixed_count = 0
    for file_path in files_to_check:
        if fix_file(file_path, args.verbose):
            fixed_count += 1
    
    # Print summary
    logger.info(f"\nRepair Summary:")
    logger.info(f"  Files with errors: {len(files_to_check)}")
    logger.info(f"  Files fixed: {fixed_count}")
    logger.info(f"  Files with remaining errors: {len(files_to_check) - fixed_count}")
    
    if fixed_count < len(files_to_check):
        logger.info("\nFiles still needing manual fixes:")
        for file_path in files_to_check:
            error = check_syntax(file_path)
            if error:
                lineno, offset, msg = error
                logger.info(f"  {file_path} (line {lineno}, col {offset}: {msg})")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())