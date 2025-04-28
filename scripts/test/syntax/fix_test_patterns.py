#!/usr/bin/env python3
"""
Test Pattern Syntax Fixer for NovaMind Digital Twin Backend

This script focuses on fixing specific common syntax patterns in test files that are
frequently causing issues. It targets test-specific patterns like patch() calls,
fixture decorators, test assertions, and more.

Usage:
  python fix_test_patterns.py [--file FILE_PATH] [--verbose]
"""

import os
import re
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
    parser = argparse.ArgumentParser(description="Fix specific syntax patterns in test files")
    parser.add_argument("--file", help="Path to a specific file to fix")
    parser.add_argument("--dir", default=TESTS_DIR, help="Directory containing test files to fix")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without applying them")
    return parser.parse_args()


def find_test_files(base_dir: str) -> List[str]:
    """Find all Python test files."""
    test_files = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.py') and ('test_' in file or file.startswith('test')):
                test_files.append(os.path.join(root, file))
    logger.info(f"Found {len(test_files)} test files in {base_dir}")
    return test_files


def fix_patch_statements(content: str) -> str:
    """Fix common issues in unittest.mock patch statements."""
    # Fix missing comma after the target string in patch calls
    content = re.sub(
        r'(with\s+patch\s*\(\s*[\'"][\w\.]+[\'"])\s+(\w+)',
        r'\1, \2',
        content
    )
    
    # Fix missing parenthesis in patch.object calls
    content = re.sub(
        r'(with\s+patch\.object\s*\([^,\n]+,\s*[^\n\)]+)\s*\n',
        r'\1)\n',
        content
    )
    
    # Fix missing closing parenthesis in patch calls with return_value
    content = re.sub(
        r'(with\s+patch\s*\([^)]*return_value\s*=[^)]*\s*)\n',
        r'\1)\n',
        content
    )
    
    # Fix missing equal sign in return_value assignments
    content = re.sub(
        r'(return_value)\s+([^=,\s][^,\)]*)',
        r'\1=\2',
        content
    )
    
    # Fix missing equal sign in side_effect assignments
    content = re.sub(
        r'(side_effect)\s+([^=,\s][^,\)]*)',
        r'\1=\2',
        content
    )
    
    # Fix missing comma between patch target and attributes
    content = re.sub(
        r'(patch\s*\(\s*[\'"]\w+(?:\.\w+)*[\'"]\s*)(\w+\s*=)',
        r'\1, \2',
        content
    )
    
    return content


def fix_fixture_decorators(content: str) -> str:
    """Fix common issues in pytest fixture decorators."""
    # Fix missing parentheses in fixture decorators
    content = re.sub(
        r'@pytest\.fixture\s+\n',
        r'@pytest.fixture()\n',
        content
    )
    
    # Fix missing comma in fixture parameters
    content = re.sub(
        r'(@pytest\.fixture\([^\)]*scope\s*=\s*[\'"][^\'"]+[\'"]\s*)(\w+\s*=)',
        r'\1, \2',
        content
    )
    
    # Fix missing colon in fixture function definitions
    content = re.sub(
        r'(@pytest\.fixture(?:\([^\)]*\))?\s*\n\s*def\s+\w+\([^\)]*\))\s*\n',
        r'\1:\n',
        content
    )
    
    return content


def fix_class_method_definitions(content: str) -> str:
    """Fix common issues in class and method definitions."""
    # Fix missing colon after class definition
    content = re.sub(
        r'(class\s+\w+(?:\([^\)]*\))?)\s*\n',
        r'\1:\n',
        content
    )
    
    # Fix missing colon after method definition
    content = re.sub(
        r'(def\s+\w+\([^\)]*\))\s*\n',
        r'\1:\n',
        content
    )
    
    # Fix missing self parameter in class methods
    content = re.sub(
        r'(class\s+\w+(?:\([^\)]*\))?:\s*\n(?:\s*"""[^"]*""")?\s*\n\s*def\s+)(\w+\(\s*\))',
        r'\1\2self)',
        content
    )
    
    # Fix incorrect indentation in class methods
    lines = content.split('\n')
    in_class = False
    class_indent = ""
    corrected_lines = []
    
    for i, line in enumerate(lines):
        if re.match(r'^\s*class\s+\w+', line):
            in_class = True
            class_indent = re.match(r'^(\s*)', line).group(1)
            corrected_lines.append(line)
        elif in_class and re.match(r'^\s*def\s+\w+', line):
            current_indent = re.match(r'^(\s*)', line).group(1)
            expected_indent = class_indent + "    "
            if current_indent != expected_indent:
                corrected_lines.append(expected_indent + line.lstrip())
            else:
                corrected_lines.append(line)
        else:
            corrected_lines.append(line)
    
    return '\n'.join(corrected_lines)


def fix_assert_statements(content: str) -> str:
    """Fix common issues in test assertions."""
    # Fix missing operator in equality assertions
    content = re.sub(
        r'(assert\s+[\w\.]+\s*)([!=]=\s*)',
        r'\1 \2 ',
        content
    )
    
    # Fix missing space after assert keyword
    content = re.sub(
        r'(assert)(\w+)',
        r'\1 \2',
        content
    )
    
    return content


def fix_pytest_mark_decorators(content: str) -> str:
    """Fix common issues in pytest mark decorators."""
    # Fix missing parentheses in pytest.mark decorators
    content = re.sub(
        r'@pytest\.mark\.(\w+)\s*\n',
        r'@pytest.mark.\1()\n',
        content
    )
    
    # Fix missing commas in pytest.mark parameters
    content = re.sub(
        r'(@pytest\.mark\.\w+\([^\)]*\w+\s*=\s*[\'"][^\'"]+[\'"]\s*)(\w+\s*=)',
        r'\1, \2',
        content
    )
    
    return content


def fix_common_import_issues(content: str) -> str:
    """Fix common issues in import statements."""
    # Fix missing commas in multi-import statements
    content = re.sub(
        r'(from\s+[\w\.]+\s+import\s+\w+\s+)(\w+)',
        r'\1, \2',
        content
    )
    
    return content


def apply_all_fixes(content: str) -> str:
    """Apply all fixes to the content."""
    content = fix_patch_statements(content)
    content = fix_fixture_decorators(content)
    content = fix_class_method_definitions(content)
    content = fix_assert_statements(content)
    content = fix_pytest_mark_decorators(content)
    content = fix_common_import_issues(content)
    return content


def fix_file(file_path: str, verbose: bool = False, dry_run: bool = False) -> bool:
    """Fix syntax issues in a specific file."""
    try:
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        fixed_content = apply_all_fixes(original_content)
        
        if fixed_content != original_content:
            if verbose:
                logger.info(f"Found fixable issues in {file_path}")
            
            if not dry_run:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(fixed_content)
                logger.info(f"✅ Fixed issues in {file_path}")
            else:
                logger.info(f"Would fix issues in {file_path} (dry run)")
            
            return True
        else:
            if verbose:
                logger.info(f"No fixable issues found in {file_path}")
            return False
    
    except Exception as e:
        logger.error(f"Error processing {file_path}: {e}")
        return False


def main():
    """Main function to fix syntax issues in test files."""
    args = parse_args()
    
    if args.file:
        # Fix a specific file
        files_to_fix = [args.file]
    else:
        # Find all test files
        files_to_fix = find_test_files(args.dir)
    
    # Fix each file
    fixed_count = 0
    for file_path in files_to_fix:
        if fix_file(file_path, args.verbose, args.dry_run):
            fixed_count += 1
    
    # Print summary
    mode = "Would fix" if args.dry_run else "Fixed"
    logger.info(f"\n{mode} {fixed_count} out of {len(files_to_fix)} files")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())