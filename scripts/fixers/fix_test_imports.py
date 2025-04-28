#!/usr/bin/env python3
"""
Script to fix import statements that incorrectly start with a comma.
This script scans Python files in the app/tests directory and fixes the syntax error.
"""

import os
import re
import sys
from pathlib import Path


def fix_imports_in_file(file_path):
    """Fix import statements in a single file that start with a comma."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Pattern to match import statements that start with a comma
    pattern = r',\s*from\s+'
    if re.search(pattern, content):
        print(f"Fixing {file_path}")
        # Replace commas at the start of import statements
        fixed_content = re.sub(pattern, 'from ', content)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
        return True
    return False


def find_and_fix_files(directory):
    """Find all Python files in the directory and fix import statements."""
    fixed_count = 0
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                if fix_imports_in_file(file_path):
                    fixed_count += 1
    
    return fixed_count


if __name__ == "__main__":
    tests_dir = Path('app/tests')
    if not tests_dir.exists():
        print(f"Directory {tests_dir} does not exist")
        sys.exit(1)
    
    print(f"Scanning {tests_dir} for Python files with comma-prefixed imports...")
    fixed_count = find_and_fix_files(tests_dir)
    print(f"Fixed {fixed_count} files")