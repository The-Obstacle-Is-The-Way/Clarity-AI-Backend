#!/usr/bin/env python
"""
Script to verify syntax of Python test files.
This script attempts to compile each Python file to check for syntax errors.
"""

import os
import sys
import ast
import traceback
from pathlib import Path


def check_file_syntax(file_path):
    """Check a file for syntax errors by attempting to parse it with ast."""
    with open(file_path, 'r', encoding='utf-8') as file:
        try:
            content = file.read()
            ast.parse(content)
            return None
        except SyntaxError as e:
            return {
                'file': file_path,
                'line': e.lineno,
                'col': e.offset,
                'error': str(e)
            }
        except Exception as e:
            return {
                'file': file_path,
                'error': f"Error parsing file: {str(e)}"
            }


def find_test_files(directory):
    """Find all Python test files in the given directory."""
    test_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.startswith('test_') and file.endswith('.py'):
                test_files.append(os.path.join(root, file))
    return test_files


def main():
    """Main function to verify syntax of test files."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tests_dir = os.path.join(base_dir, 'app', 'tests')
    
    print(f"Scanning for test files in {tests_dir}...")
    test_files = find_test_files(tests_dir)
    print(f"Found {len(test_files)} test files.")
    
    errors = []
    for file_path in test_files:
        result = check_file_syntax(file_path)
        if result:
            errors.append(result)
    
    if errors:
        print(f"\nFound {len(errors)} files with syntax errors:")
        for error in errors:
            if 'line' in error:
                print(f"{error['file']} (line {error['line']}, col {error['col']}): {error['error']}")
            else:
                print(f"{error['file']}: {error['error']}")
    else:
        print("\nNo syntax errors found! All test files are syntactically correct.")


if __name__ == "__main__":
    main()