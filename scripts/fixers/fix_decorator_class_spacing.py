#!/usr/bin/env python3
"""
Fix common decorator-class spacing issues in Python files.
This script specifically fixes:
1. Missing space between decorator and class: @pytest.mark.db_required()class TestClass
2. Missing space between import and class: import foo class TestClass

Following clean architecture principles to solve issues systematically rather than ad-hoc fixes.
"""

import os
import re
import sys
from pathlib import Path


def fix_decorator_class_spacing(file_path):
    """Fix decorator-class spacing issues in Python files."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Fix decorator-class spacing
        content = re.sub(r'(\@[a-zA-Z0-9_.]+[^(\n]*\([^)]*\))class', r'\1\nclass', content)
        
        # Fix import-class spacing
        content = re.sub(r'(from|import)([^\n]*)class', r'\1\2\nclass', content)
        
        # Fix closing parentheses with class
        content = re.sub(r'(\))class', r'\1\nclass', content)
        
        # Write back to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
        return True
    except Exception as e:
        print(f"Error fixing {file_path}: {e}")
        return False


def find_python_files(directory):
    """Recursively find all Python files in a directory."""
    py_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                py_files.append(os.path.join(root, file))
    return py_files


def main():
    """Main function to fix Python files in a directory."""
    if len(sys.argv) < 2:
        print("Usage: python fix_decorator_class_spacing.py <directory>")
        return
        
    directory = sys.argv[1]
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory")
        return
        
    py_files = find_python_files(directory)
    print(f"Found {len(py_files)} Python files to process")
    
    success_count = 0
    for file_path in py_files:
        if fix_decorator_class_spacing(file_path):
            success_count += 1
            print(f"Fixed: {file_path}")
    
    print(f"Successfully fixed {success_count} out of {len(py_files)} files")
    print("Now run the original fix_indentation.py script and then Black")


if __name__ == "__main__":
    main()
