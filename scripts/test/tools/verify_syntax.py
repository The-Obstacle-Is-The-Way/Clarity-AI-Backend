#!/usr/bin/env python3
"""
Syntax checker script to verify Python files' syntax before running tests.
Checks for syntax errors in Python files using Python's built-in compiler.
"""

import os
import sys
import py_compile
import concurrent.futures
from typing import List, Tuple

def check_file_syntax(file_path: str) -> Tuple[str, bool, str]:
    """
    Check a Python file for syntax errors.
    
    Args:
        file_path: Path to the Python file to check
        
    Returns:
        Tuple of (file_path, is_valid, error_message)
    """
    try:
        py_compile.compile(file_path, doraise=True)
        return (file_path, True, "")
    except py_compile.PyCompileError as e:
        error_msg = str(e)
        return (file_path, False, error_msg)
    except Exception as e:
        return (file_path, False, str(e))

def find_python_files(root_dir: str, pattern: str = "_test.py") -> List[str]:
    """
    Find all Python test files in a directory tree.
    
    Args:
        root_dir: Root directory to search
        pattern: File pattern to match (defaults to '_test.py')
        
    Returns:
        List of Python test file paths
    """
    python_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith(".py") and pattern in filename:
                python_files.append(os.path.join(dirpath, filename))
    return python_files

def main():
    """Main entry point."""
    # Determine the project root directory
    if len(sys.argv) > 1:
        root_dir = sys.argv[1]
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # Assuming this script is in backend/scripts/test/tools/
        root_dir = os.path.abspath(os.path.join(script_dir, '../../../'))
    
    print(f"Checking Python test files in {root_dir}")
    
    # Find all Python test files
    test_files = find_python_files(os.path.join(root_dir, 'app/tests'))
    print(f"Found {len(test_files)} test files")
    
    # Check syntax of all files in parallel
    with concurrent.futures.ProcessPoolExecutor() as executor:
        results = list(executor.map(check_file_syntax, test_files))
    
    # Print results
    valid_files = [r[0] for r in results if r[1]]
    invalid_files = [(r[0], r[2]) for r in results if not r[1]]
    
    print(f"\nResults:")
    print(f"  Valid files: {len(valid_files)}")
    print(f"  Invalid files: {len(invalid_files)}")
    
    if invalid_files:
        print("\nFiles with syntax errors:")
        for file_path, error in invalid_files:
            print(f"  {file_path}")
            print(f"    Error: {error}")
        sys.exit(1)
    else:
        print("\nAll files have valid syntax!")
        sys.exit(0)

if __name__ == "__main__":
    main()