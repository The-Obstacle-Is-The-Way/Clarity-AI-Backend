#!/usr/bin/env python3
"""
NovaMind Digital Twin Test Suite Indentation Fixer

This script automatically fixes common indentation issues in the test suite files:
1. Properly indents fixture definitions
2. Fixes nested test method definitions
3. Corrects misaligned docstrings
4. Handles import syntax errors
5. Ensures consistent spacing between decorators and functions/classes
6. Fixes unindent errors that don't match outer indentation levels

Usage:
    python novamind_test_fixer.py [path_to_directory]
"""

import os
import re
import sys
from pathlib import Path
from typing import List

# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal output."""
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def fix_indentation_issues(file_path: str) -> bool:
    """
    Fix indentation issues in the specified Python file.
    
    Args:
        file_path: Path to the Python file to fix
        
    Returns:
        bool: True if fixes were applied, False otherwise
    """
    print(f"Processing file: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Fix nested fixture declarations - ensure proper indentation of pytest fixtures
        content = re.sub(r'(\s+)@pytest\.fixture\n\s+def', r'@pytest.fixture\ndef', content)
        content = re.sub(r'(\s{4,})@pytest\.fixture', r'\n    @pytest.fixture', content)
        
        # Fix docstring indentation - ensure consistent indentation of docstrings
        content = re.sub(r'def ([^\n]+):\n([^\n]+"""[^\n]+""")', r'def \1:\n    \2', content)
        
        # Fix class member indentation
        content = re.sub(r'(class [^\n]+:)\s+"""', r'\1\n    """', content)
        
        # Fix method indentation in classes
        content = re.sub(r'(\n\s+)@pytest\.mark[^\n]+\n\s+def', r'\1@pytest.mark.standalone()\n\1def', content)
        
        # Fix docstrings that are not properly indented within methods
        content = re.sub(r'def ([^\n]+):\n([^\n]+)"""', r'def \1:\n    """', content)
        
        # Fix incorrect indentation of lines following docstrings
        content = re.sub(r'("""[^\n]+""")(\n)([^\n]+)', r'\1\2        \3', content)
        
        # Fix indentation of code blocks
        lines = content.split('\n')
        fixed_lines = []
        in_function = False
        expected_indent = 0
        
        for i, line in enumerate(lines):
            # Check if we're entering a function or method definition
            if re.match(r'^\s*def\s+', line) and line.rstrip().endswith(':'):
                in_function = True
                indent_match = re.match(r'^(\s*)', line)
                expected_indent = len(indent_match.group(1)) + 4 if indent_match else 4
            
            # Check if this line should be indented within a function
            if in_function and i+1 < len(lines):
                next_line = lines[i+1]
                next_indent_match = re.match(r'^(\s*)', next_line)
                next_indent = len(next_indent_match.group(1)) if next_indent_match else 0
                
                # If next line is not properly indented and not empty and not a decorator
                if (next_indent < expected_indent and next_line.strip() and 
                        not next_line.strip().startswith('@') and 
                        not next_line.strip().startswith('class') and
                        not next_line.strip().startswith('def')):
                    # Fix the indentation of the next line
                    spaces = ' ' * expected_indent
                    lines[i+1] = f"{spaces}{next_line.strip()}"
            
            # Check if we're exiting a function
            if in_function and (line.strip() == '' or 
                                (line.strip() and not line.strip().startswith(' ') and 
                                 not line.strip().startswith('@'))):
                in_function = False
            
            fixed_lines.append(line)
        
        content = '\n'.join(fixed_lines)
        
        # Fix indentation within block structures (if, for, etc.)
        content = re.sub(r'(if [^:]+:)(\n[^\n]+)(?!\s)', r'\1\n    \2', content)
        content = re.sub(r'(for [^:]+:)(\n[^\n]+)(?!\s)', r'\1\n    \2', content)
        content = re.sub(r'(with [^:]+:)(\n[^\n]+)(?!\s)', r'\1\n    \2', content)
        
        # Apply other indentation fixes
        content = re.sub(r'(\n\s+)return (\w+)\((\n\s+)', r'\1return \2(\n\1    ', content)
        
        # Fix spacing between decorators and class definitions
        content = re.sub(r'@pytest\.mark\.standalone\(\)\nclass', r'@pytest.mark.standalone()\n\nclass', content)
        
        # Fix decorator indentation
        content = re.sub(r'(\n)(\s+)@', r'\1\2@', content)
        
        # If changes were made, write them back to the file
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"{Colors.GREEN}Fixed indentation issues in {file_path}{Colors.RESET}")
            return True
        
        print(f"{Colors.YELLOW}No indentation issues found in {file_path}{Colors.RESET}")
        return False
        
    except Exception as e:
        print(f"{Colors.RED}Error processing {file_path}: {str(e)}{Colors.RESET}")
        return False


def process_directory(directory_path: str) -> tuple:
    """
    Process all Python files in the specified directory.
    
    Args:
        directory_path: Path to the directory to process
        
    Returns:
        tuple: (total_files, fixed_files)
    """
    python_files = []
    
    # Find all Python files in the directory
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    
    if not python_files:
        print(f"{Colors.YELLOW}No Python files found in {directory_path}{Colors.RESET}")
        return 0, 0
    
    print(f"Found {len(python_files)} Python files to process")
    
    fixed_files = 0
    for file_path in python_files:
        if fix_indentation_issues(file_path):
            fixed_files += 1
    
    return len(python_files), fixed_files


def main():
    """Main entry point for the script."""
    if len(sys.argv) < 2:
        test_dir = '/Users/ray/Desktop/GITHUB/Novamind-Backend-ONLY-TWINS/backend/app/tests/standalone/core'
        print(f"No directory specified, using default: {test_dir}")
    else:
        test_dir = sys.argv[1]
    
    if not os.path.exists(test_dir):
        print(f"{Colors.RED}Directory not found: {test_dir}{Colors.RESET}")
        sys.exit(1)
    
    print(f"{Colors.BOLD}NovaMind Digital Twin Test Suite Indentation Fixer{Colors.RESET}")
    print(f"Processing directory: {test_dir}\n")
    
    total_files, fixed_files = process_directory(test_dir)
    
    print(f"\n{Colors.BOLD}Summary:{Colors.RESET}")
    print(f"Successfully fixed {fixed_files} out of {total_files} files")
    
    if fixed_files > 0:
        print(f"\n{Colors.YELLOW}You may now run Black on the directory to ensure consistent code style:{Colors.RESET}")
        print(f"  cd /Users/ray/Desktop/GITHUB/Novamind-Backend-ONLY-TWINS/backend && python -m black {test_dir}")
    
    if fixed_files == total_files:
        print(f"\n{Colors.GREEN}All files successfully processed!{Colors.RESET}")
    else:
        print(f"\n{Colors.YELLOW}Some files may still have issues. Check the output for details.{Colors.RESET}")


if __name__ == "__main__":
    main()
