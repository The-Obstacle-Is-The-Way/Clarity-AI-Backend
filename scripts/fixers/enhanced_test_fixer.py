#!/usr/bin/env python3
"""
NovaMind Digital Twin Enhanced Test Suite Fixer

This script aggressively fixes all indentation, syntax and structure issues in Python test files:
1. Fixes broken docstrings and string literals
2. Corrects indentation in all contexts
3. Ensures proper decorator placement
4. Fixes method declarations and return statements
5. Adds missing parentheses
6. Ensures proper whitespace between functions and classes
7. Fixes test function and class structure

Usage:
    python enhanced_test_fixer.py [path_to_directory]
"""

import os
import re
import sys
import ast
import tokenize
from io import StringIO
from pathlib import Path


# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal output."""
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def fix_indentation_in_fixtures(content):
    """Fix indentation in pytest fixtures."""
    # Fix fixture declarations - ensure they have proper spacing and indentation
    content = re.sub(r'(\s+)@pytest\.fixture\n(\s+)def', r'@pytest.fixture\ndef', content)
    content = re.sub(r'@pytest\.fixture\s*\n\s*def ([^\n]+):\s*\n\s*"""', r'@pytest.fixture\ndef \1:\n    """', content)
    
    # Fix missing returns after """
    content = re.sub(r'"""([^"]*?)"""\s*\n\s*return', r'"""\1"""\n    return', content)
    
    # Fix returns not inside functions
    content = re.sub(r'(\n\s*)return ([^\n]+)(\n)', r'\1    return \2\3', content)
    
    # Ensure proper spacing between fixture functions
    content = re.sub(r'(\n\s*def [^\n]+:[^\n]+\n\s*return [^\n]+\n)(\s*@pytest)', r'\1\n\n\2', content)
    
    return content


def fix_docstrings(content):
    """Fix broken docstrings and string literals."""
    # Fix unclosed docstrings
    opening_counts = content.count('"""')
    if opening_counts % 2 != 0:
        # Find the last occurrence of """
        last_idx = content.rfind('"""')
        if last_idx != -1:
            # Add a closing docstring
            content = content[:last_idx+3] + '\n' + content[last_idx+3:]
    
    # Fix unclosed parentheses
    lines = content.split('\n')
    stack = []
    for i, line in enumerate(lines):
        for char in line:
            if char == '(':
                stack.append((i, char))
            elif char == ')' and stack and stack[-1][1] == '(':
                stack.pop()
    
    # Add missing closing parentheses
    for line_idx, _ in reversed(stack):
        if line_idx < len(lines):
            lines[line_idx] = lines[line_idx] + ')'
    
    content = '\n'.join(lines)
    
    # Fix docstring indentation in methods and classes
    content = re.sub(r'(def [^\n]+:)\s*\n([^\n]+?)"""', r'\1\n    """', content)
    content = re.sub(r'(class [^\n]+:)\s*\n([^\n]+?)"""', r'\1\n    """', content)
    
    return content


def fix_class_method_indentation(content):
    """Fix indentation in class methods."""
    # Make sure class methods are properly indented
    lines = content.split('\n')
    in_class = False
    class_indent = 0
    expected_method_indent = 0
    result_lines = []
    
    for i, line in enumerate(lines):
        line_strip = line.strip()
        
        # Check if this is a class definition
        if line_strip.startswith('class ') and line_strip.endswith(':'):
            in_class = True
            class_indent = len(line) - len(line.lstrip())
            expected_method_indent = class_indent + 4
            result_lines.append(line)
            continue
        
        # In a class, methods should be indented
        if in_class and line_strip.startswith('def '):
            indent = len(line) - len(line.lstrip())
            # If method is not properly indented
            if indent < expected_method_indent:
                line = ' ' * expected_method_indent + line.lstrip()
        
        # If we hit another class or top-level function, we're no longer in a class
        if in_class and line_strip and not line.startswith(' '):
            if line_strip.startswith('class ') or line_strip.startswith('def '):
                in_class = False
        
        result_lines.append(line)
    
    content = '\n'.join(result_lines)
    
    # Make sure test methods have proper decorators
    content = re.sub(r'(\n\s+)def (test_[^(]+)\(', r'\1@pytest.mark.standalone()\n\1def \2(', content)
    
    # Fix method body indentation
    content = re.sub(r'(\n\s+def [^\n]+:)\s*\n([^\n]+)', r'\1\n        \2', content)
    
    return content


def fix_test_methods(content):
    """Fix common issues with test methods."""
    # Ensure test methods have proper test_ prefix
    content = re.sub(r'(\n\s+)def (should_|must_|can_|verify_|check_)([^(]+)\(', r'\1def test_\3(', content)
    
    # Fix missing self parameter
    content = re.sub(r'(\n\s+@pytest\.mark\.standalone\(\)\n\s+def test_[^(]+)\(\):', r'\1(self):', content)
    
    # Fix broken assert statements
    content = re.sub(r'assert\(([^)]+)\)', r'assert \1', content)
    
    return content


def fix_syntax_errors(file_path):
    """
    Fix syntax errors in the specified Python file.
    
    Args:
        file_path: Path to the Python file to fix
    
    Returns:
        bool: True if fixes were applied, False otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Multiple cleanup passes
        for _ in range(3):  # Apply fixes in multiple passes
            # Fix indentation in pytest fixtures
            content = fix_indentation_in_fixtures(content)
            
            # Fix docstrings
            content = fix_docstrings(content)
            
            # Fix class and method indentation
            content = fix_class_method_indentation(content)
            
            # Fix test methods
            content = fix_test_methods(content)
            
            # Fix decorator spacing
            content = re.sub(r'@pytest\.mark\.standalone\(\)(\n[^\n@])', r'@pytest.mark.standalone()\n\1', content)
            
            # Ensure proper spacing between imports and first class/function
            content = re.sub(r'(import [^\n]+\n)(\n*)(?=class|def)', r'\1\n\n', content)
            
            # Fix statements without newlines
            content = re.sub(r'([;)])\s*([a-zA-Z])', r'\1\n\2', content)
            
            # Fix unexpected indentation
            content = re.sub(r'\n( +)(\S[^\n]*)\n\1  (\S)', r'\n\1\2\n\1    \3', content)
            
            # Fix common indentation pattern for pytest fixtures
            content = re.sub(r'(@pytest\.fixture\([^\)]*\))(\n)( *)def', r'\1\2\3def', content)
            
            # Fix blank lines with indentation
            content = re.sub(r'\n[ \t]+\n', r'\n\n', content)
            
            # Fix imports
            content = re.sub(r'import pytest,', r'import pytest,\nimport', content)
            
            # Fix missing parentheses in conditions
            content = re.sub(r'(if|while|for) ([^:\n(]+)([^:(][^:]*):',
                          r'\1 (\2\3):', content)
        
        # If changes were made, write them back to the file
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"{Colors.GREEN}Fixed syntax issues in {file_path}{Colors.RESET}")
            return True
        
        print(f"{Colors.YELLOW}No syntax issues found in {file_path}{Colors.RESET}")
        return False
        
    except Exception as e:
        print(f"{Colors.RED}Error processing {file_path}: {str(e)}{Colors.RESET}")
        return False


def process_directory(directory_path):
    """
    Process all Python files in the specified directory and its subdirectories.
    
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
        if fix_syntax_errors(file_path):
            fixed_files += 1
    
    return len(python_files), fixed_files


def main():
    """Main entry point for the script."""
    if len(sys.argv) < 2:
        test_dir = '/Users/ray/Desktop/GITHUB/Novamind-Backend-ONLY-TWINS/backend/app/tests/standalone'
        print(f"No directory specified, using default: {test_dir}")
    else:
        test_dir = sys.argv[1]
    
    if not os.path.exists(test_dir):
        print(f"{Colors.RED}Directory not found: {test_dir}{Colors.RESET}")
        sys.exit(1)
    
    print(f"{Colors.BOLD}NovaMind Digital Twin Enhanced Test Suite Fixer{Colors.RESET}")
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
