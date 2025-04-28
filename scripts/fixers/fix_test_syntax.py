#!/usr/bin/env python
"""
Script to automatically fix common syntax errors in Python test files.
This script focuses on fixing indentation issues, parentheses mismatches,
and other common syntax problems.
"""

import os
import re
import sys
from pathlib import Path


def fix_indentation(content):
    """Fix indentation issues in the file content."""
    lines = content.split('\n')
    fixed_lines = []
    current_indent = 0
    in_class = False
    in_function = False
    
    for line in lines:
        # Skip empty lines
        if not line.strip():
            fixed_lines.append(line)
            continue
        
        # Calculate the current indentation level
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        
        # Check for class or function definition
        if re.match(r'^\s*class\s+\w+', line):
            in_class = True
            current_indent = indent
            fixed_lines.append(line)
        elif re.match(r'^\s*def\s+\w+', line):
            in_function = True
            if in_class:
                # Methods in classes should be indented by 4 spaces
                expected_indent = current_indent + 4
                if indent != expected_indent:
                    line = ' ' * expected_indent + stripped
            fixed_lines.append(line)
        elif re.match(r'^\s*@', line):  # Decorator
            fixed_lines.append(line)
        else:
            # Regular line - try to fix indentation
            if in_function and stripped.startswith(('return', 'assert', 'self.', 'if ', 'else:', 'elif ', 'for ', 'while ')):
                if in_class:
                    expected_indent = current_indent + 8  # Inside a method in a class
                else:
                    expected_indent = current_indent + 4  # Inside a function
                if indent != expected_indent:
                    line = ' ' * expected_indent + stripped
            fixed_lines.append(line)
        
        # Check for end of blocks
        if stripped.endswith(':'):
            current_indent = indent
    
    return '\n'.join(fixed_lines)


def fix_parentheses(content):
    """Fix mismatched parentheses in the file content."""
    # Simple fix for common patterns of unclosed parentheses
    content = re.sub(r'\(\s*$', '()', content)
    content = re.sub(r',\s*$', '', content)
    
    # Fix missing closing parentheses at the end of function calls
    lines = content.split('\n')
    for i in range(len(lines)):
        if re.search(r'\([^)]*$', lines[i]) and i < len(lines) - 1:
            if not re.search(r'[)]', lines[i+1]):
                lines[i] = lines[i] + ')'
    
    return '\n'.join(lines)


def fix_return_outside_function(content):
    """Fix 'return' statements outside of functions."""
    lines = content.split('\n')
    fixed_lines = []
    in_function = False
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # Check if we're entering a function
        if re.match(r'^\s*def\s+\w+', line):
            in_function = True
            fixed_lines.append(line)
        # Check for return outside function
        elif stripped.startswith('return ') and not in_function:
            # Convert to a variable assignment if it's a fixture
            if i > 0 and 'fixture' in lines[i-1]:
                indent = len(line) - len(stripped)
                fixed_lines.append(' ' * indent + 'result = ' + stripped[7:])
                fixed_lines.append(' ' * indent + 'return result')
            else:
                # Just comment it out
                fixed_lines.append('# ' + line)
        else:
            fixed_lines.append(line)
        
        # Check if we're exiting a function
        if in_function and not stripped and i < len(lines) - 1:
            next_line = lines[i+1].strip()
            if next_line and not next_line.startswith(('def', 'class', '@', ' ')):
                in_function = False
    
    return '\n'.join(fixed_lines)


def fix_file(file_path):
    """Fix syntax issues in a single file."""
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Apply fixes
    fixed_content = content
    fixed_content = fix_indentation(fixed_content)
    fixed_content = fix_parentheses(fixed_content)
    fixed_content = fix_return_outside_function(fixed_content)
    
    # Write back if changes were made
    if fixed_content != content:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(fixed_content)
        return True
    
    return False


def find_test_files(directory):
    """Find all Python test files in the given directory."""
    test_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.startswith('test_') and file.endswith('.py'):
                test_files.append(os.path.join(root, file))
    return test_files


def main():
    """Main function to fix syntax errors in test files."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    tests_dir = os.path.join(base_dir, 'app', 'tests')
    
    print(f"Scanning for test files in {tests_dir}...")
    test_files = find_test_files(tests_dir)
    print(f"Found {len(test_files)} test files.")
    
    fixed_count = 0
    for file_path in test_files:
        if fix_file(file_path):
            print(f"Fixed: {file_path}")
            fixed_count += 1
    
    print(f"\nFixed {fixed_count} files.")


if __name__ == "__main__":
    main()