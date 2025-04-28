#!/usr/bin/env python
"""
Advanced script to fix complex syntax errors in Python test files.
This script focuses on fixing unmatched parentheses, brackets, and other
specific syntax issues that the basic fixer couldn't handle.
"""

import os
import re
import sys
from pathlib import Path


def fix_unmatched_parentheses(content):
    """Fix unmatched parentheses in the file content."""
    lines = content.split('\n')
    fixed_lines = []
    
    # Count opening and closing parentheses in each line
    for i, line in enumerate(lines):
        open_count = line.count('(')
        close_count = line.count(')')
        
        # If there are more opening than closing parentheses
        if open_count > close_count:
            # Add missing closing parentheses
            line += ')' * (open_count - close_count)
        
        # If there are more closing than opening parentheses
        elif close_count > open_count:
            # Remove extra closing parentheses
            for _ in range(close_count - open_count):
                line = line.rstrip(')')
        
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)


def fix_unmatched_brackets(content):
    """Fix unmatched brackets in the file content."""
    lines = content.split('\n')
    fixed_lines = []
    
    # Count opening and closing brackets in each line
    for i, line in enumerate(lines):
        open_count = line.count('[')
        close_count = line.count(']')
        
        # If there are more opening than closing brackets
        if open_count > close_count:
            # Add missing closing brackets
            line += ']' * (open_count - close_count)
        
        # If there are more closing than opening brackets
        elif close_count > open_count:
            # Remove extra closing brackets
            for _ in range(close_count - open_count):
                line = line.rstrip(']')
        
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)


def fix_indentation_issues(content):
    """Fix indentation issues in the file content."""
    lines = content.split('\n')
    fixed_lines = []
    
    # Track indentation levels
    indent_stack = [0]  # Start with no indentation
    
    for i, line in enumerate(lines):
        # Skip empty lines
        if not line.strip():
            fixed_lines.append(line)
            continue
        
        # Calculate current indentation
        stripped = line.lstrip()
        current_indent = len(line) - len(stripped)
        
        # Check if this line starts a new block
        if stripped.endswith(':'):
            fixed_lines.append(line)
            # Next line should be indented by 4 spaces more
            indent_stack.append(current_indent + 4)
            continue
        
        # Check if this line ends a block
        if i > 0 and current_indent < indent_stack[-1]:
            # Pop indentation levels until we find a match or reach the base level
            while len(indent_stack) > 1 and current_indent < indent_stack[-1]:
                indent_stack.pop()
        
        # Adjust indentation if needed
        if current_indent != indent_stack[-1] and stripped:
            # Only adjust non-empty lines
            line = ' ' * indent_stack[-1] + stripped
        
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)


def fix_return_outside_function(content):
    """Fix 'return' statements outside of functions."""
    lines = content.split('\n')
    fixed_lines = []
    in_function = False
    in_fixture = False
    
    for i, line in enumerate(lines):
        stripped = line.strip()
        
        # Check if we're entering a function or fixture
        if re.match(r'^\s*def\s+\w+', line):
            in_function = True
            fixed_lines.append(line)
        elif re.match(r'^\s*@pytest\.fixture', line):
            in_fixture = True
            fixed_lines.append(line)
        # Check for return outside function
        elif stripped.startswith('return ') and not in_function:
            if in_fixture:
                # In a fixture, but outside a function, create a proper function
                indent = len(line) - len(stripped)
                if i > 0 and 'fixture' in lines[i-1]:
                    # Add function definition
                    fixed_lines.append(' ' * indent + 'def _fixture_func():')
                    fixed_lines.append(' ' * (indent + 4) + stripped)
                    fixed_lines.append(' ' * indent + 'return _fixture_func()')
                else:
                    # Just comment it out
                    fixed_lines.append('# ' + line)
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
        
        # Check if we're exiting a fixture
        if in_fixture and not stripped and i < len(lines) - 1:
            next_line = lines[i+1].strip()
            if next_line and not next_line.startswith(('def', 'class', '@', ' ')):
                in_fixture = False
    
    return '\n'.join(fixed_lines)


def fix_file(file_path):
    """Fix syntax issues in a single file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        
        # Apply fixes
        fixed_content = content
        fixed_content = fix_unmatched_parentheses(fixed_content)
        fixed_content = fix_unmatched_brackets(fixed_content)
        fixed_content = fix_indentation_issues(fixed_content)
        fixed_content = fix_return_outside_function(fixed_content)
        
        # Write back if changes were made
        if fixed_content != content:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(fixed_content)
            return True
        
        return False
    except Exception as e:
        print(f"Error fixing {file_path}: {str(e)}")
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
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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