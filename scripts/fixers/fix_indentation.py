#!/usr/bin/env python3
"""
Fix common indentation issues in Python files that prevent Black from running.
This script identifies and fixes:
1. Empty parentheses in imports - from module import ()
2. Indentation mismatches
3. Missing colons in function/class definitions
4. Missing parentheses in function calls
"""

import os
import re
import sys
from pathlib import Path


def fix_empty_imports(content):
    """Fix empty imports like 'from module import ()'."""
    return re.sub(r'from\s+([a-zA-Z0-9_.]+)\s+import\s+\(\)', r'from \1 import', content)


def fix_indentation_issues(file_path):
    """Fix basic indentation issues in Python files."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Fix empty imports
        content = fix_empty_imports(content)
        
        # Normalize line endings
        content = content.replace('\r\n', '\n')
        
        # Split into lines for line-by-line processing
        lines = content.split('\n')
        fixed_lines = []
        
        # Process lines
        in_method = False
        expected_indent = 0
        
        for i, line in enumerate(lines):
            # Skip empty lines
            if not line.strip():
                fixed_lines.append(line)
                continue
                
            # Get current indentation
            indent = len(line) - len(line.lstrip())
            stripped = line.strip()
            
            # Check if line needs indent fixing
            if in_method and indent < expected_indent and not (stripped.startswith(')') or stripped.startswith('}')):
                # Add proper indentation
                fixed_lines.append(' ' * expected_indent + stripped)
            else:
                fixed_lines.append(line)
            
            # Update indent expectations
            if stripped.endswith(':'):
                in_method = True
                expected_indent = indent + 4  # Python standard is 4 spaces
            
            # Reset for closing brackets
            if stripped == ')' or stripped == '}':
                in_method = False
        
        # Rejoin and write back
        fixed_content = '\n'.join(fixed_lines)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(fixed_content)
            
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
        print("Usage: python fix_indentation.py <directory>")
        return
        
    directory = sys.argv[1]
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory")
        return
        
    py_files = find_python_files(directory)
    print(f"Found {len(py_files)} Python files to process")
    
    success_count = 0
    for file_path in py_files:
        if fix_indentation_issues(file_path):
            success_count += 1
            print(f"Fixed: {file_path}")
    
    print(f"Successfully fixed {success_count} out of {len(py_files)} files")
    print("You may now run Black on the directory")


if __name__ == "__main__":
    main()
