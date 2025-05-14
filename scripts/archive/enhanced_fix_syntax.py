#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced syntax fix script for Python test files.
This script handles various common syntax errors including missing colons,
indentation issues, and other common formatting problems.
"""

import os
import re
import sys
from pathlib import Path

# Regex patterns to fix
PATTERNS = [
    # Class definition without colon
    (r'^(\s*class\s+\w+(?:\s*\([^)]*\))?\s*)$', r'\1:'),
    
    # Function definition without colon
    (r'^(\s*def\s+\w+\s*\([^)]*\)\s*)$', r'\1:'),
    
    # Async function definition without colon
    (r'^(\s*async\s+def\s+\w+\s*\([^)]*\)\s*)$', r'\1:'),
    
    # With statement without colon
    (r'^(\s*with\s+[^:]+)\s*$', r'\1:'),
    
    # If statement without colon
    (r'^(\s*if\s+[^:]+)\s*$', r'\1:'),
    
    # Else without colon
    (r'^(\s*else\s*)$', r'\1:'),
    
    # Elif without colon
    (r'^(\s*elif\s+[^:]+)\s*$', r'\1:'),
    
    # For loop without colon
    (r'^(\s*for\s+\w+\s+in\s+[^:]+)\s*$', r'\1:'),
    
    # While loop without colon
    (r'^(\s*while\s+[^:]+)\s*$', r'\1:'),
    
    # Try without colon
    (r'^(\s*try\s*)$', r'\1:'),
    
    # Except without colon
    (r'^(\s*except(?:\s+\w+(?:\s+as\s+\w+)?)?\s*)$', r'\1:'),
    
    # Finally without colon
    (r'^(\s*finally\s*)$', r'\1:')
]

def find_project_root():
    """Find the project root directory containing the 'backend' folder."""
    current_dir = os.path.abspath(os.getcwd())
    
    # Check if we're already in the backend directory
    if os.path.basename(current_dir) == 'backend':
        return os.path.dirname(current_dir)
    
    # Check if backend is in current directory
    if os.path.exists(os.path.join(current_dir, 'backend')):
        return current_dir
    
    # Try to find by traversing up
    parent = os.path.dirname(current_dir)
    while parent != current_dir:
        if os.path.exists(os.path.join(parent, 'backend')):
            return parent
        current_dir = parent
        parent = os.path.dirname(current_dir)
    
    return None

def is_python_file(file_path):
    """Check if a file is a Python file."""
    return file_path.endswith('.py')

def fix_file(file_path):
    """Fix syntax issues in a file."""
    print(f"Checking {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        modified = False
        
        # Fix line by line
        lines = content.split('\n')
        for i, line in enumerate(lines):
            for pattern, replacement in PATTERNS:
                if re.match(pattern, line):
                    print(f"  Line {i+1}: Found syntax issue in: {line.strip()}")
                    lines[i] = re.sub(pattern, replacement, line)
                    modified = True
                    print(f"  Line {i+1}: Fixed to: {lines[i].strip()}")
        
        if modified:
            content = '\n'.join(lines)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Fixed {file_path}")
            return True
        else:
            print(f"No syntax issues found in {file_path}")
            return False
            
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        return False

def find_and_fix_files(directory):
    """Find and fix Python files in the given directory."""
    fixed_count = 0
    examined_count = 0
    
    for root, _, files in os.walk(directory):
        for file in files:
            if not is_python_file(file):
                continue
                
            file_path = os.path.join(root, file)
            if os.path.join('app', 'tests') in file_path:
                examined_count += 1
                if fix_file(file_path):
                    fixed_count += 1
    
    return fixed_count, examined_count

def main():
    """Main function to find and fix files."""
    project_root = find_project_root()
    if not project_root:
        print("Could not find project root containing backend directory.")
        return
    
    backend_dir = os.path.join(project_root, 'backend')
    fixed_count, examined_count = find_and_fix_files(backend_dir)
    
    print(f"\nFixed {fixed_count} files out of {examined_count} examined")

if __name__ == "__main__":
    main()