#!/usr/bin/env python3
"""
A focused indentation and syntax fixer for the Digital Twin tests.
This script enforces proper Python indentation and fixes common syntax issues
with a focus on the core Digital Twin tests, following clean code principles.
"""

import os
import sys
import re


def fix_indentation(content):
    """Fix indentation issues by ensuring proper 4-space indentation throughout."""
    lines = content.split('\n')
    fixed_lines = []
    
    # Track indentation level
    indent_stack = [0]  # Start with 0 indentation
    
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        
        # Skip empty lines and comments
        if not stripped or stripped.startswith('#'):
            fixed_lines.append(line)
            continue
        
        # Calculate current indentation
        current_indent = len(line) - len(stripped)
        
        # Check if we're starting a new block
        if stripped.endswith(':'):
            fixed_lines.append(line)
            # Push new indentation level
            indent_stack.append(current_indent + 4)
            continue
            
        # Check if we're ending a block
        if current_indent < indent_stack[-1] and any(stripped.startswith(keyword) for keyword in 
                                                 ['def ', 'class ', 'return', 'raise', 'break', 'continue', 'pass']):
            # Pop indentation level if we've decreased indentation
            while current_indent < indent_stack[-1] and len(indent_stack) > 1:
                indent_stack.pop()
        
        # Adjust indentation to match expected level
        fixed_lines.append(' ' * indent_stack[-1] + stripped)
    
    return '\n'.join(fixed_lines)


def fix_method_calls(content):
    """Fix method calls with improper indentation."""
    # Fix method calls where arguments are improperly indented
    pattern = r'(\w+\()\s*\n\s*([^)]+)\s*\n\s*\)'
    replacement = r'\1\n        \2\n    )'
    content = re.sub(pattern, replacement, content)
    
    # Fix assert statements
    pattern = r'self\.assert (\w+)'
    replacement = r'self.assert\1'
    return re.sub(pattern, replacement, content)


def fix_file(file_path):
    """Fix indentation and syntax issues in a Python file."""
    print(f"Fixing {file_path}...")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Fix basic syntax issues
        content = fix_indentation(content)
        content = fix_method_calls(content)
        
        # Fix any remaining assert statements with spaces
        content = content.replace('assert IsInstance', 'assertIsInstance')
        content = content.replace('assert Equal', 'assertEqual')
        content = content.replace('assert In', 'assertIn')
        content = content.replace('assert True', 'assertTrue')
        content = content.replace('assert False', 'assertFalse')
        content = content.replace('assert Raises', 'assertRaises')
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"Error fixing {file_path}: {e}")
        return False


def main():
    """Main function to find and fix Digital Twin test files."""
    base_dir = "/Users/ray/Desktop/GITHUB/Novamind-Backend-ONLY-TWINS/backend/app/tests"
    
    # Target specific files that are causing problems
    target_files = [
        # Standalone tests
        os.path.join(base_dir, "standalone/core/test_mock_digital_twin.py"),
        
        # Critical fixtures
        os.path.join(base_dir, "fixtures/mock_db_fixture.py"),
        
        # Core test modules
        os.path.join(base_dir, "unit/core/services/ml/test_mock_dt.py"),
        os.path.join(base_dir, "unit/core/services/ml/test_mock_digital_twin.py"),
    ]
    
    for file_path in target_files:
        if os.path.exists(file_path):
            fix_file(file_path)
            print(f"Fixed {file_path}")
        else:
            print(f"File not found: {file_path}")


if __name__ == "__main__":
    main()
