#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Syntax fix script for missing colons in test files.
This script specifically targets common missing colons in class and function definitions.
"""

import os
import re
import sys
from pathlib import Path

# Files with "expected ':'" errors from the terminal output
FILES_TO_FIX = [
    "app/tests/unit/test_mentallama_service.py",
    "app/tests/unit/core/services/ml/pat/test_mock_pat.py",
    "app/tests/unit/services/ml/pat/test_pat_service.py",
    "app/tests/unit/infrastructure/ml/pharmacogenomics/test_model_service_pgx.py", 
    "app/tests/unit/infrastructure/ml/pharmacogenomics/test_treatment_model.py",
    "app/tests/unit/infrastructure/ml/symptom_forecasting/test_model_service_symptom.py",
    "app/tests/unit/infrastructure/ml/symptom_forecasting/test_ensemble_model.py",
    "app/tests/unit/infrastructure/ml/symptom_forecasting/test_transformer_model.py",
    "app/tests/unit/infrastructure/ml/biometric_correlation/test_model_service.py",
    "app/tests/security/test_log_sanitization.py"
]

# Patterns to fix
PATTERNS = [
    # Class definition without colon
    (r'^\s*class\s+(\w+)(\s*\([\w,\s.]*\))?\s*$', r'class \1\2:'),
    # Function definition without colon
    (r'^\s*def\s+(\w+)(\s*\([^)]*\))\s*$', r'def \1\2:'),
    # Async function definition without colon
    (r'^\s*async\s+def\s+(\w+)(\s*\([^)]*\))\s*$', r'async def \1\2:'),
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

def fix_file(file_path):
    """Fix missing colons in a file."""
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
                    print(f"  Line {i+1}: Found missing colon in: {line.strip()}")
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
            print(f"No missing colons found in {file_path}")
            return False
            
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        return False

def main():
    """Main function to fix files."""
    project_root = find_project_root()
    if not project_root:
        print("Could not find project root containing backend directory.")
        return
    
    backend_dir = os.path.join(project_root, 'backend')
    fixed_count = 0
    
    for rel_path in FILES_TO_FIX:
        file_path = os.path.join(backend_dir, rel_path)
        if os.path.exists(file_path):
            if fix_file(file_path):
                fixed_count += 1
        else:
            print(f"File not found: {file_path}")
    
    print(f"\nFixed {fixed_count} files out of {len(FILES_TO_FIX)}")

if __name__ == "__main__":
    main()