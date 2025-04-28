#!/usr/bin/env python
"""
Script to automatically fix common syntax errors in Python test files.
This script will scan test files, identify common syntax issues, and fix them when possible.
"""

import os
import sys
import re
import ast
import py_compile
import subprocess
from pathlib import Path
import logging
import tempfile
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def find_test_files(root_dir):
    """Find all test files in the given directory."""
    test_files = []
    for path in Path(root_dir).rglob('test_*.py'):
        test_files.append(str(path))
    return test_files

def check_syntax(file_path):
    """Check file for syntax errors and return error message if any."""
    try:
        py_compile.compile(file_path, doraise=True)
        return None
    except py_compile.PyCompileError as e:
        return str(e)
    except SyntaxError as e:
        return f"Line {e.lineno}, col {e.offset}: {e.msg}"
    except Exception as e:
        return str(e)

def fix_timedelta_params(content):
    """Fix issues with timedelta parameters."""
    # Pattern for timedelta with multiple parameters using comma
    pattern = r'timedelta\(days=(\d+),\s*hours=(\d+)\)'
    replacement = r'timedelta(days=\1) + timedelta(hours=\2)'
    return re.sub(pattern, replacement, content)

def fix_unmatched_parentheses(content):
    """
    Fix unmatched parentheses in the file.
    This is a simplified fix that tries to balance parentheses in each line.
    """
    lines = content.split('\n')
    fixed_lines = []
    
    for line in lines:
        # Count opening and closing parentheses
        open_count = line.count('(')
        close_count = line.count(')')
        
        # If more openings than closings, add the missing closings
        if open_count > close_count:
            line += ')' * (open_count - close_count)
        # If more closings than openings, add the missing openings at the beginning
        # (this is less common and might not always be correct)
        elif close_count > open_count:
            line = '(' * (close_count - open_count) + line
            
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)

def fix_indentation_errors(content):
    """Fix common indentation errors."""
    lines = content.split('\n')
    fixed_lines = []
    
    # Simple approach: make sure indentation is consistent
    # This won't fix all indentation issues but can handle simple cases
    for i, line in enumerate(lines):
        if i > 0 and line.strip() and lines[i-1].strip() and lines[i-1].rstrip().endswith(':'):
            # If previous line ends with a colon, indent this line if not already indented
            if not line.startswith(' ') and not line.startswith('\t'):
                line = '    ' + line
        fixed_lines.append(line)
    
    return '\n'.join(fixed_lines)

def fix_common_syntax_errors(file_path):
    """Attempt to fix common syntax errors in a file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Apply fixes
    content = fix_timedelta_params(content)
    content = fix_unmatched_parentheses(content)
    content = fix_indentation_errors(content)
    
    # If changes were made, write back to file
    if content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    
    return False

def verify_fix(file_path):
    """Verify that the file compiles after fixing."""
    error = check_syntax(file_path)
    if error:
        return False, error
    return True, None

def main():
    """Main function."""
    # Find the backend directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(script_dir)))
    
    # Find all test files
    logger.info(f"Searching for test files in {backend_dir}")
    test_files = find_test_files(backend_dir)
    logger.info(f"Found {len(test_files)} test files")
    
    # Check each file for syntax errors and fix if possible
    files_with_errors = []
    fixed_files = []
    files_still_with_errors = []
    
    for file_path in test_files:
        rel_path = os.path.relpath(file_path, backend_dir)
        
        # Check for syntax errors
        error = check_syntax(file_path)
        if error:
            logger.info(f"Attempting to fix {rel_path}")
            files_with_errors.append(rel_path)
            
            # Try to fix
            fixed = fix_common_syntax_errors(file_path)
            
            # Verify fix
            success, new_error = verify_fix(file_path)
            if success:
                logger.info(f"Successfully fixed {rel_path}")
                fixed_files.append(rel_path)
            else:
                logger.warning(f"Could not fix {rel_path}: {new_error}")
                files_still_with_errors.append((rel_path, new_error))
    
    # Report summary
    logger.info("\nRepair Summary:")
    logger.info(f"  Total test files: {len(test_files)}")
    logger.info(f"  Files with errors: {len(files_with_errors)}")
    logger.info(f"  Successfully fixed: {len(fixed_files)}")
    logger.info(f"  Failed to fix: {len(files_still_with_errors)}")
    
    if files_still_with_errors:
        logger.warning("Some files still need manual fixes. See above for details.")
        
        # Export list of files with errors to a text file for easy reference
        with open(os.path.join(backend_dir, "unfixed_syntax_errors.txt"), "w") as f:
            for rel_path, error in files_still_with_errors:
                f.write(f"{rel_path}: {error}\n")
    else:
        logger.info("All syntax errors have been fixed!")

if __name__ == "__main__":
    main()