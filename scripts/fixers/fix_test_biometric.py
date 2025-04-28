#!/usr/bin/env python3
"""
Script to fix indentation issues in test_biometric_event_processor.py

This script detects and corrects common indentation issues in the specified test file
using proper indentation based on Python's syntax rules.
"""
import re
import sys

def fix_indentation(file_path):
    """Fix all indentation issues in the specified file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Fix fixture indentation issues
    content = re.sub(r'(\n\s+)@pytest\.fixture\n\s+def', r'\1@pytest.fixture\n\1def', content)
    
    # Fix method indentation issues inside classes
    content = re.sub(r'(\n\s+)@pytest\.mark\.standalone\(\)\n\s+def', r'\1@pytest.mark.standalone()\n\1def', content)
    
    # Fix docstring indentation
    content = re.sub(r'def ([^:]+):\n(\s+)"""', r'def \1:\n\2"""', content)
    
    # Fix indentation inside methods
    content = re.sub(r'assert ([^\n]+)\n(\s+)assert', r'assert \1\n\2assert', content)
    
    # Fix issues with misaligned blocks after conditionals
    content = re.sub(r'if ([^:]+):\n(\s+)([^\s])', r'if \1:\n\2\3', content)
    content = re.sub(r'for ([^:]+):\n(\s+)([^\s])', r'for \1:\n\2\3', content)
    
    # Fix function parameter indentation
    content = re.sub(r'(\n\s+)return ([^\n]+)\(\n\s+', r'\1return \2(\n\1    ', content)
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Fixed indentation in {file_path}")

if __name__ == "__main__":
    file_path = "/Users/ray/Desktop/GITHUB/Novamind-Backend-ONLY-TWINS/backend/app/tests/standalone/core/test_biometric_event_processor.py"
    fix_indentation(file_path)
    
    # Also fix the digital twin test
    twin_file = "/Users/ray/Desktop/GITHUB/Novamind-Backend-ONLY-TWINS/backend/app/tests/standalone/core/test_mock_digital_twin.py"
    fix_indentation(twin_file)
