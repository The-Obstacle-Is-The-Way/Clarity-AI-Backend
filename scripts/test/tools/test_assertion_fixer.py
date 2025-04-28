#!/usr/bin/env python3
"""
Test Assertion Fixer for Novamind Backend

This script fixes common issues in test files, including:
1. Assertion method spacing (self.assert Equal -> self.assertEqual)
2. Indentation issues
3. Return statements outside functions
4. Import path corrections

Usage:
    python test_assertion_fixer.py [--dry-run] [--verbose]
"""

import argparse
import ast
import os
import re
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class TestAssertionFixer:
    """Tests for the AssertionFixer tool."""

    def setup_method(self, method):
        """Set up for each test method."""
        # Setup logic can go here if needed, replacing __init__
        self.project_root = Path(__file__).resolve().parent
        self.tests_dir = self.project_root / "app" / "tests"
        self.dry_run = False
        self.verbose = False
        self.fixed_files = []
        self.failed_files = []
        
        # Common assertion methods that might have spaces
        self.assertion_patterns = [
            (r'self\.assert\s+Equal\(', 'self.assertEqual('),
            (r'self\.assert\s+True\(', 'self.assertTrue('),
            (r'self\.assert\s+False\(', 'self.assertFalse('),
            (r'self\.assert\s+Is\(', 'self.assertIs('),
            (r'self\.assert\s+IsNot\(', 'self.assertIsNot('),
            (r'self\.assert\s+IsNone\(', 'self.assertIsNone('),
            (r'self\.assert\s+IsNotNone\(', 'self.assertIsNotNone('),
            (r'self\.assert\s+In\(', 'self.assertIn('),
            (r'self\.assert\s+NotIn\(', 'self.assertNotIn('),
            (r'self\.assert\s+Greater\(', 'self.assertGreater('),
            (r'self\.assert\s+GreaterEqual\(', 'self.assertGreaterEqual('),
            (r'self\.assert\s+Less\(', 'self.assertLess('),
            (r'self\.assert\s+LessEqual\(', 'self.assertLessEqual('),
            (r'self\.assert\s+Raises\(', 'self.assertRaises('),
            (r'self\.assert\s+Regex\(', 'self.assertRegex('),
            (r'self\.assert\s+NotRegex\(', 'self.assertNotRegex('),
            (r'self\.assert\s+Almost\s+Equal\(', 'self.assertAlmostEqual('),
            (r'self\.assert\s+Not\s+Almost\s+Equal\(', 'self.assertNotAlmostEqual('),
            (r'self\.assert\s+Dict\s+Equal\(', 'self.assertDictEqual('),
            (r'self\.assert\s+List\s+Equal\(', 'self.assertListEqual('),
            (r'self\.assert\s+Tuple\s+Equal\(', 'self.assertTupleEqual('),
            (r'self\.assert\s+Set\s+Equal\(', 'self.assertSetEqual('),
            (r'self\.assert\s+Multi\s+Line\s+Equal\(', 'self.assertMultiLineEqual('),
        ]
        
        # Import corrections
        self.import_corrections = {
            'from app.': 'from app.',
            'from app.domain.value_objects.patient_id import PatientId': 'from app.domain.models.patient import PatientId',
            'from app.domain.models.patient import Patient': 'from app.domain.entities.patient import Patient',
        }

    def teardown_method(self, method):
        """Clean up after each test method."""
        pass

    def find_test_files(self) -> List[Path]:
        """Find all test files in the test directory."""
        test_files = []
        for path in self.tests_dir.glob('**/*.py'):
            if path.name.startswith('test_'):
                test_files.append(path)
        return test_files

    def fix_file(self, file_path: Path) -> bool:
        """
        Fix issues in a test file.
        
        Returns:
            bool: True if fixes were applied successfully, False otherwise
        """
        try:
            if self.verbose:
                print(f"Examining {file_path}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Store original content for comparison
            original_content = content
            
            # Fix assertion method spacing
            for pattern, replacement in self.assertion_patterns:
                content = re.sub(pattern, replacement, content)
            
            # Fix import paths
            for old_import, new_import in self.import_corrections.items():
                content = content.replace(old_import, new_import)
            
            # Fix indentation issues
            content = self.fix_indentation(content)
            
            # Fix 'return' outside function
            content = self.fix_return_outside_function(content)
            
            # Only write to file if content changed and we're not in dry run mode
            if content != original_content:
                if not self.dry_run:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                print(f"{Colors.GREEN}Fixed {file_path}{Colors.ENDC}")
                self.fixed_files.append(file_path)
                return True
            elif self.verbose:
                print(f"{Colors.BLUE}No issues found in {file_path}{Colors.ENDC}")
                
            return True
                
        except Exception as e:
            print(f"{Colors.RED}Error fixing {file_path}: {str(e)}{Colors.ENDC}")
            self.failed_files.append((file_path, str(e)))
            return False

    def fix_indentation(self, content: str) -> str:
        """Fix common indentation issues."""
        lines = content.split('\n')
        fixed_lines = []
        
        in_class = False
        in_function = False
        class_indent = 0
        function_indent = 0
        
        for i, line in enumerate(lines):
            # Skip empty lines
            if not line.strip():
                fixed_lines.append(line)
                continue
                
            # Get current line indentation
            current_indent = len(line) - len(line.lstrip())
            
            # Check for class definition
            if re.match(r'^\s*class\s+\w+', line):
                in_class = True
                class_indent = current_indent
            
            # Check for function definition
            if re.match(r'^\s*def\s+\w+', line):
                in_function = True
                function_indent = current_indent
            
            # Fix indentation for class methods
            if in_class and current_indent > 0 and not line.strip().startswith('#'):
                if current_indent != class_indent and current_indent != class_indent + 4 and not in_function:
                    # Adjust indentation for class-level code
                    line = ' ' * (class_indent + 4) + line.strip()
                elif in_function and current_indent != function_indent and current_indent != function_indent + 4:
                    # Adjust indentation for function-level code
                    if i > 0 and lines[i-1].strip().endswith(':'):
                        # This is likely the first line after a block opener, indent it properly
                        line = ' ' * (function_indent + 4) + line.strip()
            
            fixed_lines.append(line)
            
            # Check for end of blocks
            if in_function and (i+1 < len(lines)) and not lines[i+1].strip():
                in_function = False
            
        return '\n'.join(fixed_lines)

    def fix_return_outside_function(self, content: str) -> str:
        """Fix return statements that are outside of functions."""
        lines = content.split('\n')
        fixed_lines = []
        
        in_function = False
        function_indent = 0
        
        for i, line in enumerate(lines):
            # Skip empty lines
            if not line.strip():
                fixed_lines.append(line)
                continue
                
            # Get current line indentation
            current_indent = len(line) - len(line.lstrip())
            
            # Check for function definition
            if re.match(r'^\s*def\s+\w+', line):
                in_function = True
                function_indent = current_indent
            
            # Check for return statement outside function
            if re.match(r'^\s*return\s', line) and not in_function:
                # Wrap in a function if necessary
                if i > 0 and "class" in lines[i-1]:
                    # This is probably a method that's missing its def line
                    fixed_lines.append(f"{' ' * current_indent}def missing_method(self):")
                    fixed_lines.append(f"{' ' * (current_indent + 4)}{line.strip()}")
                    continue
                else:
                    # Just comment it out as we can't safely fix this
                    fixed_lines.append(f"# {line} # FIXME: return outside function")
                    continue
                    
            fixed_lines.append(line)
            
            # Check for end of function
            if in_function and function_indent >= current_indent and i > 0 and lines[i-1].strip():
                if not line.strip().startswith('def') and not line.strip().startswith('class'):
                    in_function = False
            
        return '\n'.join(fixed_lines)

    def run(self) -> bool:
        """
        Run the fixer on all test files.
        
        Returns:
            bool: True if all files were fixed successfully, False otherwise
        """
        print(f"{Colors.HEADER}Running Test Assertion Fixer...{Colors.ENDC}")
        print(f"Project root: {self.project_root}")
        print(f"Tests directory: {self.tests_dir}")
        
        if self.dry_run:
            print(f"{Colors.YELLOW}DRY RUN MODE: No files will be modified{Colors.ENDC}")
        
        test_files = self.find_test_files()
        print(f"Found {len(test_files)} test files")
        
        for file_path in test_files:
            self.fix_file(file_path)
        
        # Print summary
        print(f"\nSummary:")
        print(f"  - Fixed {len(self.fixed_files)} files")
        print(f"  - Failed to fix {len(self.failed_files)} files")
        
        if self.failed_files:
            print(f"\n{Colors.RED}Files with errors:{Colors.ENDC}")
            for file_path, error in self.failed_files:
                print(f"  - {file_path}: {error}")
        
        return len(self.failed_files) == 0


def parse_args():
    parser = argparse.ArgumentParser(description="Test Assertion Fixer for Novamind Backend")
    parser.add_argument("--dry-run", action="store_true", help="Don't write any changes to files")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")
    return parser.parse_args()


def main():
    args = parse_args()
    
    # Determine project root
    current_dir = Path(__file__).resolve().parent
    project_root = current_dir
    while project_root.name != 'backend' and project_root != project_root.parent:
        project_root = project_root.parent
    
    fixer = TestAssertionFixer()
    fixer.dry_run = args.dry_run
    fixer.verbose = args.verbose
    success = fixer.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()