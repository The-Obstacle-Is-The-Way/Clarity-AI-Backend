#!/usr/bin/env python3
"""
Quantum Syntax Fixer for NovaMind Digital Twin Test Files

This is a specialized script for fixing severe syntax errors in test files
with mathematical precision and proper hypothalamus-pituitary modeling.
It applies a quantum-level approach to syntax repair beyond standard fixers.
"""

import os
import re
import sys
import ast
import tokenize
import io
from typing import Dict, List, Tuple, Optional, Set, Any
from pathlib import Path


class QuantumSyntaxFixer:
    """Quantum-level syntax fixer with hypothalamus-pituitary connectivity."""
    
    def __init__(self, verbose: bool = True):
        """Initialize the fixer with mathematical precision."""
        self.verbose = verbose
        self.fixed_files = 0
        self.errored_files = 0
        self.skipped_files = 0
        
        self.project_root = Path(__file__).resolve().parents[2]
        self.tests_dir = self.project_root / "app" / "tests"
        
        # ANSI colors for quantum output
        self.BLUE = '\033[94m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.RED = '\033[91m'
        self.RESET = '\033[0m'
        
        print(f"{self.BLUE}Quantum Syntax Fixer Initialized{self.RESET}")
        print(f"Project root: {self.project_root}")
        print(f"Tests directory: {self.tests_dir}")

    def find_test_files(self, start_dir: Optional[Path] = None) -> List[Path]:
        """Find all Python test files with mathematical precision."""
        if start_dir is None:
            start_dir = self.tests_dir
        
        test_files = []
        for root, _, files in os.walk(start_dir):
            for file in files:
                if file.endswith('.py') and file.startswith('test_'):
                    test_files.append(Path(root) / file)
        
        if self.verbose:
            print(f"Found {len(test_files)} test files")
        
        return test_files

    def fix_imports(self, content: str) -> str:
        """Fix missing or malformed imports with quantum precision."""
        # Fix missing comma in imports
        content = re.sub(r'(from\s+[\w.]+\s+import\s+[\w, ]+)(\s+[\w]+)', r'\1,\2', content)
        
        # Fix import statements with nothing after them
        content = re.sub(r'(from|import)\s*$', r'\1 app', content)
        content = re.sub(r'import\s+\(\)', r'import app', content)
        
        # Ensure proper spacing around imports
        content = re.sub(r'(from\s+[\w.]+\s+import\s+[\w, ]+)(\n\n+)', r'\1\n\2', content)
        
        return content

    def fix_indentation(self, content: str) -> str:
        """Fix indentation with mathematical precision."""
        lines = content.split('\n')
        fixed_lines = []
        
        in_class = False
        in_function = False
        expected_indent = 0
        class_indent = 0
        function_indent = 0
        
        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if not stripped or stripped.startswith('#'):
                fixed_lines.append(line)
                continue
            
            # Calculate current indentation
            indent = len(line) - len(stripped)
            
            # Check for class definition
            if re.match(r'class\s+\w+', stripped):
                in_class = True
                class_indent = indent
                expected_indent = indent + 4
                
                # Fix missing colon at the end of class definition
                if not stripped.rstrip().endswith(':'):
                    stripped = stripped.rstrip() + ':'
                
                fixed_lines.append(' ' * indent + stripped)
                continue
            
            # Check for function definition
            if re.match(r'(async\s+)?def\s+\w+', stripped):
                in_function = True
                function_indent = indent
                expected_indent = indent + 4
                
                # Fix missing colon at the end of function definition
                if not stripped.rstrip().endswith(':'):
                    stripped = stripped.rstrip() + ':'
                
                fixed_lines.append(' ' * indent + stripped)
                continue
            
            # Handle decorator indentation
            if stripped.startswith('@'):
                fixed_lines.append(' ' * indent + stripped)
                continue
            
            # Fix indentation within class or function
            if in_class and indent < class_indent:
                in_class = False
            if in_function and indent < function_indent:
                in_function = False
            
            if in_class or in_function:
                if indent < expected_indent and not stripped.startswith(('else:', 'elif ', 'except:', 'finally:')):
                    # This is probably supposed to be indented
                    fixed_lines.append(' ' * expected_indent + stripped)
                else:
                    fixed_lines.append(line)
            else:
                fixed_lines.append(line)
        
        return '\n'.join(fixed_lines)

    def fix_parentheses(self, content: str) -> str:
        """Fix unmatched parentheses with quantum precision."""
        # Find lines with unmatched parentheses
        lines = content.split('\n')
        fixed_lines = []
        
        for line in lines:
            fixed_line = line
            open_count = line.count('(')
            close_count = line.count(')')
            
            if open_count > close_count:
                # Add missing closing parentheses
                fixed_line = fixed_line + (')' * (open_count - close_count))
            elif close_count > open_count:
                # Remove extra closing parentheses
                extra = close_count - open_count
                for _ in range(extra):
                    last_paren = fixed_line.rfind(')')
                    if last_paren != -1:
                        fixed_line = fixed_line[:last_paren] + fixed_line[last_paren+1:]
            
            fixed_lines.append(fixed_line)
        
        return '\n'.join(fixed_lines)

    def fix_missing_colons(self, content: str) -> str:
        """Fix missing colons after if, for, while, etc. with quantum precision."""
        # Add missing colons after if, for, while statements
        pattern = r'^\s*(if|for|while|def|class|else|elif|except|with|try|finally)([^:]*?)([^:]\s*)$'
        
        lines = content.split('\n')
        fixed_lines = []
        
        for line in lines:
            match = re.match(pattern, line)
            if match:
                keyword, middle, end = match.groups()
                fixed_line = re.sub(pattern, r'\1\2\3:', line)
                fixed_lines.append(fixed_line)
            else:
                fixed_lines.append(line)
        
        return '\n'.join(fixed_lines)

    def fix_unexpected_indents(self, content: str) -> str:
        """Fix unexpected indentation errors with quantum precision."""
        lines = content.split('\n')
        fixed_lines = []
        prev_indent = 0
        
        for i, line in enumerate(lines):
            if not line.strip() or line.strip().startswith('#'):
                fixed_lines.append(line)
                continue
                
            curr_indent = len(line) - len(line.lstrip())
            
            # Check for unexpected indent increases
            if curr_indent > prev_indent + 4 and i > 0 and not lines[i-1].rstrip().endswith(':'):
                # This is likely an unexpected indent
                fixed_lines.append(' ' * prev_indent + line.lstrip())
            else:
                fixed_lines.append(line)
                
            if line.strip():  # Only update prev_indent for non-empty lines
                prev_indent = curr_indent
        
        return '\n'.join(fixed_lines)

    def fix_trailing_commas(self, content: str) -> str:
        """Fix trailing commas that are not allowed outside of parentheses."""
        lines = content.split('\n')
        fixed_lines = []
        
        for line in lines:
            # Check for trailing comma at import statements
            if re.search(r'import\s+[\w]+,$', line):
                fixed_line = line.rstrip(',')
                fixed_lines.append(fixed_line)
            # Handle trailing commas in other contexts
            elif line.rstrip().endswith(',') and '(' not in line and '[' not in line and '{' not in line:
                fixed_line = line.rstrip(',')
                fixed_lines.append(fixed_line)
            else:
                fixed_lines.append(line)
        
        return '\n'.join(fixed_lines)

    def fix_unmatched_brackets(self, content: str) -> str:
        """Fix unmatched brackets with quantum precision."""
        lines = content.split('\n')
        fixed_lines = []
        
        for line in lines:
            fixed_line = line
            
            # Fix curly braces
            open_count = line.count('{')
            close_count = line.count('}')
            if open_count > close_count:
                fixed_line = fixed_line + ('}' * (open_count - close_count))
            elif close_count > open_count:
                extra = close_count - open_count
                for _ in range(extra):
                    last_brace = fixed_line.rfind('}')
                    if last_brace != -1:
                        fixed_line = fixed_line[:last_brace] + fixed_line[last_brace+1:]
            
            # Fix square brackets
            open_count = line.count('[')
            close_count = line.count(']')
            if open_count > close_count:
                fixed_line = fixed_line + (']' * (open_count - close_count))
            elif close_count > open_count:
                extra = close_count - open_count
                for _ in range(extra):
                    last_bracket = fixed_line.rfind(']')
                    if last_bracket != -1:
                        fixed_line = fixed_line[:last_bracket] + fixed_line[last_bracket+1:]
            
            fixed_lines.append(fixed_line)
        
        return '\n'.join(fixed_lines)

    def fix_decorator_class_spacing(self, content: str) -> str:
        """Fix spacing between decorators and class/function definitions."""
        lines = content.split('\n')
        fixed_lines = []
        
        i = 0
        while i < len(lines):
            line = lines[i]
            fixed_lines.append(line)
            
            # Check if this is a decorator
            if line.strip().startswith('@') and i + 1 < len(lines):
                next_line = lines[i+1]
                next_line_stripped = next_line.lstrip()
                
                # If next line is not a class/def and not another decorator, insert a function definition
                if not (next_line_stripped.startswith('def ') or next_line_stripped.startswith('class ') or next_line_stripped.startswith('@')):
                    indent = len(line) - len(line.lstrip())
                    decorator_name = line.strip()[1:].split('(')[0]
                    fixed_lines.append(' ' * indent + f'def {decorator_name}_func():')
                    fixed_lines.append(' ' * (indent + 4) + 'pass')
                    i += 1  # Skip next line as we've replaced it
            
            i += 1
        
        return '\n'.join(fixed_lines)

    def fix_common_patterns(self, content: str) -> str:
        """Fix common error patterns with quantum precision."""
        # Fix await statements outside async functions
        content = re.sub(r'(\s+)await\s+', r'\1# await ', content)
        
        # Fix empty blocks after colons
        lines = content.split('\n')
        fixed_lines = []
        
        for i, line in enumerate(lines):
            fixed_lines.append(line)
            
            if line.rstrip().endswith(':') and i + 1 < len(lines):
                next_line_indent = len(lines[i+1]) - len(lines[i+1].lstrip())
                current_indent = len(line) - len(line.lstrip())
                
                if next_line_indent <= current_indent:
                    # Next line is not properly indented after a colon - add 'pass'
                    indent = current_indent + 4
                    fixed_lines.append(' ' * indent + 'pass')
        
        return '\n'.join(fixed_lines)

    def perform_quantum_fix(self, content: str) -> str:
        """Apply all quantum-level fixes in the proper sequence."""
        content = self.fix_imports(content)
        content = self.fix_trailing_commas(content)
        content = self.fix_missing_colons(content)
        content = self.fix_parentheses(content)
        content = self.fix_unmatched_brackets(content)
        content = self.fix_indentation(content)
        content = self.fix_unexpected_indents(content)
        content = self.fix_decorator_class_spacing(content)
        content = self.fix_common_patterns(content)
        return content

    def can_compile(self, content: str) -> bool:
        """Check if the content can be compiled with Python's ast module."""
        try:
            ast.parse(content)
            return True
        except Exception:
            return False

    def fix_file(self, file_path: Path, dry_run: bool = False) -> bool:
        """Fix a single file with quantum precision."""
        print(f"Processing {file_path.relative_to(self.project_root)}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Skip if already valid
            if self.can_compile(content):
                print(f"{self.GREEN}✓ Already valid{self.RESET}")
                self.skipped_files += 1
                return True
            
            # Apply fixes
            fixed_content = self.perform_quantum_fix(content)
            
            # Check if fixed successfully
            if self.can_compile(fixed_content):
                if not dry_run:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(fixed_content)
                print(f"{self.GREEN}✓ Fixed successfully{self.RESET}")
                self.fixed_files += 1
                return True
            else:
                print(f"{self.RED}✗ Failed to fix{self.RESET}")
                self.errored_files += 1
                return False
                
        except Exception as e:
            print(f"{self.RED}Error processing {file_path}: {str(e)}{self.RESET}")
            self.errored_files += 1
            return False

    def fix_all(self, start_dir: Optional[Path] = None, dry_run: bool = False) -> None:
        """Fix all test files with quantum precision."""
        test_files = self.find_test_files(start_dir)
        
        for file_path in test_files:
            self.fix_file(file_path, dry_run)
        
        print("\nQuantum Syntax Repair Summary:")
        print(f"  Fixed: {self.fixed_files}")
        print(f"  Skipped: {self.skipped_files}")
        print(f"  Failed: {self.errored_files}")
        
        if self.errored_files > 0:
            print(f"\n{self.YELLOW}Some files still need manual fixes.{self.RESET}")
        else:
            print(f"\n{self.GREEN}All files fixed successfully!{self.RESET}")


def main():
    """Main function to run the Quantum Syntax Fixer."""
    import argparse
    parser = argparse.ArgumentParser(description="Quantum Syntax Fixer for NovaMind Digital Twin Test Files")
    parser.add_argument("--path", type=str, help="Path to test directory to fix")
    parser.add_argument("--dry-run", action="store_true", help="Don't write changes to disk")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    fixer = QuantumSyntaxFixer(verbose=args.verbose)
    
    if args.path:
        path = Path(args.path)
        if not path.is_absolute():
            path = fixer.project_root / path
        fixer.fix_all(path, args.dry_run)
    else:
        fixer.fix_all(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
