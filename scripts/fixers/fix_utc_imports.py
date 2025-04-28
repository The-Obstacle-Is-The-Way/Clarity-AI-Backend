#!/usr/bin/env python3
"""
UTC Import Fixer for Novamind Digital Twin.

This script analyzes the entire codebase and fixes imports of UTC directly from
datetime module, replacing them with imports from the new datetime_utils module
following clean architecture principles.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Set, Tuple

# Configuration constants
PROJECT_ROOT = Path(__file__).parent.parent
BACKEND_DIR = PROJECT_ROOT
EXCLUDE_DIRS = [
    BACKEND_DIR / ".git",
    BACKEND_DIR / ".venv",
    BACKEND_DIR / "venv",
    BACKEND_DIR / "__pycache__",
    BACKEND_DIR / "test-results",
]

# Regular expression patterns
DIRECT_UTC_IMPORT_PATTERN = re.compile(r'from\s+datetime\s+import\s+([^,]*,\s*)*UTC(\s*,\s*[^,]*)*')
DATETIME_UTC_USAGE_PATTERN = re.compile(r'datetime\.UTC')

# Replacement patterns
UTILS_IMPORT = "from app.domain.utils.datetime_utils import UTC"


class ImportRefactorer:
    """
    Neural system for refactoring imports with mathematical precision.
    
    This class embodies the single responsibility principle by focusing solely
    on refactoring imports without mixing concerns.
    """
    
    def __init__(self, dry_run: bool = False):
        """
        Initialize the refactorer with execution parameters.
        
        Args:
            dry_run: If True, don't actually change files, just report what would change
        """
        self.dry_run = dry_run
        self.files_processed = 0
        self.files_modified = 0
    
    def should_exclude(self, path: Path) -> bool:
        """
        Determine if a path should be excluded from processing.
        
        Args:
            path: The path to check
            
        Returns:
            True if the path should be excluded, False otherwise
        """
        # Check if the path is in any excluded directory
        for exclude_dir in EXCLUDE_DIRS:
            if str(path).startswith(str(exclude_dir)):
                return True
        
        # Skip non-Python files
        if path.suffix != '.py':
            return True
        
        # Skip the datetime_utils.py file itself
        if path.name == 'datetime_utils.py':
            return True
            
        return False
    
    def find_python_files(self) -> List[Path]:
        """
        Find all Python files in the codebase that need processing.
        
        Returns:
            List of Path objects for Python files
        """
        python_files = []
        
        for root, dirs, files in os.walk(BACKEND_DIR):
            # Convert to Path objects
            root_path = Path(root)
            
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not self.should_exclude(root_path / d)]
            
            # Process Python files
            for file in files:
                file_path = root_path / file
                if not self.should_exclude(file_path):
                    python_files.append(file_path)
        
        return python_files
    
    def process_file(self, file_path: Path) -> bool:
        """
        Process a single file, updating UTC imports as needed.
        
        Args:
            file_path: Path to the file to process
            
        Returns:
            True if the file was modified, False otherwise
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Check if the file needs modification
            has_direct_import = bool(DIRECT_UTC_IMPORT_PATTERN.search(content))
            has_datetime_usage = bool(DATETIME_UTC_USAGE_PATTERN.search(content))
            
            if not (has_direct_import or has_datetime_usage):
                return False
                
            # Perform the replacements
            if has_direct_import:
                # Replace direct imports of UTC from datetime
                modified_content = DIRECT_UTC_IMPORT_PATTERN.sub(
                    lambda m: self._fix_import_line(m.group(0)),
                    content
                )
            else:
                modified_content = content
                
            if has_datetime_usage:
                # Replace datetime.UTC with just UTC
                modified_content = DATETIME_UTC_USAGE_PATTERN.sub('UTC', modified_content)
                
                # Add the import if it's not already there
                if UTILS_IMPORT not in modified_content:
                    import_insertion_point = self._find_import_insertion_point(modified_content)
                    modified_content = (
                        modified_content[:import_insertion_point] +
                        UTILS_IMPORT + "\n" +
                        modified_content[import_insertion_point:]
                    )
            
            # Write changes back to the file if this isn't a dry run
            if not self.dry_run and modified_content != content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(modified_content)
                return True
                
            # For dry runs, just report that we would have made changes
            return modified_content != content
            
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return False
    
    def _fix_import_line(self, import_line: str) -> str:
        """
        Fix a datetime import line to remove UTC while preserving other imports.
        
        Args:
            import_line: The original import line
            
        Returns:
            Modified import line with UTC removed
        """
        # Extract the things being imported
        matches = re.match(r'from\s+datetime\s+import\s+(.*)', import_line)
        if not matches:
            return import_line
            
        imported_items = matches.group(1).split(',')
        clean_items = []
        
        for item in imported_items:
            item = item.strip()
            if item != 'UTC':
                clean_items.append(item)
        
        if not clean_items:
            # If UTC was the only import, remove the entire line
            return ""
        else:
            # Reconstruct the import line without UTC
            return f"from datetime import {', '.join(clean_items)}"
    
    def _find_import_insertion_point(self, content: str) -> int:
        """
        Find the appropriate point to insert the new import.
        
        Args:
            content: The file content
            
        Returns:
            Character index where the import should be inserted
        """
        # Try to find the last import statement
        import_matches = list(re.finditer(r'^(?:from|import)\s+\w+', content, re.MULTILINE))
        
        if import_matches:
            last_import = import_matches[-1]
            # Find the end of the line
            end_of_line = content.find('\n', last_import.end())
            if end_of_line != -1:
                return end_of_line + 1
                
        # If no imports found, insert after any module docstring
        docstring_match = re.search(r'^""".*?"""', content, re.DOTALL)
        if docstring_match:
            return docstring_match.end() + 1
            
        # Default to the beginning of the file
        return 0
    
    def run(self) -> Tuple[int, int]:
        """
        Run the import refactoring process on the entire codebase.
        
        Returns:
            Tuple of (files_processed, files_modified)
        """
        print(f"Running {'in dry-run mode ' if self.dry_run else ''}from {BACKEND_DIR}")
        
        python_files = self.find_python_files()
        print(f"Found {len(python_files)} Python files to process")
        
        for file_path in python_files:
            self.files_processed += 1
            modified = self.process_file(file_path)
            
            if modified:
                self.files_modified += 1
                status = "Would modify" if self.dry_run else "Modified"
            else:
                status = "Unchanged"
                
            # Print progress every 10 files
            if self.files_processed % 10 == 0 or modified:
                print(f"[{self.files_processed}/{len(python_files)}] {status}: {file_path.relative_to(BACKEND_DIR)}")
        
        return self.files_processed, self.files_modified


if __name__ == "__main__":
    # Parse command line arguments
    dry_run = "--dry-run" in sys.argv
    
    # Run the refactorer
    refactorer = ImportRefactorer(dry_run=dry_run)
    files_processed, files_modified = refactorer.run()
    
    # Report results
    print("\n=== Summary ===")
    print(f"Files processed: {files_processed}")
    print(f"Files {('to be ' if dry_run else '')}modified: {files_modified}")
    
    # Instructions for dry run
    if dry_run and files_modified > 0:
        print("\nRun without --dry-run to apply these changes")
