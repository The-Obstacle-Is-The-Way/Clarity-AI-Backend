#!/usr/bin/env python
"""
Novamind Digital Twin Test Migration Tool

This script migrates tests to the new directory structure based on
dependency-level analysis. It ensures proper import updates and
handles fixture references correctly.

Usage:
    python migrate_tests.py --analysis-file test_analysis_results.json
    python migrate_tests.py --analysis-file test_analysis_results.json --dry-run
    python migrate_tests.py --analysis-file test_analysis_results.json --force
"""

import os
import re
import json
import shutil
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set


class TestMigrator:
    """
    Migrates tests to their proper location based on dependency level.
    """
    
    def __init__(self, project_root: Optional[Path] = None):
        """
        Initialize the test migrator.
        
        Args:
            project_root: Root directory of the project
        """
        self.project_root = project_root or Path(__file__).resolve().parents[4]
        # Fix path to include backend directory
        self.tests_dir = self.project_root / "backend" / "app" / "tests"
        print(f"Project root: {self.project_root}")
        print(f"Tests directory: {self.tests_dir}")
        
        # Ensure destination directories exist
        for level in ["standalone", "venv", "integration"]:
            for component in ["domain", "application", "infrastructure", "api", "core"]:
                (self.tests_dir / level / component).mkdir(exist_ok=True, parents=True)
    
    def load_analysis(self, analysis_file: str) -> Dict[str, Any]:
        """
        Load test analysis results from a file.
        
        Args:
            analysis_file: Path to the analysis file
            
        Returns:
            Analysis results as a dictionary
        """
        with open(analysis_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def migrate_tests(self, 
                      analysis: Dict[str, Any], 
                      dry_run: bool = False,
                      force: bool = False) -> Tuple[int, int, int]:
        """
        Migrate tests based on analysis results.
        
        Args:
            analysis: Test analysis results
            dry_run: If True, don't actually move files
            force: If True, overwrite existing files
            
        Returns:
            Tuple of (number of tests migrated, number of errors, number of skipped)
        """
        tests = analysis.get("tests", [])
        migrated = 0
        errors = 0
        skipped = 0
        
        for test in tests:
            # Skip tests with syntax errors unless forced
            if test.get("has_syntax_error") and not force:
                print(f"Skipping file with syntax error: {test['file_path']}")
                print(f"  Error: {test.get('error_message')}")
                skipped += 1
                continue
            
            # Skip tests with unknown dependency level
            if test.get("dependency_level") == "unknown":
                print(f"Skipping file with unknown dependency level: {test['file_path']}")
                skipped += 1
                continue
            
            # Get source and destination paths
            source_path = test.get("file_path")
            
            # Fix destination path to include backend directory if needed
            dest_path_rel = test.get("destination_path", "")
            if not dest_path_rel.startswith("backend/"):
                dest_path_rel = "backend/" + dest_path_rel
                
            dest_path = os.path.join(
                str(self.project_root),
                dest_path_rel
            )
            
            # Ensure destination directory exists
            dest_dir = os.path.dirname(dest_path)
            if not os.path.exists(dest_dir):
                if not dry_run:
                    os.makedirs(dest_dir, exist_ok=True)
                print(f"Creating directory: {dest_dir}")
            
            # Check if destination file already exists
            if os.path.exists(dest_path) and not force:
                print(f"Skipping existing file: {dest_path}")
                skipped += 1
                continue
            
            # Read the source file
            try:
                with open(source_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Update imports if needed
                updated_content = self._update_imports(content, source_path, dest_path)
                
                # Write to destination
                if not dry_run:
                    with open(dest_path, 'w', encoding='utf-8') as f:
                        f.write(updated_content)
                    
                    # Create __init__.py files as needed
                    self._ensure_init_files(dest_path)
                    
                print(f"Migrated: {source_path} -> {dest_path}")
                migrated += 1
                
            except Exception as e:
                print(f"Error migrating {source_path}: {str(e)}")
                errors += 1
        
        return migrated, errors, skipped
    
    def _update_imports(self, content: str, source_path: str, dest_path: str) -> str:
        """
        Update import statements in a test file.
        
        Args:
            content: File content
            source_path: Original file path
            dest_path: Destination file path
            
        Returns:
            Updated content
        """
        # Get relative paths
        source_rel = os.path.relpath(source_path, str(self.project_root))
        dest_rel = os.path.relpath(dest_path, str(self.project_root))
        
        # Determine source and destination package paths
        source_pkg = os.path.dirname(source_rel).replace(os.path.sep, '.')
        dest_pkg = os.path.dirname(dest_rel).replace(os.path.sep, '.')
        
        # Update relative imports
        if source_pkg != dest_pkg:
            # Update from ... import ... statements
            content = self._update_from_imports(content, source_pkg, dest_pkg)
            
            # Update import ... statements
            content = self._update_direct_imports(content, source_pkg, dest_pkg)
        
        return content
    
    def _update_from_imports(self, content: str, source_pkg: str, dest_pkg: str) -> str:
        """
        Update 'from ... import ...' statements.
        
        Args:
            content: File content
            source_pkg: Original package path
            dest_pkg: Destination package path
            
        Returns:
            Updated content
        """
        # Regex to match 'from package import module'
        from_import_re = re.compile(r'from\s+([\w.]+)\s+import')
        
        # Track replacements to avoid duplicate replacements
        replacements = {}
        
        for match in from_import_re.finditer(content):
            import_pkg = match.group(1)
            
            # Skip stdlib imports
            if not import_pkg.startswith(('app', 'backend', '.')):
                continue
            
            # Handle relative imports
            if import_pkg.startswith('.'):
                # Count dots to determine relative level
                dots = len(import_pkg) - len(import_pkg.lstrip('.'))
                rel_path = import_pkg[dots:]
                
                # Calculate the new relative path
                source_parts = source_pkg.split('.')
                source_prefix = '.'.join(source_parts[:-dots]) if dots < len(source_parts) else ''
                full_path = f"{source_prefix}.{rel_path}" if rel_path else source_prefix
                
                # Map to the absolute import
                new_pkg = full_path
            else:
                # It's an absolute import, might not need changes
                new_pkg = import_pkg
            
            # Store the replacement
            full_match = match.group(0)
            new_match = f"from {new_pkg} import"
            replacements[full_match] = new_match
        
        # Apply replacements
        for old, new in replacements.items():
            content = content.replace(old, new)
        
        return content
    
    def _update_direct_imports(self, content: str, source_pkg: str, dest_pkg: str) -> str:
        """
        Update 'import ...' statements.
        
        Args:
            content: File content
            source_pkg: Original package path
            dest_pkg: Destination package path
            
        Returns:
            Updated content
        """
        # Regex to match 'import package.module'
        import_re = re.compile(r'import\s+([\w.]+)')
        
        # Track replacements to avoid duplicate replacements
        replacements = {}
        
        for match in import_re.finditer(content):
            import_pkg = match.group(1)
            
            # Skip stdlib imports
            if not import_pkg.startswith(('app', 'backend')):
                continue
            
            # Store the replacement
            full_match = match.group(0)
            new_match = f"import {import_pkg}"
            replacements[full_match] = new_match
        
        # Apply replacements
        for old, new in replacements.items():
            content = content.replace(old, new)
        
        return content
    
    def _ensure_init_files(self, dest_path: str) -> None:
        """
        Ensure __init__.py files exist in all parent directories.
        
        Args:
            dest_path: Destination file path
        """
        dest_dir = os.path.dirname(dest_path)
        current_dir = dest_dir
        
        # Create __init__.py files up to the project root
        while current_dir.startswith(str(self.project_root)):
            init_file = os.path.join(current_dir, "__init__.py")
            if not os.path.exists(init_file):
                with open(init_file, 'w', encoding='utf-8') as f:
                    f.write("# Generated by test_migrator.py\n")
                print(f"Created: {init_file}")
            
            # Move up one directory
            parent_dir = os.path.dirname(current_dir)
            if parent_dir == current_dir:  # We've reached the root
                break
            current_dir = parent_dir


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Novamind Digital Twin Test Migrator")
    
    parser.add_argument(
        "--analysis-file",
        type=str,
        required=True,
        help="Path to the test analysis results file"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without actually moving files"
    )
    
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force migration even for files with syntax errors or existing destination files"
    )
    
    return parser.parse_args()


def main():
    """Main entry point for the test migrator."""
    args = parse_args()
    
    # Load analysis
    migrator = TestMigrator()
    try:
        analysis = migrator.load_analysis(args.analysis_file)
    except Exception as e:
        print(f"Error loading analysis file: {str(e)}")
        return 1
    
    # Migrate tests
    print(f"{'DRY RUN: ' if args.dry_run else ''}Migrating tests...")
    migrated, errors, skipped = migrator.migrate_tests(
        analysis,
        dry_run=args.dry_run,
        force=args.force
    )
    
    # Print summary
    print("\nMigration summary:")
    print(f"  Migrated: {migrated}")
    print(f"  Errors: {errors}")
    print(f"  Skipped: {skipped}")
    print(f"  Total: {migrated + errors + skipped}")
    
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())