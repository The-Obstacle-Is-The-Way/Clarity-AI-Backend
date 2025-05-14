#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Standalone Test Candidate Identifier for Novamind Backend.

This script analyzes existing unit tests to identify those that could 
potentially be moved to the standalone test directory because they have 
minimal or no external dependencies.

It helps with the incremental migration of tests to the proper dependency
level structure, supporting a more efficient CI/CD pipeline.

Usage:
    python identify_standalone_candidates.py [--migrate] [--verbose]
    
Options:
    --migrate: Attempt to migrate identified tests to standalone directory
    --verbose: Show detailed analysis for each test file
"""

import argparse
import ast
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional


# Import patterns that indicate standalone eligibility
STANDALONE_IMPORTS = {
    # Standard library imports are standalone-friendly
    "re", "os", "sys", "json", "time", "datetime", "uuid", "enum",
    "typing", "collections", "math", "random", "functools", "itertools",
    "logging", "argparse", "pathlib", "io", "tempfile", 
    
    # Testing imports are standalone-friendly
    "pytest", "unittest", "mock",
    
    # Core domain imports might be standalone-friendly
    "app.domain", "app.core.utils",
}

# Patterns that indicate NON-standalone eligibility
NON_STANDALONE_IMPORTS = {
    # External services
    "app.infrastructure.database", "app.infrastructure.repositories",
    "asyncpg", "sqlalchemy", "redis", "motor", "httpx", "requests",
    
    # Framework dependencies
    "fastapi", "starlette",
}


def find_test_files(directory: str = "app/tests/unit") -> List[str]:
    """Find all test files in the given directory."""
    test_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.startswith("test_") and file.endswith(".py"):
                test_files.append(os.path.join(root, file))
    return test_files


def analyze_imports(file_path: str) -> Tuple[Set[str], bool]:
    """
    Analyze a file for import statements to determine standalone eligibility.
    
    Returns:
        Tuple of (imported_modules, is_standalone_eligible)
    """
    imported_modules = set()
    has_standalone_marker = False
    has_non_standalone_dependencies = False
    
    try:
        with open(file_path, "r") as f:
            file_content = f.read()
            
        # Check if already marked as standalone
        if re.search(r"@pytest\.mark\.standalone", file_content):
            has_standalone_marker = True
            
        tree = ast.parse(file_content)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imported_modules.add(name.name.split(".")[0])  # Get top-level module
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module_path = node.module
                    imported_modules.add(module_path.split(".")[0])  # Get top-level module
                    
                    # Check for non-standalone imports
                    for pattern in NON_STANDALONE_IMPORTS:
                        if module_path.startswith(pattern):
                            has_non_standalone_dependencies = True
    
    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")
        return imported_modules, False
    
    # Check if all imports are standalone-friendly
    is_standalone_eligible = not has_non_standalone_dependencies
    
    return imported_modules, is_standalone_eligible or has_standalone_marker


def migrate_test_to_standalone(source_path: str, dry_run: bool = True) -> bool:
    """
    Migrate a test file to the standalone directory.
    
    Args:
        source_path: Path to the test file
        dry_run: If True, only print what would be done
        
    Returns:
        bool: True if migration successful or would be successful, False otherwise
    """
    # Determine destination path
    test_file = os.path.basename(source_path)
    dest_path = os.path.join("app/tests/standalone", test_file)
    
    # Ensure destination directory exists
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    
    # Check if test already exists in standalone directory
    if os.path.exists(dest_path):
        print(f"Error: Test already exists at {dest_path}")
        return False
    
    # Read source file content
    try:
        with open(source_path, "r") as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {source_path}: {e}")
        return False
    
    # Add standalone marker if not present
    if not re.search(r"@pytest\.mark\.standalone", content):
        content = re.sub(
            r"(\s*def\s+test_\w+)",
            r"\n@pytest.mark.standalone\1",
            content
        )
        
        # Ensure pytest is imported
        if "import pytest" not in content:
            # Find the right spot after imports
            import_section_end = 0
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if (line.startswith("import ") or line.startswith("from ")) and i > import_section_end:
                    import_section_end = i
            
            if import_section_end > 0:
                # Insert pytest import after last import
                lines.insert(import_section_end + 1, "import pytest")
                content = "\n".join(lines)
            else:
                # Insert at top if no imports found
                content = "import pytest\n\n" + content
    
    if dry_run:
        print(f"Would migrate {source_path} -> {dest_path}")
        return True
    
    # Write to destination
    try:
        with open(dest_path, "w") as f:
            f.write(content)
        print(f"Successfully migrated {source_path} -> {dest_path}")
        return True
    except Exception as e:
        print(f"Error writing to {dest_path}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Identify standalone test candidates")
    parser.add_argument("--migrate", action="store_true", help="Migrate identified tests")
    parser.add_argument("--verbose", action="store_true", help="Show detailed analysis")
    args = parser.parse_args()
    
    # Ensure we're in the backend directory
    current_dir = os.path.basename(os.getcwd())
    if current_dir != "backend":
        if os.path.exists("backend"):
            os.chdir("backend")
        else:
            print("Error: Script must be run from the backend directory or its parent")
            sys.exit(1)
    
    # Find test files
    unit_test_files = find_test_files("app/tests/unit")
    
    standalone_candidates = []
    
    # Analyze each test file
    for file_path in unit_test_files:
        imported_modules, is_standalone_eligible = analyze_imports(file_path)
        
        if args.verbose:
            eligibility = "ELIGIBLE" if is_standalone_eligible else "NOT ELIGIBLE"
            print(f"{file_path}: {eligibility}")
            if imported_modules:
                print(f"  Imports: {', '.join(sorted(imported_modules))}")
            print()
            
        if is_standalone_eligible:
            standalone_candidates.append(file_path)
    
    # Print summary
    print(f"\nFound {len(standalone_candidates)} standalone candidates out of {len(unit_test_files)} unit tests")
    
    if standalone_candidates:
        print("\nStandalone candidates:")
        for candidate in standalone_candidates:
            print(f"  {candidate}")
        
        if args.migrate:
            print("\nMigrating standalone candidates...")
            migrated_count = 0
            for candidate in standalone_candidates:
                if migrate_test_to_standalone(candidate, dry_run=False):
                    migrated_count += 1
            
            print(f"\nSuccessfully migrated {migrated_count} tests to standalone directory")
            
            if migrated_count < len(standalone_candidates):
                print(f"Failed to migrate {len(standalone_candidates) - migrated_count} tests")


if __name__ == "__main__":
    main()