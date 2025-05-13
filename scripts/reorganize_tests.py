#!/usr/bin/env python
"""
Test Organization Helper Script

This script helps with test organization tasks:
1. Identify duplicate/redundant test files
2. Find test files that aren't following naming conventions
3. Find empty test directories
4. Check test coverage by layer
5. Move tests to the correct location based on clean architecture principles

Usage:
    python scripts/reorganize_tests.py [action]

Actions:
    check       - Check for organization issues
    move        - Move tests to their proper locations (interactive)
    create-dirs - Create directory structure for clean architecture tests
"""

import os
import re
import sys
import shutil
from typing import List, Dict, Tuple, Set
from pathlib import Path


# Configuration
TEST_ROOT = Path("app/tests")
INTEGRATION_ROOT = TEST_ROOT / "integration"
UNIT_ROOT = TEST_ROOT / "unit"

# Clean architecture layers
LAYERS = ["api", "application", "domain", "infrastructure", "core"]

# API version directories
API_VERSIONS = ["v1"]

# Expected patterns for test files
TEST_FILE_PATTERN = re.compile(r"^test_.*\.py$")


def create_directory_structure() -> None:
    """Create the directory structure for clean architecture tests."""
    # Integration test structure
    for layer in LAYERS:
        layer_dir = INTEGRATION_ROOT / layer
        os.makedirs(layer_dir, exist_ok=True)
        # Create __init__.py
        init_file = layer_dir / "__init__.py"
        if not init_file.exists():
            init_file.touch()
        
        # Special handling for API layer
        if layer == "api":
            for version in API_VERSIONS:
                version_dir = layer_dir / version
                endpoints_dir = version_dir / "endpoints"
                os.makedirs(endpoints_dir, exist_ok=True)
                
                # Create __init__.py files
                (version_dir / "__init__.py").touch(exist_ok=True)
                (endpoints_dir / "__init__.py").touch(exist_ok=True)
                
    # Create conftest.py if it doesn't exist
    conftest_file = INTEGRATION_ROOT / "conftest.py"
    if not conftest_file.exists():
        with open(conftest_file, "w") as f:
            f.write('"""Integration Test Fixtures\n\nThis file contains fixtures for integration tests.\n"""\n\nimport pytest\n')
    
    print("✅ Created clean architecture test directory structure")


def find_test_files() -> Dict[str, List[Path]]:
    """Find all test files organized by layer."""
    result: Dict[str, List[Path]] = {layer: [] for layer in LAYERS}
    result["other"] = []
    
    for root, _, files in os.walk(INTEGRATION_ROOT):
        for file in files:
            if not file.startswith("test_") or not file.endswith(".py"):
                continue
                
            file_path = Path(root) / file
            rel_path = file_path.relative_to(INTEGRATION_ROOT)
            
            # Determine which layer this belongs to
            layer_match = False
            for layer in LAYERS:
                if str(rel_path).startswith(layer + "/"):
                    result[layer].append(file_path)
                    layer_match = True
                    break
                    
            if not layer_match:
                result["other"].append(file_path)
                
    return result


def find_duplicate_tests() -> List[Tuple[Path, Path]]:
    """Find potentially duplicate test files based on naming similarity."""
    test_files = []
    duplicates = []
    
    # Get all test files
    for root, _, files in os.walk(INTEGRATION_ROOT):
        for file in files:
            if file.startswith("test_") and file.endswith(".py"):
                test_files.append(Path(root) / file)
    
    # Compare files by name without _integration or _int suffixes
    name_to_files: Dict[str, List[Path]] = {}
    for file_path in test_files:
        # Remove _integration, _int, etc. suffixes for comparison
        base_name = file_path.name
        base_name = re.sub(r"_integration|_int", "", base_name)
        
        if base_name not in name_to_files:
            name_to_files[base_name] = []
        name_to_files[base_name].append(file_path)
    
    # Find duplicates
    for base_name, files in name_to_files.items():
        if len(files) > 1:
            # We have potential duplicates
            for i in range(len(files)):
                for j in range(i+1, len(files)):
                    duplicates.append((files[i], files[j]))
    
    return duplicates


def find_empty_directories() -> List[Path]:
    """Find empty test directories (no test files)."""
    empty_dirs = []
    
    for root, dirs, files in os.walk(INTEGRATION_ROOT):
        # Check if there are any test files
        has_test_files = any(file.startswith("test_") and file.endswith(".py") for file in files)
        
        # If no test files and no subdirectories, it's empty
        if not has_test_files and not dirs and root != str(INTEGRATION_ROOT):
            empty_dirs.append(Path(root))
    
    return empty_dirs


def check_naming_conventions() -> List[Path]:
    """Check for test files not following naming conventions."""
    non_compliant = []
    
    for root, _, files in os.walk(INTEGRATION_ROOT):
        for file in files:
            if file.endswith(".py") and not file.startswith("__") and not file.startswith("test_"):
                non_compliant.append(Path(root) / file)
    
    return non_compliant


def check_organization() -> None:
    """Check for test organization issues."""
    duplicates = find_duplicate_tests()
    empty_dirs = find_empty_directories()
    non_compliant = check_naming_conventions()
    
    if duplicates:
        print("⚠️ Potential duplicate test files:")
        for file1, file2 in duplicates:
            print(f"  - {file1.relative_to(TEST_ROOT)} and {file2.relative_to(TEST_ROOT)}")
        print()
    
    if empty_dirs:
        print("⚠️ Empty test directories:")
        for dir_path in empty_dirs:
            print(f"  - {dir_path.relative_to(TEST_ROOT)}")
        print()
    
    if non_compliant:
        print("⚠️ Files not following naming conventions:")
        for file_path in non_compliant:
            print(f"  - {file_path.relative_to(TEST_ROOT)}")
        print()
    
    if not duplicates and not empty_dirs and not non_compliant:
        print("✅ No test organization issues found!")


def show_test_summary() -> None:
    """Show a summary of test files by layer."""
    test_files = find_test_files()
    
    print("📊 Test Files Summary:")
    for layer, files in test_files.items():
        print(f"  - {layer.capitalize()}: {len(files)} tests")
    
    print(f"\nTotal: {sum(len(files) for files in test_files.values())} test files")


def main() -> None:
    """Main entry point."""
    if len(sys.argv) < 2:
        print(__doc__)
        return
    
    action = sys.argv[1]
    
    if action == "check":
        check_organization()
        show_test_summary()
    elif action == "create-dirs":
        create_directory_structure()
    elif action == "move":
        print("Interactive move feature is not implemented yet.")
    else:
        print(f"Unknown action: {action}")
        print(__doc__)


if __name__ == "__main__":
    main() 