#!/usr/bin/env python3
"""
Digital Twin Refactoring Execution Script

This script executes the refactoring plan step-by-step to:
1. Create canonical directory structure
2. Move files from /refactored/ to canonical locations
3. Update imports 
4. Run tests with coverage metrics

Usage:
    python execute_refactoring_steps.py
"""

import os
import sys
import shutil
import re
import subprocess
from pathlib import Path
import time

def print_step(step_number, step_name):
    """Print a formatted step header."""
    print("\n" + "=" * 80)
    print(f"STEP {step_number}: {step_name}")
    print("=" * 80)

def create_directory_structure(base_dir):
    """Create the canonical directory structure."""
    print_step(1, "Creating canonical directory structure")
    
    # Define the directories to create
    dirs = [
        # Domain layer
        "app/domain/entities/auth",
        "app/domain/entities/digital_twin", 
        "app/domain/entities/patient",
        "app/domain/entities/analytics",
        "app/domain/exceptions",
        "app/domain/events",
        "app/domain/value_objects",
        "app/domain/repositories",
        
        # Application layer
        "app/application/interfaces",
        "app/application/use_cases/digital_twin",
        "app/application/use_cases/auth",
        "app/application/use_cases/analytics",
        
        # Infrastructure layer
        "app/infrastructure/repositories/mongodb",
        "app/infrastructure/services/trinity_stack",
        "app/infrastructure/security",
        
        # API layer
        "app/api/v1/endpoints",
        "app/api/v1/schemas",
        
        # Core layer
        "app/core/security",
        "app/core/logging",
        "app/core/errors",
        
        # Tests
        "tests/unit/domain",
        "tests/unit/application",
        "tests/integration/repositories",
        "tests/integration/api",
        "tests/e2e",
    ]
    
    # Create each directory
    for directory in dirs:
        dir_path = os.path.join(base_dir, directory)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
            print(f"Created: {directory}")
        
        # Create an __init__.py file in each directory
        init_file = os.path.join(dir_path, "__init__.py")
        if not os.path.exists(init_file):
            with open(init_file, 'w') as f:
                f.write('"""' + directory.split('/')[-1] + ' package."""\n')
            print(f"Created: {directory}/__init__.py")

def find_refactored_files(base_dir):
    """Find all files with 'refactored' in their path."""
    print_step(2, "Finding files with 'refactored' in their path")
    
    refactored_files = []
    for root, _, files in os.walk(os.path.join(base_dir, "app")):
        if "refactored" in root:
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    refactored_files.append(file_path)
    
    print(f"Found {len(refactored_files)} files with 'refactored' in their path")
    for file in refactored_files[:10]:  # Show first 10 files
        print(f"  - {os.path.relpath(file, base_dir)}")
    if len(refactored_files) > 10:
        print(f"  - ... and {len(refactored_files) - 10} more")
    
    return refactored_files

def determine_destination(file_path, base_dir):
    """Determine the canonical destination for a file."""
    # Get relative path from base_dir
    rel_path = os.path.relpath(file_path, base_dir)
    parts = rel_path.split(os.sep)
    
    # Skip 'refactored' in the path
    if "refactored" in parts:
        parts.remove("refactored")
    
    # Domain entities
    if "domain" in parts and "entities" in parts and "digital_twin" in file_path.lower():
        return os.path.join(base_dir, "app", "domain", "entities", "digital_twin", os.path.basename(file_path))
    
    # Domain repositories
    if "repository" in file_path.lower() and not "mongodb" in file_path.lower():
        return os.path.join(base_dir, "app", "domain", "repositories", os.path.basename(file_path))
    
    # Infrastructure repositories
    if "repository" in file_path.lower() and "mongodb" in file_path.lower():
        return os.path.join(base_dir, "app", "infrastructure", "repositories", "mongodb", os.path.basename(file_path))
    
    # Trinity stack services
    if "trinity" in file_path.lower() or "mental_llama" in file_path.lower() or "pat" in file_path.lower() or "xgboost" in file_path.lower():
        return os.path.join(base_dir, "app", "infrastructure", "services", "trinity_stack", os.path.basename(file_path))
    
    # Application use cases
    if "service" in file_path.lower() or "use_case" in file_path.lower() or "application" in file_path.lower():
        if "digital_twin" in file_path.lower():
            return os.path.join(base_dir, "app", "application", "use_cases", "digital_twin", os.path.basename(file_path))
        else:
            return os.path.join(base_dir, "app", "application", "use_cases", os.path.basename(file_path))
    
    # API endpoints
    if "endpoint" in file_path.lower() or "api" in file_path.lower():
        return os.path.join(base_dir, "app", "api", "v1", "endpoints", os.path.basename(file_path))
    
    # API schemas
    if "schema" in file_path.lower() or "model" in file_path.lower():
        return os.path.join(base_dir, "app", "api", "v1", "schemas", os.path.basename(file_path))
    
    # Security
    if "security" in file_path.lower() or "auth" in file_path.lower():
        return os.path.join(base_dir, "app", "core", "security", os.path.basename(file_path))
    
    # Default: keep in same directory without 'refactored'
    return os.path.join(base_dir, *parts)

def move_files(refactored_files, base_dir):
    """Move files to their canonical locations."""
    print_step(3, "Moving files to canonical locations")
    
    moved_files = {}  # Original path -> new path
    for file_path in refactored_files:
        dest_path = determine_destination(file_path, base_dir)
        
        # Create parent directories if they don't exist
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        
        # Copy the file
        shutil.copy2(file_path, dest_path)
        moved_files[file_path] = dest_path
        print(f"Moved: {os.path.relpath(file_path, base_dir)} -> {os.path.relpath(dest_path, base_dir)}")
    
    return moved_files

def create_import_mappings(moved_files, base_dir):
    """Create mappings for import statements based on moved files."""
    print_step(4, "Creating import mappings")
    
    import_mappings = {}
    for old_path, new_path in moved_files.items():
        # Convert file paths to import paths
        old_import = os.path.relpath(old_path, base_dir).replace(os.sep, ".")
        if old_import.endswith(".py"):
            old_import = old_import[:-3]
            
        new_import = os.path.relpath(new_path, base_dir).replace(os.sep, ".")
        if new_import.endswith(".py"):
            new_import = new_import[:-3]
            
        import_mappings[old_import] = new_import
        print(f"Import mapping: {old_import} -> {new_import}")
    
    return import_mappings

def update_imports(base_dir, import_mappings):
    """Update import statements in all Python files."""
    print_step(5, "Updating import statements")
    
    # Find all Python files
    python_files = []
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".py"):
                python_files.append(os.path.join(root, file))
    
    print(f"Found {len(python_files)} Python files to update")
    
    # Process each file
    updated_files = 0
    for file_path in python_files:
        with open(file_path, 'r') as f:
            content = f.read()
        
        original_content = content
        for old_import, new_import in import_mappings.items():
            # Replace imports
            pattern = re.compile(rf'from\s+{re.escape(old_import)}(\s+import|\.)') 
            content = pattern.sub(f'from {new_import}\\1', content)
            
            # Replace direct imports
            pattern = re.compile(rf'import\s+{re.escape(old_import)}([,\s])') 
            content = pattern.sub(f'import {new_import}\\1', content)
        
        if content != original_content:
            with open(file_path, 'w') as f:
                f.write(content)
            updated_files += 1
    
    print(f"Updated imports in {updated_files} files")

def run_tests_with_coverage(base_dir):
    """Run tests with coverage metrics."""
    print_step(6, "Running tests with coverage")
    
    try:
        # Change to the backend directory
        os.chdir(base_dir)
        
        # Run pytest with coverage
        cmd = ["python", "-m", "pytest", "--cov=app", "--cov-report=term", "--cov-report=html"]
        print(f"Running command: {' '.join(cmd)}")
        
        process = subprocess.run(cmd, check=False, capture_output=True, text=True)
        
        print("Test output:")
        print(process.stdout)
        
        if process.returncode != 0:
            print("Test errors:")
            print(process.stderr)
            print("Tests failed. Please fix the issues.")
        else:
            print("All tests passed!")
        
        # Look for coverage percentage in the output
        coverage_match = re.search(r'TOTAL\s+\d+\s+\d+\s+(\d+)%', process.stdout)
        if coverage_match:
            coverage = int(coverage_match.group(1))
            print(f"Coverage: {coverage}%")
            
            if coverage < 80:
                print("WARNING: Coverage is below the target of 80%")
            else:
                print("SUCCESS: Coverage meets or exceeds the 80% target")
        else:
            print("Could not determine coverage percentage")
            
    except Exception as e:
        print(f"Error running tests: {str(e)}")

def clean_up_empty_directories(base_dir):
    """Remove empty directories."""
    print_step(7, "Cleaning up empty directories")
    
    # Start with deepest directories first
    for root, dirs, files in os.walk(os.path.join(base_dir, "app"), topdown=False):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            # Check if directory is empty (no files and no subdirectories)
            if not os.listdir(dir_path):
                os.rmdir(dir_path)
                print(f"Removed empty directory: {os.path.relpath(dir_path, base_dir)}")

def main():
    """Main entry point."""
    start_time = time.time()
    
    print("\n" + "=" * 80)
    print("DIGITAL TWIN REFACTORING EXECUTION")
    print("=" * 80)
    print(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Get the base directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    
    print(f"Base directory: {base_dir}")
    
    # Execute refactoring steps
    create_directory_structure(base_dir)
    
    refactored_files = find_refactored_files(base_dir)
    if not refactored_files:
        print("No files with 'refactored' in their path found. Already refactored?")
    
    moved_files = move_files(refactored_files, base_dir)
    
    import_mappings = create_import_mappings(moved_files, base_dir)
    update_imports(base_dir, import_mappings)
    
    clean_up_empty_directories(base_dir)
    
    run_tests_with_coverage(base_dir)
    
    elapsed_time = time.time() - start_time
    print("\n" + "=" * 80)
    print("REFACTORING COMPLETED")
    print("=" * 80)
    print(f"Elapsed time: {elapsed_time:.2f} seconds")
    print(f"Files processed: {len(refactored_files)}")
    print(f"Files moved: {len(moved_files)}")
    print("\nNext steps:")
    print("1. Fix any failing tests")
    print("2. Improve test coverage if below 80%")
    print("3. Run the application and verify functionality")

if __name__ == "__main__":
    main()