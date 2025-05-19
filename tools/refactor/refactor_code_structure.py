#!/usr/bin/env python3
"""
Refactoring Script for Novamind Digital Twin Platform

This script refactors the code structure to follow clean architecture principles,
eliminating legacy code paths (especially /refactored/ paths) and moving files
to their canonical locations.

Usage:
    python refactor_code_structure.py [--dry-run]

Options:
    --dry-run  Show what would be done without making changes
"""

import os
import sys
import re
import shutil
from pathlib import Path
from enum import Enum
import argparse


class Layer(Enum):
    """Clean architecture layers."""

    DOMAIN = "domain"
    APPLICATION = "application"
    INFRASTRUCTURE = "infrastructure"
    API = "api"
    CORE = "core"
    TESTS = "tests"


class RefactoringStrategy:
    """Base class for refactoring strategies."""

    def __init__(self, base_dir, dry_run=False):
        self.base_dir = Path(base_dir)
        self.dry_run = dry_run
        self.app_dir = self.base_dir / "app"

    def create_directories(self):
        """Create necessary directories for clean architecture."""
        directories = [
            # Domain layer
            self.app_dir / Layer.DOMAIN.value / "entities" / "auth",
            self.app_dir / Layer.DOMAIN.value / "entities" / "digital_twin",
            self.app_dir / Layer.DOMAIN.value / "entities" / "patient",
            self.app_dir / Layer.DOMAIN.value / "entities" / "analytics",
            self.app_dir / Layer.DOMAIN.value / "exceptions",
            self.app_dir / Layer.DOMAIN.value / "events",
            self.app_dir / Layer.DOMAIN.value / "value_objects",
            self.app_dir / Layer.DOMAIN.value / "repositories",
            # Application layer
            self.app_dir / Layer.APPLICATION.value / "interfaces",
            self.app_dir / Layer.APPLICATION.value / "use_cases" / "digital_twin",
            self.app_dir / Layer.APPLICATION.value / "use_cases" / "auth",
            self.app_dir / Layer.APPLICATION.value / "use_cases" / "analytics",
            # Infrastructure layer
            self.app_dir / Layer.INFRASTRUCTURE.value / "repositories" / "mongodb",
            self.app_dir / Layer.INFRASTRUCTURE.value / "services" / "trinity_stack",
            self.app_dir / Layer.INFRASTRUCTURE.value / "security",
            # API layer
            self.app_dir / Layer.API.value / "v1" / "endpoints",
            self.app_dir / Layer.API.value / "v1" / "schemas",
            # Core layer
            self.app_dir / Layer.CORE.value / "security",
            self.app_dir / Layer.CORE.value / "logging",
            self.app_dir / Layer.CORE.value / "errors",
            # Tests
            self.base_dir / Layer.TESTS.value / "unit" / "domain",
            self.base_dir / Layer.TESTS.value / "unit" / "application",
            self.base_dir / Layer.TESTS.value / "integration" / "repositories",
            self.base_dir / Layer.TESTS.value / "integration" / "api",
            self.base_dir / Layer.TESTS.value / "e2e",
        ]

        for directory in directories:
            if not directory.exists():
                if self.dry_run:
                    print(f"Would create directory: {directory}")
                else:
                    print(f"Creating directory: {directory}")
                    directory.mkdir(parents=True, exist_ok=True)

    def find_files_to_refactor(self):
        """Find files that need to be refactored."""
        all_files = []

        # Find all Python files in app directory
        for root, _, files in os.walk(self.app_dir):
            root_path = Path(root)
            for file in files:
                if file.endswith(".py"):
                    file_path = root_path / file
                    all_files.append(file_path)

        # Filter files in refactored paths
        refactored_files = [f for f in all_files if "refactored" in str(f)]

        return refactored_files

    def get_destination_path(self, source_path):
        """Determine destination path for a file based on clean architecture."""
        relative_path = source_path.relative_to(self.app_dir)
        path_parts = list(relative_path.parts)

        # Skip 'refactored' in path
        if "refactored" in path_parts:
            path_parts.remove("refactored")

        # Handle domain layer files
        if "entities" in path_parts and path_parts[0] == "domain":
            # Already in correct layer, just remove 'refactored'
            return self.app_dir.joinpath(*path_parts)

        # Handle digital twin specific files
        if "digital_twin" in path_parts[-1]:
            if "repository" in path_parts[-1].lower():
                # Repository interface goes to domain/repositories
                return self.app_dir / "domain" / "repositories" / path_parts[-1]
            elif "service" in path_parts[-1].lower():
                # Service goes to application/use_cases/digital_twin
                return (
                    self.app_dir
                    / "application"
                    / "use_cases"
                    / "digital_twin"
                    / path_parts[-1]
                )
            else:
                # Entity goes to domain/entities/digital_twin
                return (
                    self.app_dir
                    / "domain"
                    / "entities"
                    / "digital_twin"
                    / path_parts[-1]
                )

        # Handle infrastructure implementations
        if "repositories" in path_parts and "mongodb" in str(source_path).lower():
            return (
                self.app_dir
                / "infrastructure"
                / "repositories"
                / "mongodb"
                / path_parts[-1]
            )

        # Handle trinity stack services
        if "trinity_stack" in path_parts:
            return (
                self.app_dir
                / "infrastructure"
                / "services"
                / "trinity_stack"
                / path_parts[-1]
            )

        # For tests
        if "tests" in path_parts:
            if "domain" in str(source_path).lower():
                return self.base_dir / "tests" / "unit" / "domain" / path_parts[-1]
            elif (
                "application" in str(source_path).lower()
                or "service" in str(source_path).lower()
            ):
                return self.base_dir / "tests" / "unit" / "application" / path_parts[-1]
            elif "repository" in str(source_path).lower():
                return (
                    self.base_dir
                    / "tests"
                    / "integration"
                    / "repositories"
                    / path_parts[-1]
                )
            elif (
                "api" in str(source_path).lower()
                or "endpoint" in str(source_path).lower()
            ):
                return self.base_dir / "tests" / "integration" / "api" / path_parts[-1]
            else:
                return self.base_dir / "tests" / "unit" / path_parts[-1]

        # Default: keep in same directory but without 'refactored'
        return self.app_dir.joinpath(*path_parts)

    def update_imports(self, file_path, import_mappings):
        """Update import statements in a file based on new file locations."""
        if self.dry_run:
            print(f"Would update imports in: {file_path}")
            return

        with open(file_path, "r") as file:
            content = file.read()

        for old_import, new_import in import_mappings.items():
            # Replace imports
            pattern = re.compile(rf"from\s+{re.escape(old_import)}(\s+import|\.)")
            content = pattern.sub(f"from {new_import}\\1", content)

            # Replace direct imports
            pattern = re.compile(rf"import\s+{re.escape(old_import)}([,\s])")
            content = pattern.sub(f"import {new_import}\\1", content)

        with open(file_path, "w") as file:
            file.write(content)

    def move_file(self, source, destination):
        """Move a file to its new location and ensure parent directories exist."""
        if self.dry_run:
            print(f"Would move: {source} -> {destination}")
            return

        # Ensure parent directory exists
        destination.parent.mkdir(parents=True, exist_ok=True)

        # Create empty __init__.py files in all parent directories if not exist
        path_parts = list(destination.relative_to(self.base_dir).parts)
        current_path = self.base_dir
        for part in path_parts[:-1]:  # Exclude the file itself
            current_path = current_path / part
            init_file = current_path / "__init__.py"
            if not init_file.exists():
                with open(init_file, "w") as f:
                    f.write('"""' + part + ' package."""\n')

        # Move the file
        print(f"Moving: {source} -> {destination}")
        shutil.copy2(source, destination)

    def create_import_mappings(self, files_moved):
        """Create mappings for import statements based on file moves."""
        import_mappings = {}

        for source, dest in files_moved.items():
            # Convert file paths to import paths
            source_import = (
                str(source.relative_to(self.base_dir))
                .replace("/", ".")
                .replace("\\", ".")
            )
            if source_import.endswith(".py"):
                source_import = source_import[:-3]

            dest_import = (
                str(dest.relative_to(self.base_dir))
                .replace("/", ".")
                .replace("\\", ".")
            )
            if dest_import.endswith(".py"):
                dest_import = dest_import[:-3]

            import_mappings[source_import] = dest_import

        return import_mappings

    def delete_empty_directories(self):
        """Delete empty directories after moving files."""
        if self.dry_run:
            print("Would delete empty directories")
            return

        # Start with deepest directories first
        for root, dirs, files in os.walk(self.app_dir, topdown=False):
            for dir_name in dirs:
                dir_path = Path(root) / dir_name
                # Check if directory is empty (no files and no subdirectories)
                if not any(dir_path.iterdir()):
                    print(f"Removing empty directory: {dir_path}")
                    dir_path.rmdir()

    def execute(self):
        """Execute the refactoring strategy."""
        # Create clean architecture directory structure
        self.create_directories()

        # Find files to refactor
        files_to_refactor = self.find_files_to_refactor()
        print(f"Found {len(files_to_refactor)} files to refactor")

        # Determine destination for each file
        files_to_move = {}
        for file_path in files_to_refactor:
            dest_path = self.get_destination_path(file_path)
            files_to_move[file_path] = dest_path

        # Move files
        for source, destination in files_to_move.items():
            self.move_file(source, destination)

        # Create import mappings
        import_mappings = self.create_import_mappings(files_to_move)

        # Update imports in all Python files
        if not self.dry_run:
            all_py_files = []
            for root, _, files in os.walk(self.base_dir):
                for file in files:
                    if file.endswith(".py"):
                        all_py_files.append(Path(root) / file)

            for file_path in all_py_files:
                self.update_imports(file_path, import_mappings)

        # Delete empty directories
        self.delete_empty_directories()

        print("Refactoring completed successfully!")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Refactor code structure to follow clean architecture"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )
    args = parser.parse_args()

    # Get backend directory
    script_dir = Path(__file__).parent
    backend_dir = script_dir.parent

    print(f"Starting refactoring of {backend_dir}")

    if args.dry_run:
        print("Running in dry-run mode - no changes will be made")

    strategy = RefactoringStrategy(backend_dir, args.dry_run)
    strategy.execute()

    print("\nNext steps:")
    print("1. Resolve any import errors manually")
    print("2. Run the test suite to verify all functionality")
    print("3. Review the refactored structure for any adjustments needed")


if __name__ == "__main__":
    main()
