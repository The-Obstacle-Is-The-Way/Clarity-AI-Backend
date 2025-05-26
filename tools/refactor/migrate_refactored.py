#!/usr/bin/env python3
"""
Migration script to move code from /refactored/ path to canonical locations.

This script:
1. Moves all files from backend/app/domain/refactored/ to their canonical locations
2. Updates import paths in all moved files
3. Removes the refactored directory if empty
"""
import os
import re
from pathlib import Path

# Base directories
BASE_DIR = Path("/Users/ray/Desktop/GITHUB/Novamind-Backend-ONLY-TWINS")
REFACTORED_DIR = BASE_DIR / "backend/app/domain/refactored"
DOMAIN_DIR = BASE_DIR / "backend/app/domain"
APP_DIR = BASE_DIR / "backend/app"

# Mapping of source directories to target directories
DIR_MAPPING = {
    REFACTORED_DIR: DOMAIN_DIR,  # Handle files directly in refactored
    REFACTORED_DIR / "entities": DOMAIN_DIR / "entities",
    REFACTORED_DIR / "entities/digital_twin": DOMAIN_DIR / "entities/digital_twin",
    REFACTORED_DIR / "entities/identity": DOMAIN_DIR / "entities/identity",
    REFACTORED_DIR / "entities/temporal": DOMAIN_DIR / "entities/temporal",
    REFACTORED_DIR / "repositories": DOMAIN_DIR / "repositories",
    REFACTORED_DIR / "services": APP_DIR / "application/services",
    REFACTORED_DIR / "services/trinity_stack": APP_DIR / "application/services/trinity_stack",
    REFACTORED_DIR / "tests": APP_DIR / "tests/domain",
    REFACTORED_DIR / "tests/integration": APP_DIR / "tests/integration",
    REFACTORED_DIR / "exceptions": DOMAIN_DIR / "exceptions",
}

# Import path substitutions
IMPORT_REPLACEMENTS = [
    (r"from app\\.domain\\.refactored\\.", "from app.domain."),
    (r"from app\\.domain\\.refactored\\.services", "from app.application.services"),
    (r"import app\\.domain\\.refactored\\.", "import app.domain."),
]


def ensure_directory_exists(path: Path) -> None:
    """Create directory if it doesn't exist."""
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {path}")


def copy_file_with_updated_imports(src_file: Path, dest_file: Path) -> Path:
    """Copy file and update imports."""
    # Create destination directory if needed
    ensure_directory_exists(dest_file.parent)

    # Read content and update imports
    with open(src_file) as f:
        content = f.read()

    # Apply all import replacements
    for pattern, replacement in IMPORT_REPLACEMENTS:
        content = re.sub(pattern, replacement, content)

    # Write updated content to destination
    with open(dest_file, "w") as f:
        f.write(content)

    print(f"Copied and updated: {src_file} -> {dest_file}")
    return dest_file


def find_target_dir(src_path: Path) -> Path | None:
    """Find the appropriate target directory for a given source path."""
    best_match = None
    max_match_len = 0

    for src_dir, target_dir in DIR_MAPPING.items():
        try:
            # Check if src_path is relative to this source directory
            if src_path.is_relative_to(src_dir):
                # Get the relative path length to find the most specific match
                rel_path = src_path.relative_to(src_dir)
                match_len = len(str(src_dir))

                # Keep track of the longest/most specific match
                if match_len > max_match_len:
                    max_match_len = match_len
                    rel_path_str = str(rel_path) if rel_path != Path() else ""
                    best_match = target_dir / rel_path_str if rel_path_str else target_dir
        except ValueError:
            # Path is not relative to this source directory
            continue

    return best_match


def process_directory(src_dir: Path, processed_files: list[Path]) -> None:
    """Process all files in source directory and subdirectories."""
    if not src_dir.exists() or not src_dir.is_dir():
        print(f"Source directory doesn't exist: {src_dir}")
        return

    # Process all Python files in this directory
    for item in src_dir.iterdir():
        if item.is_file() and item.suffix == ".py":
            # Find target directory for this file
            target_dir = find_target_dir(item.parent)
            if target_dir:
                dest_file = target_dir / item.name
                copied_file = copy_file_with_updated_imports(item, dest_file)
                processed_files.append(copied_file)
            else:
                print(f"No target mapping for file: {item}")
        elif item.is_dir():
            process_directory(item, processed_files)


def ensure_all_init_files(dir_mapping: dict[Path, Path]) -> None:
    """Ensure all target directories have __init__.py files."""
    for target_dir in dir_mapping.values():
        # Create all parent directories
        ensure_directory_exists(target_dir)

        # Create __init__.py in this directory
        init_file = target_dir / "__init__.py"
        if not init_file.exists():
            with open(init_file, "w") as f:
                f.write('"""Auto-generated during migration."""\n')
            print(f"Created __init__.py: {init_file}")


def update_imports_in_backend(processed_files: list[Path]) -> None:
    """Update imports in all Python files in the backend directory."""
    # Find all Python files in backend
    backend_dir = BASE_DIR / "backend"
    all_py_files: list[Path] = []
    for root, _, files in os.walk(backend_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = Path(root) / file
                # Skip the files we just processed
                if file_path not in processed_files:
                    all_py_files.append(file_path)

    # Update imports in all Python files
    for file_path in all_py_files:
        try:
            with open(file_path) as f:
                content = f.read()

            original_content = content
            for pattern, replacement in IMPORT_REPLACEMENTS:
                content = re.sub(pattern, replacement, content)

            # Only write if changes were made
            if content != original_content:
                with open(file_path, "w") as f:
                    f.write(content)
                print(f"Updated imports in: {file_path}")
        except Exception as e:
            print(f"Error processing {file_path}: {e}")


def main() -> None:
    """Execute the migration process."""
    print("Starting refactored code migration...")

    # First ensure all target directories exist with __init__.py files
    print("Creating target directories and __init__.py files...")
    ensure_all_init_files(DIR_MAPPING)

    processed_files: list[Path] = []

    # Process all directories in REFACTORED_DIR
    if REFACTORED_DIR.exists():
        print("Processing files...")
        process_directory(REFACTORED_DIR, processed_files)

        # Update imports in all backend files
        print("Updating imports in existing files...")
        update_imports_in_backend(processed_files)

        print(f"Migration completed. Processed {len(processed_files)} files.")

        # Don't remove the refactored directory - let's do this manually after verifying
        print(
            """
Migration completed. Please verify the following:
1. All code has been properly moved to canonical locations
2. All import paths have been updated correctly
3. The application still functions as expected

After verification, you can manually remove the refactored directory with:
rm -rf backend/app/domain/refactored
        """
        )
    else:
        print(f"Refactored directory not found: {REFACTORED_DIR}")


if __name__ == "__main__":
    main()
