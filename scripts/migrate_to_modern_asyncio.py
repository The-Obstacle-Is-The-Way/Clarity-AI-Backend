#!/usr/bin/env python3
"""
Migration script for updating asyncio tests to modern approach.

This script helps refactor test files to use the modern pytest-asyncio
decorator-based approach instead of custom event loop fixtures.

Usage:
    python scripts/migrate_to_modern_asyncio.py [--dry-run] [--path=PATH]

Options:
    --dry-run  Show changes without applying them
    --path     Specific path to process (default: app/tests)
"""

import os
import re
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Tuple


CUSTOM_EVENT_LOOP_PATTERN = re.compile(
    r'@pytest\.fixture.*\ndef event_loop\([^\)]*\):'
)

ASYNC_TEST_PATTERN = re.compile(
    r'async def (test_\w+)'
)

FIXTURE_IMPORT_PATTERN = re.compile(
    r'from app\.tests\.utils\.asyncio_helpers import'
)


def should_process_file(file_path: Path) -> bool:
    """Check if a file should be processed.
    
    Args:
        file_path: Path to the file
        
    Returns:
        bool: True if the file should be processed
    """
    # Skip if not a Python file
    if not file_path.suffix == '.py':
        return False
    
    # Skip if not a test file
    if not file_path.name.startswith('test_'):
        return False
    
    # Skip example file
    if 'examples/test_modern_asyncio.py' in str(file_path):
        return False
    
    # Check if file has async tests
    content = file_path.read_text()
    return 'async def test_' in content


def process_file(file_path: Path, dry_run: bool = False) -> Tuple[bool, List[str]]:
    """Process a file to migrate to modern asyncio approach.
    
    Args:
        file_path: Path to the file
        dry_run: If True, only show changes without applying them
        
    Returns:
        Tuple[bool, List[str]]: (was_modified, list of changes)
    """
    content = file_path.read_text()
    modified = False
    changes = []
    
    # Track lines to remove (custom event loop fixture)
    lines_to_remove = set()
    
    # Step 1: Check for imports
    if 'import asyncio' not in content:
        content = content.replace('import pytest', 'import asyncio\nimport pytest')
        modified = True
        changes.append("Added asyncio import")
    
    # Step 2: Check for helpers import
    if not FIXTURE_IMPORT_PATTERN.search(content) and 'app/tests/utils/asyncio_helpers' not in content:
        if 'import pytest' in content:
            content = content.replace(
                'import pytest', 
                'import pytest\nfrom app.tests.utils.asyncio_helpers import run_with_timeout'
            )
        else:
            content = 'import pytest\nfrom app.tests.utils.asyncio_helpers import run_with_timeout\n' + content
        modified = True
        changes.append("Added asyncio helpers import")
    
    # Step 3: Find custom event_loop fixture to remove
    lines = content.split('\n')
    in_event_loop_fixture = False
    
    for i, line in enumerate(lines):
        if CUSTOM_EVENT_LOOP_PATTERN.search(line):
            lines_to_remove.add(i)
            in_event_loop_fixture = True
            changes.append(f"Remove custom event_loop fixture starting at line {i+1}")
        elif in_event_loop_fixture:
            if line.strip() and not line.startswith(' '):
                in_event_loop_fixture = False
            else:
                lines_to_remove.add(i)
    
    # Step 4: Add the @pytest.mark.asyncio decorator to async tests
    new_lines = []
    skip_line = False
    
    for i, line in enumerate(lines):
        if i in lines_to_remove:
            skip_line = True
            continue
        
        if skip_line:
            skip_line = False
            if i not in lines_to_remove:
                new_lines.append(line)
            continue
        
        match = ASYNC_TEST_PATTERN.search(line)
        if match and '@pytest.mark.asyncio' not in lines[i-1]:
            # Add the decorator
            indent = ' ' * (len(line) - len(line.lstrip()))
            new_lines.append(f"{indent}@pytest.mark.asyncio")
            changes.append(f"Added @pytest.mark.asyncio decorator to {match.group(1)} at line {i+1}")
            modified = True
        
        new_lines.append(line)
    
    # Apply changes if modified
    if modified and not dry_run:
        file_path.write_text('\n'.join(new_lines))
    
    return modified, changes


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description='Migrate asyncio tests to modern approach')
    parser.add_argument('--dry-run', action='store_true', help='Show changes without applying them')
    parser.add_argument('--path', type=str, default='app/tests', help='Path to process')
    args = parser.parse_args()
    
    base_path = Path(args.path)
    if not base_path.exists():
        print(f"Path {args.path} does not exist")
        sys.exit(1)
    
    modified_count = 0
    processed_count = 0
    
    if base_path.is_file():
        if should_process_file(base_path):
            modified, changes = process_file(base_path, args.dry_run)
            if modified:
                print(f"Modified {base_path}:")
                for change in changes:
                    print(f"  - {change}")
                modified_count += 1
            processed_count += 1
    else:
        for root, _, files in os.walk(base_path):
            for file in files:
                file_path = Path(root) / file
                if should_process_file(file_path):
                    modified, changes = process_file(file_path, args.dry_run)
                    if modified:
                        print(f"Modified {file_path}:")
                        for change in changes:
                            print(f"  - {change}")
                        modified_count += 1
                    processed_count += 1
    
    print(f"\nProcessed {processed_count} files, modified {modified_count} files")
    if args.dry_run:
        print("This was a dry run. No changes were applied.")


if __name__ == '__main__':
    main() 