#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test File Syntax Fixer for Identified Files

This script targets specific syntax errors in identified test files based on the error report.
It fixes:
1. Missing colons after class/function definitions
2. Indentation issues in common test patterns
3. Tests that need specific structural fixes

Usage:
    python scripts/test/tools/fix_specific_test_files.py
"""

import os
import re
import sys
import ast
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("test_file_fixer")

# List of files with identified issues based on error reports
PROBLEMATIC_FILES = [
    "app/tests/unit/test_mentallama_service.py",
    "app/tests/unit/core/services/ml/pat/test_mock_pat.py",
    "app/tests/unit/services/ml/pat/test_pat_service.py",
    "app/tests/unit/infrastructure/ml/pharmacogenomics/test_model_service_pgx.py",
    "app/tests/unit/infrastructure/ml/pharmacogenomics/test_treatment_model.py",
    "app/tests/unit/infrastructure/ml/symptom_forecasting/test_model_service_symptom.py",
    "app/tests/unit/infrastructure/ml/symptom_forecasting/test_ensemble_model.py",
    "app/tests/unit/infrastructure/ml/symptom_forecasting/test_transformer_model.py",
    "app/tests/unit/infrastructure/ml/biometric_correlation/test_model_service.py",
    "app/tests/security/test_log_sanitization.py",
]


# Project root path
def find_project_root() -> str:
    """Find the root directory of the project"""
    current_dir = os.getcwd()

    # Keep going up until we find the 'backend' directory or reach the root
    while current_dir != os.path.dirname(current_dir):  # Stop at the root directory
        if os.path.exists(os.path.join(current_dir, "backend")):
            return os.path.join(current_dir, "backend")
        current_dir = os.path.dirname(current_dir)

    # Fallback to current directory if backend not found
    return os.getcwd()


# Fix functions for different types of problems
def fix_missing_colon(content: str) -> str:
    """Fix missing colons after function/class declarations"""
    lines = content.splitlines()
    fixed_lines = []

    # Common patterns for Python declarations
    class_pattern = re.compile(r"^\s*class\s+\w+[\w\s(),]*$")
    func_pattern = re.compile(r"^\s*def\s+\w+[\w\s(),=\[\]\'\"*]*$")

    for i, line in enumerate(lines):
        if class_pattern.match(line) or func_pattern.match(line):
            # Line is a function or class def without a colon
            fixed_lines.append(line + ":")
            logger.info(f"Added missing colon at line {i+1}")
        else:
            fixed_lines.append(line)

    return "\n".join(fixed_lines)


def fix_indentation(content: str) -> str:
    """Fix indentation issues after class/function declarations"""
    lines = content.splitlines()
    fixed_lines = []

    i = 0
    while i < len(lines):
        line = lines[i]
        fixed_lines.append(line)

        # Check if this line needs indentation in the next line
        if line.strip().endswith(":"):
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                # Skip empty lines and comments
                j = i + 1
                while j < len(lines) and (
                    not lines[j].strip() or lines[j].strip().startswith("#")
                ):
                    fixed_lines.append(lines[j])
                    j += 1

                # If we found a non-empty, non-comment line that needs indentation
                if (
                    j < len(lines)
                    and not lines[j].startswith(" ")
                    and not lines[j].startswith("\t")
                ):
                    fixed_lines.append("    " + lines[j])
                    logger.info(f"Fixed indentation at line {j+1}")
                    i = j  # Skip the line we just fixed

        i += 1

    return "\n".join(fixed_lines)


def fix_specific_file(file_path: str, project_root: str) -> bool:
    """Apply specific fixes to a test file based on known issues"""
    rel_path = os.path.relpath(file_path, project_root)
    logger.info(f"Attempting to fix: {rel_path}")

    try:
        # Read the file
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check if it already has valid syntax
        try:
            ast.parse(content)
            logger.info(f"File already has valid syntax: {rel_path}")
            return True
        except SyntaxError as e:
            logger.info(f"Found syntax error at line {e.lineno}: {e.msg}")

        # Apply fixes
        original_content = content
        content = fix_missing_colon(content)
        content = fix_indentation(content)

        # Write back if changes were made
        if content != original_content:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            # Verify if the syntax is now correct
            try:
                ast.parse(content)
                logger.info(f"Successfully fixed: {rel_path}")
                return True
            except SyntaxError as e:
                logger.warning(
                    f"File still has syntax errors after fix at line {e.lineno}: {e.msg}"
                )
                return False
        else:
            logger.info(f"No changes needed for: {rel_path}")
            return True

    except Exception as e:
        logger.error(f"Error fixing {rel_path}: {str(e)}")
        return False


def fix_mentallama_service(file_path: str) -> bool:
    """Special fixes for test_mentallama_service.py"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Line 18 is reported to have a missing colon (expected ':')
        if len(lines) >= 18 and "class TestMentalLamaService" in lines[17]:
            lines[17] = lines[17].rstrip() + ":\n"
            logger.info("Fixed TestMentalLamaService class definition")

        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # Verify the fix worked
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        try:
            ast.parse(content)
            logger.info("Successfully fixed test_mentallama_service.py")
            return True
        except SyntaxError:
            logger.warning("Failed to fix test_mentallama_service.py")
            return False

    except Exception as e:
        logger.error(f"Error fixing test_mentallama_service.py: {str(e)}")
        return False


def fix_mock_pat(file_path: str) -> bool:
    """Special fixes for test_mock_pat.py"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Line 25 is reported to have expected ':'
        if len(lines) >= 25:
            lines[24] = lines[24].rstrip() + ":\n"
            logger.info("Fixed test_mock_pat.py line 25")

        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # Verify
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        try:
            ast.parse(content)
            logger.info("Successfully fixed test_mock_pat.py")
            return True
        except SyntaxError:
            logger.warning("Failed to fix test_mock_pat.py")
            return False

    except Exception as e:
        logger.error(f"Error fixing test_mock_pat.py: {str(e)}")
        return False


def main():
    """Main function to run the script"""
    project_root = find_project_root()
    logger.info(f"Project root: {project_root}")

    fixed_count = 0
    failed_count = 0

    # Process each problematic file
    for file_path in PROBLEMATIC_FILES:
        full_path = os.path.join(project_root, file_path)

        if not os.path.exists(full_path):
            logger.warning(f"File not found: {file_path}")
            continue

        # Apply file-specific fixes for known problematic files
        if "test_mentallama_service.py" in file_path:
            success = fix_mentallama_service(full_path)
        elif "test_mock_pat.py" in file_path:
            success = fix_mock_pat(full_path)
        else:
            # Apply general fixes
            success = fix_specific_file(full_path, project_root)

        if success:
            fixed_count += 1
        else:
            failed_count += 1

    # Report results
    logger.info("\nFix Summary:")
    logger.info(f"Successfully fixed: {fixed_count} files")
    logger.info(f"Failed to fix: {failed_count} files")

    if failed_count > 0:
        logger.info("Some files still need manual fixes.")
        return 1
    else:
        logger.info("All targeted files were fixed successfully.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
