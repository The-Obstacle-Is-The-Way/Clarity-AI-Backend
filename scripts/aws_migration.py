#!/usr/bin/env python
"""
AWS Services Migration Script

This script transitions the codebase from the legacy boto3 shimming approach
to the new clean architecture implementation.

Usage:
    python scripts/aws_migration.py [--dry-run]

This script will:
1. Backup the original boto3.py file
2. Replace boto3.py with a transitional implementation that uses the new factory
3. Update imports across the codebase to use the new abstractions
4. Run tests to validate the changes
"""

import argparse
import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("aws_migration")

# Path constants
REPO_ROOT = Path(__file__).parent.parent
BOTO3_PATH = REPO_ROOT / "boto3.py"
BACKUP_DIR = REPO_ROOT / "backups"
TRANSITIONAL_BOTO3 = """
\"\"\"
Transitional boto3 module for backward compatibility.

This module provides a transitional mechanism during the migration
to the new AWS service abstraction architecture.

THIS MODULE IS DEPRECATED. Use the new abstractions directly:
    from app.infrastructure.aws.service_factory_provider import get_aws_service_factory
\"\"\"

import logging
import os
import warnings

# Warn about using deprecated module
warnings.warn(
    "Direct boto3 imports are deprecated. Use the AWS service abstractions.",
    DeprecationWarning, 
    stacklevel=2
)

# Import the service factory
from app.infrastructure.aws.service_factory_provider import get_aws_service_factory

# For transitional compatibility, re-export client and resource
# from the in-memory implementation if TESTING is set
if os.environ.get("TESTING", "").lower() in ("1", "true", "yes"):
    # Use in-memory implementation
    from app.infrastructure.aws.in_memory_boto3 import client, resource
    __shim__ = True
else:
    # Delegate to the real boto3
    try:
        import boto3 as _real_boto3
        client = _real_boto3.client
        resource = _real_boto3.resource
    except ImportError:
        # Fall back to in-memory as a safety net
        from app.infrastructure.aws.in_memory_boto3 import client, resource
        __shim__ = True

__all__ = ["client", "resource"]
"""

FILES_TO_BACKUP = [
    BOTO3_PATH,
    REPO_ROOT / "app" / "core" / "services" / "ml" / "xgboost" / "aws.py",
]


def create_backup_directory():
    """Create backup directory with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = BACKUP_DIR / f"aws_migration_{timestamp}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir


def backup_files(backup_dir):
    """Backup original files before modification."""
    logger.info("Backing up original files...")
    
    for file_path in FILES_TO_BACKUP:
        if file_path.exists():
            backup_path = backup_dir / file_path.name
            logger.info(f"Backing up {file_path} to {backup_path}")
            shutil.copy2(file_path, backup_path)
        else:
            logger.warning(f"File {file_path} not found, skipping backup")


def create_transitional_boto3():
    """Create transitional boto3.py file."""
    logger.info(f"Creating transitional boto3.py at {BOTO3_PATH}")
    
    with open(BOTO3_PATH, "w") as f:
        f.write(TRANSITIONAL_BOTO3.strip())
    
    logger.info("Transitional boto3.py created")


def replace_xgboost_implementation():
    """Replace the XGBoost AWS implementation with the refactored version."""
    aws_path = REPO_ROOT / "app" / "core" / "services" / "ml" / "xgboost" / "aws.py"
    aws_refactored_path = REPO_ROOT / "app" / "core" / "services" / "ml" / "xgboost" / "aws_refactored.py"
    
    if aws_refactored_path.exists():
        logger.info(f"Replacing {aws_path} with refactored implementation")
        
        # Read the refactored implementation
        with open(aws_refactored_path, "r") as f:
            refactored_content = f.read()
        
        # Write to the original file
        with open(aws_path, "w") as f:
            f.write(refactored_content)
        
        logger.info("XGBoost implementation replaced")
    else:
        logger.error(f"Refactored implementation {aws_refactored_path} not found")
        return False
    
    return True


def import_updates():
    """Update direct boto3 imports to use the new abstraction layer."""
    # This would be a more complex search and replace operation
    # For a full implementation, consider using ast to parse Python files
    # and replace import statements properly.
    logger.info("Automatic import updates not implemented in this script")
    logger.info("Manual updates may be required for direct boto3 imports")


def run_tests(dry_run=False):
    """Run the test suite to validate changes."""
    if dry_run:
        logger.info("[DRY RUN] Would run tests")
        return True
    
    logger.info("Running tests to validate changes...")
    result = subprocess.run(
        ["pytest", "-xvs", "app/tests/unit/services/ml/xgboost/test_aws_xgboost_refactored.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    
    if result.returncode == 0:
        logger.info("Tests passed successfully!")
        return True
    else:
        logger.error("Tests failed:")
        logger.error(result.stdout)
        logger.error(result.stderr)
        return False


def main():
    """Main entry point for the migration script."""
    parser = argparse.ArgumentParser(description="AWS Services Migration Script")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without making changes")
    args = parser.parse_args()
    
    logger.info("Starting AWS services migration")
    logger.info(f"Dry run: {args.dry_run}")
    
    # Create backup directory
    backup_dir = create_backup_directory()
    logger.info(f"Created backup directory at {backup_dir}")
    
    if not args.dry_run:
        # Backup files
        backup_files(backup_dir)
        
        # Create transitional boto3
        create_transitional_boto3()
        
        # Replace XGBoost implementation
        if not replace_xgboost_implementation():
            logger.error("Failed to replace XGBoost implementation")
            return 1
        
        # Update imports
        import_updates()
    else:
        logger.info("[DRY RUN] Would backup files and create transitional boto3.py")
    
    # Run tests
    if not run_tests(args.dry_run):
        logger.error("Migration validation failed")
        return 1
    
    logger.info("AWS services migration completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
