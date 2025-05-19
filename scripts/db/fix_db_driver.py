#!/usr/bin/env python3
"""
Database Driver Fix Utility

This script fixes the database configuration to ensure the correct
async driver is used with SQLAlchemy. The error was:
"sqlalchemy.exc.InvalidRequestError: The asyncio extension requires an async driver to be used."

This script will update the database configuration to use asyncpg instead of psycopg2.

Usage:
    python -m backend.scripts.fix_db_driver
"""

import re
from pathlib import Path


def fix_db_driver():
    """Fix the database driver configuration for async SQLAlchemy."""
    # Get the base paths
    base_dir = Path(__file__).resolve().parent.parent
    config_file = base_dir / "app" / "core" / "config" / "settings.py"
    db_file = base_dir / "app" / "core" / "db.py"

    if not config_file.exists():
        print(f"Config file not found: {config_file}")
        return False

    if not db_file.exists():
        print(f"DB file not found: {db_file}")
        return False

    # Backup the files before modifying
    backup_dir = base_dir / "backup"
    backup_dir.mkdir(exist_ok=True)

    # Backup the config file
    config_backup = backup_dir / "settings.py.bak"
    db_backup = backup_dir / "db.py.bak"

    print(f"Backing up {config_file} to {config_backup}")
    if config_file.exists():
        with open(config_file) as src:
            with open(config_backup, "w") as dst:
                dst.write(src.read())

    print(f"Backing up {db_file} to {db_backup}")
    if db_file.exists():
        with open(db_file) as src:
            with open(db_backup, "w") as dst:
                dst.write(src.read())

    # Read the config file
    with open(config_file) as f:
        config_content = f.read()

    # Replace psycopg2 with asyncpg in the database URL if present
    config_content_updated = re.sub(
        r"postgresql\+psycopg2://", "postgresql+asyncpg://", config_content
    )

    # Update the file if changes were made
    if config_content != config_content_updated:
        print("Updating database URL in config file...")
        with open(config_file, "w") as f:
            f.write(config_content_updated)
    else:
        print("No changes needed in config file.")

    # Read the db.py file
    with open(db_file) as f:
        db_content = f.read()

    # Ensure correct SQLAlchemy imports and configuration for async
    if (
        "from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine"
        not in db_content
    ):
        print("Adding missing async SQLAlchemy imports...")
        db_content = db_content.replace(
            "from sqlalchemy.ext.asyncio import",
            "from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, create_async_session_factory",
        )

    # Update the configuration to use future=True
    db_content_updated = re.sub(
        r"engine = create_async_engine\(\s*settings\.SQLALCHEMY_DATABASE_URI,\s*echo=False,\s*future=True,\s*pool_pre_ping=True\s*\)",
        "engine = create_async_engine(\n    settings.SQLALCHEMY_DATABASE_URI,\n    echo=False,\n    future=True,\n    pool_pre_ping=True,\n    pool_size=5,\n    max_overflow=10,\n    pool_timeout=30\n)",
        db_content,
    )

    # Update the file if changes were made
    if db_content != db_content_updated:
        print("Updating database engine configuration...")
        with open(db_file, "w") as f:
            f.write(db_content_updated)
    else:
        print("No changes needed in db file.")

    # Check for requirements and add asyncpg if needed
    requirements_file = base_dir / "requirements.txt"
    if requirements_file.exists():
        with open(requirements_file) as f:
            requirements_content = f.read()

        if "asyncpg" not in requirements_content:
            print("Adding asyncpg to requirements.txt...")
            with open(requirements_file, "a") as f:
                f.write("\n# Async database driver for SQLAlchemy\nasyncpg>=0.27.0\n")

    print("\nDatabase driver fix complete!")
    print(
        "Please run 'pip install -r requirements.txt' to install the new dependencies."
    )
    return True


if __name__ == "__main__":
    fix_db_driver()
