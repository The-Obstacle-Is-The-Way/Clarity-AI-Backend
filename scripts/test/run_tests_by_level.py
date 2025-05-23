#!/usr/bin/env python3
"""
Import redirector for Docker test environment.
This file redirects imports to the actual implementation in scripts/test/runners/legacy/.
Enhanced for Docker container test execution with environment variable handling.
"""

import argparse
import os
import sys
from pathlib import Path

# Get the actual module path
current_dir = Path(__file__).parent.resolve()
project_root = current_dir.parent  # /backend directory

# Make sure the script can find modules
sys.path.insert(0, str(project_root))  # Add the backend directory to path first

# Add scripts directory explicitly
scripts_dir = project_root / "scripts"
sys.path.insert(0, str(scripts_dir))

# Configure Docker environment variables
if any("--docker" in arg for arg in sys.argv):
    print("Setting up Docker test environment variables...")
    # Ensure test database URL is properly set
    if "TEST_DATABASE_URL" in os.environ:
        db_url = os.environ["TEST_DATABASE_URL"]
        os.environ["DB_HOST"] = db_url.split("@")[1].split(":")[0]
        os.environ["DB_PORT"] = db_url.split(":")[-1].split("/")[0]
        os.environ["DB_USERNAME"] = db_url.split("://")[1].split(":")[0]
        os.environ["DB_PASSWORD"] = db_url.split(":")[2].split("@")[0]
        os.environ["DB_DATABASE"] = db_url.split("/")[-1]
        print(f"Configured database from TEST_DATABASE_URL: {db_url}")

    # Set test environment flags
    os.environ["TESTING"] = "1"
    os.environ["ENVIRONMENT"] = "test"
    os.environ["TEST_MODE"] = "1"

# Import and customize run_tests_by_level for Docker
from scripts.test.runners.legacy.run_tests_by_level import main as original_main


def docker_enhanced_main():
    """Enhanced main function with Docker support."""
    parser = argparse.ArgumentParser(description="Run tests by dependency level")
    parser.add_argument(
        "level",
        choices=["standalone", "venv_only", "db_required", "all"],
        help="Test level to run",
    )
    parser.add_argument(
        "--timeout", type=int, default=300, help="Timeout in seconds for test execution"
    )
    parser.add_argument("--fix", action="store_true", help="Apply fixes for standalone tests")
    parser.add_argument("--xml", action="store_true", help="Generate XML reports")
    parser.add_argument(
        "--cleanup", action="store_true", help="Cleanup temporary files after tests"
    )
    parser.add_argument("--docker", action="store_true", help="Running in Docker environment")

    args = parser.parse_args()

    # Print Docker environment for debugging
    if args.docker:
        print("Running in Docker environment")
        print(f"TEST_DATABASE_URL: {os.environ.get('TEST_DATABASE_URL', 'Not set')}")
        print(f"TEST_REDIS_URL: {os.environ.get('TEST_REDIS_URL', 'Not set')}")

    # Use the original main function
    return original_main()


if __name__ == "__main__":
    # Pass command line arguments to the enhanced main function
    sys.exit(docker_enhanced_main())
