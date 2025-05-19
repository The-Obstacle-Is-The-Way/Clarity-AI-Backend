#!/usr/bin/env python3
"""
Docker entrypoint for Novamind Digital Twin Testing.

This module provides superintelligent orchestration of test execution in Docker,
following clean architecture principles with mathematically precise implementation.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

# Define execution constants
TEST_RESULTS_DIR = Path("/app/test-results")
LOG_DIR = Path("/app/logs")
DEFAULT_TIMEOUT = 300  # seconds


class DockerTestOrchestrator:
    """
    Neural orchestration of test execution in Docker environment.

    This class embodies clean architecture principles by maintaining
    separation of concerns between test discovery, execution, and reporting.
    """

    def __init__(self) -> None:
        """Initialize the orchestrator with mathematically optimal configuration."""
        self.environment = os.environ.get("ENVIRONMENT", "test")
        self.log_level = os.environ.get("LOG_LEVEL", "INFO")
        self.test_database_url = os.environ.get("TEST_DATABASE_URL", "")

        # Ensure output directories exist
        TEST_RESULTS_DIR.mkdir(exist_ok=True, parents=True)
        LOG_DIR.mkdir(exist_ok=True, parents=True)

        # Configure Python path
        self._configure_python_path()

        print(f"Initialized DockerTestOrchestrator in {self.environment} environment")
        print(f"Database URL: {self.test_database_url}")

    def _configure_python_path(self) -> None:
        """Configure Python path with mathematically optimal settings."""
        # Ensure the application root is in the Python path
        app_dir = Path("/app")
        if str(app_dir) not in sys.path:
            sys.path.insert(0, str(app_dir))

        # Display debugging information
        print(f"Python version: {sys.version}")
        print(f"Python path: {sys.path}")

    def wait_for_dependencies(self, timeout: int = 30) -> bool:
        """
        Wait for dependencies to be available with exponential backoff.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if dependencies are available, False otherwise
        """
        if not self.test_database_url:
            print("No database URL provided, skipping dependency check")
            return True

        print(f"Waiting for database to be ready (timeout: {timeout}s)...")

        # Use exponential backoff for retry
        start_time = time.time()
        retry_interval = 0.5
        max_retry_interval = 5

        while time.time() - start_time < timeout:
            try:
                # Use simple command to check database connection
                result = subprocess.run(
                    ["pg_isready", "-U", "postgres", "-h", "novamind-db-test"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0:
                    print("Database is ready!")
                    return True

                print(f"Database not ready yet: {result.stdout} {result.stderr}")

            except (subprocess.SubprocessError, OSError) as e:
                print(f"Error checking database: {e}")

            # Sleep with exponential backoff
            time.sleep(retry_interval)
            retry_interval = min(retry_interval * 2, max_retry_interval)

        print(f"Database dependency check timed out after {timeout}s")
        return False

    def run_tests(self, test_level: str, options: list[str] = None) -> int:
        """
        Run tests for a specific level with specified options.

        Args:
            test_level: Level of tests to run (standalone, db_required, etc.)
            options: Additional pytest options

        Returns:
            Exit code from test execution
        """
        if options is None:
            options = []

        # Build test command with pure implementation principles
        cmd = [
            sys.executable,
            "-m",
            "scripts.run_tests_by_level",
            test_level,
            "--docker",
        ] + options

        print(f"Running tests: {' '.join(cmd)}")

        # Execute tests
        try:
            result = subprocess.run(cmd, check=False)
            return result.returncode
        except subprocess.SubprocessError as e:
            print(f"Error running tests: {e}")
            return 1

    def main(self, args: list[str]) -> int:
        """
        Main entry point with clean error handling.

        Args:
            args: Command-line arguments

        Returns:
            Exit code
        """
        # Parse arguments with mathematical precision
        if len(args) < 2 or args[1] not in {
            "standalone",
            "venv_only",
            "db_required",
            "all",
        }:
            print(
                "Usage: docker_entrypoint.py [standalone|venv_only|db_required|all] [options]"
            )
            return 1

        test_level = args[1]
        options = args[2:]

        # Wait for dependencies if running integration tests
        if test_level in {"db_required", "all"}:
            if not self.wait_for_dependencies(timeout=60):
                print("Dependencies not available, cannot run tests")
                return 1

        # Run tests
        return self.run_tests(test_level, options)


if __name__ == "__main__":
    # Execute with pure error handling
    orchestrator = DockerTestOrchestrator()
    sys.exit(orchestrator.main(sys.argv))
