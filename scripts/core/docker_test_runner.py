#!/usr/bin/env python3
"""
Novamind Digital Twin Docker Test Runner.

This script provides a clean architecture implementation for running tests 
in the Docker environment, serving as the quantum-level Single Source of Truth
for test execution with mathematical precision.
"""

import os
import sys
import time
import pytest
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("docker_test_runner")

# Define constants with mathematical precision
PROJECT_ROOT = Path("/app")
TEST_RESULTS_DIR = PROJECT_ROOT / "test-results"
LOG_DIR = PROJECT_ROOT / "logs"
APP_DIR = PROJECT_ROOT / "app"
TESTS_DIR = APP_DIR / "tests"

# Define test levels with neural pathway organization
TEST_LEVELS = {
    "standalone": [str(TESTS_DIR / "standalone")],
    "unit": [str(TESTS_DIR / "unit")],
    "integration": [str(TESTS_DIR / "integration")],
    "api": [str(TESTS_DIR / "api")],
    "e2e": [str(TESTS_DIR / "e2e")],
    "all": None,  # Will be dynamically calculated
}

# Calculate the "all" level directories
TEST_LEVELS["all"] = [
    dir_path
    for level, dirs in TEST_LEVELS.items()
    if level != "all" and dirs is not None
    for dir_path in dirs
]


class DockerTestRunner:
    """
    Neural test runner for Docker environment following clean architecture.
    """

    def __init__(self, level: str = "all", timeout: int = 300) -> None:
        """
        Initialize the test runner with mathematically optimal configuration.

        Args:
            level: Test level to run
            timeout: Timeout in seconds
        """
        self.level = level
        self.timeout = timeout
        self.start_time = time.time()

        # Ensure critical directories exist
        TEST_RESULTS_DIR.mkdir(exist_ok=True, parents=True)
        LOG_DIR.mkdir(exist_ok=True, parents=True)

        # Configure Python path with mathematical precision
        if str(PROJECT_ROOT) not in sys.path:
            sys.path.insert(0, str(PROJECT_ROOT))

        # Configure environment
        os.environ["PYTHONPATH"] = f"{PROJECT_ROOT}"
        os.environ["TESTING"] = "1"
        os.environ["ENVIRONMENT"] = "test"
        os.environ["TEST_MODE"] = "1"

        self._validate_configuration()
        logger.info(f"DockerTestRunner initialized for level: {level}")

    def _validate_configuration(self) -> None:
        """Validate runner configuration with quantum-level precision."""
        if self.level not in TEST_LEVELS:
            raise ValueError(
                f"Invalid test level: {self.level}. Valid levels: {list(TEST_LEVELS.keys())}"
            )

        # Validate database URL for appropriate levels
        if self.level in ["integration", "api", "e2e", "all"]:
            db_url = os.environ.get("TEST_DATABASE_URL")
            if not db_url:
                raise ValueError(
                    "TEST_DATABASE_URL environment variable is required for this test level"
                )
            logger.info(f"Using database URL: {db_url}")

        # Check that test directories exist
        if self.level != "all":
            for test_dir in TEST_LEVELS[self.level]:
                if not Path(test_dir).exists():
                    logger.warning(f"Test directory does not exist: {test_dir}")

    def prepare_environment(self) -> None:
        """
        Prepare the test environment with neural precision.
        """
        logger.info("Preparing test environment...")

        # Wait for dependencies (database, redis)
        if self.level in ["integration", "api", "e2e", "all"]:
            # Check database connectivity
            db_url = os.environ.get("TEST_DATABASE_URL", "")
            if "postgres" in db_url:
                host = db_url.split("@")[1].split(":")[0]
                self._wait_for_postgres(host)

            # Check Redis if configured
            redis_url = os.environ.get("TEST_REDIS_URL", "")
            if redis_url:
                host = redis_url.split("@")[-1].split(":")[0]
                if not host:
                    host = redis_url.split("//")[-1].split(":")[0]
                self._wait_for_redis(host)

        logger.info("Environment prepared")

    def _wait_for_postgres(
        self, host: str, max_retries: int = 30, delay: int = 1
    ) -> None:
        """Wait for PostgreSQL to be ready with exponential backoff."""
        logger.info(f"Waiting for PostgreSQL at {host}...")

        retry = 0
        retry_delay = delay

        while retry < max_retries:
            try:
                result = subprocess.run(
                    ["pg_isready", "-h", host],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0:
                    logger.info("PostgreSQL is ready")
                    return

                logger.info(f"PostgreSQL not ready: {result.stdout} {result.stderr}")

            except Exception as e:
                logger.warning(f"Error checking PostgreSQL: {e}")

            time.sleep(retry_delay)
            retry_delay = min(
                retry_delay * 2, 10
            )  # Exponential backoff, max 10 seconds
            retry += 1

        logger.warning(f"PostgreSQL not ready after {max_retries} attempts")

    def _wait_for_redis(self, host: str, max_retries: int = 30, delay: int = 1) -> None:
        """Wait for Redis to be ready with exponential backoff."""
        logger.info(f"Waiting for Redis at {host}...")

        retry = 0
        retry_delay = delay

        while retry < max_retries:
            try:
                result = subprocess.run(
                    ["redis-cli", "-h", host, "ping"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode == 0 and "PONG" in result.stdout:
                    logger.info("Redis is ready")
                    return

                logger.info(f"Redis not ready: {result.stdout} {result.stderr}")

            except Exception as e:
                logger.warning(f"Error checking Redis: {e}")

            time.sleep(retry_delay)
            retry_delay = min(
                retry_delay * 2, 10
            )  # Exponential backoff, max 10 seconds
            retry += 1

        logger.warning(f"Redis not ready after {max_retries} attempts")

    def run_tests(self) -> int:
        """
        Run the tests with quantum-level precision and mathematical elegance.

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        logger.info(f"Starting test execution for level: {self.level}")

        # Get test directories
        test_dirs = TEST_LEVELS[self.level]

        # Prepare pytest arguments
        pytest_args = [
            "--color=yes",
            "-v",
            "--tb=native",
            f"--junitxml={TEST_RESULTS_DIR}/test_results_{self.level}.xml",
        ]

        # Add coverage for full test runs
        if self.level == "all":
            pytest_args.extend(
                [
                    "--cov=app",
                    "--cov-report=term-missing:skip-covered",
                    f"--cov-report=xml:{TEST_RESULTS_DIR}/coverage.xml",
                ]
            )

        # Add test directories
        pytest_args.extend(test_dirs)

        logger.info(f"Running pytest with args: {pytest_args}")

        # Execute tests
        start_time = time.time()
        result = pytest.main(pytest_args)
        duration = time.time() - start_time

        # Generate test summary
        exit_status = "SUCCESS" if result == 0 else "FAILURE"
        logger.info(f"Test execution completed with status: {exit_status}")
        logger.info(f"Total execution time: {duration:.2f} seconds")

        return result


def main() -> int:
    """
    Main function with neural-level error handling.

    Returns:
        Exit code
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Docker Test Runner for Novamind Digital Twin"
    )
    parser.add_argument(
        "level", choices=list(TEST_LEVELS.keys()), help="Test level to run"
    )
    parser.add_argument(
        "--timeout", type=int, default=300, help="Test timeout in seconds"
    )

    args = parser.parse_args()

    try:
        # Run tests in mathematically precise steps
        runner = DockerTestRunner(level=args.level, timeout=args.timeout)
        runner.prepare_environment()
        return runner.run_tests()

    except Exception as e:
        logger.error(f"Error running tests: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
