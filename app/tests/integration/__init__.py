"""
Integration Tests Package

This package contains tests that require external services or persistent databases.
These tests verify that components work together correctly in a real environment.
Tests in this package:
    - May require external network services (databases, APIs, etc.)
    - May have external dependencies such as Redis, PostgreSQL, etc.
    - May test multiple components together
    - May require specific environment configurations
    - Must be isolated enough to not interfere with production systems
    - Should clean up after themselves to avoid test pollution
    """
