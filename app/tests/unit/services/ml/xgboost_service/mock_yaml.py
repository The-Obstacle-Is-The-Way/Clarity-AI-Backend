"""
Mock YAML implementation for testing purposes.

This module provides a minimal implementation of the YAML interface
needed for testing, without requiring the actual PyYAML package.
"""

from typing import Any


def safe_load(stream: Any) -> dict[str, Any]:
    """
    Mock implementation of yaml.safe_load.

    For testing purposes, returns a predefined dictionary based on
    common configuration patterns in our codebase.

    Args:
        stream: A file-like object or string to parse

    Returns:
        dict: A predefined dictionary with mock configuration
    """
    # Return a predefined configuration to avoid actual parsing
    return {
        "aws": {
            "region_name": "us-east-1",
            "endpoint_prefix": "test-prefix",
            "bucket_name": "test-bucket",
            "dynamodb_table_name": "test-table",
            "audit_table_name": "test-audit",
        },
        "models": {
            "risk_relapse": {
                "endpoint_name": "test-prefix-risk-relapse-endpoint",
                "version": "1.0",
                "features": ["feature1", "feature2"],
            },
            "risk_suicide": {
                "endpoint_name": "test-prefix-risk-suicide-endpoint",
                "version": "1.0",
                "features": ["feature1", "feature2"],
            },
        },
    }


def dump(data: Any, stream: Any | None = None, **kwargs: Any) -> str | None:
    """
    Mock implementation of yaml.dump.

    For testing purposes, returns a string representation
    instead of actually dumping to YAML format.

    Args:
        data: The data to dump
        stream: Optional file-like object to write to
        **kwargs: Additional arguments

    Returns:
        str: A simple string representation of the data
    """
    result = str(data)
    if stream is not None:
        stream.write(result)
        return None
    return result
