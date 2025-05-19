"""
AWS Service Factory Provider.

This module provides a centralized way to access AWS service factories.
It manages the selection between real and in-memory implementations
based on application configuration.
"""

import os
from typing import Optional

from app.core.interfaces.aws_service_interface import AWSServiceFactory
from app.infrastructure.aws.in_memory_aws_services import InMemoryAWSServiceFactory
from app.infrastructure.aws.real_aws_services import RealAWSServiceFactory


class AWSServiceFactoryProvider:
    """Provider for AWS service factories based on environment."""

    _instance: Optional["AWSServiceFactoryProvider"] = None
    _aws_service_factory: AWSServiceFactory | None = None

    @classmethod
    def get_instance(cls) -> "AWSServiceFactoryProvider":
        """Get the singleton instance of the provider."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def initialize(cls, use_in_memory: bool | None = None, region_name: str | None = None) -> None:
        """
        Initialize the provider with configuration.

        Args:
            use_in_memory: If True, force in-memory implementation,
                           If False, force real implementation,
                           If None, determine based on TESTING environment variable
            region_name: AWS region to use for real implementations
        """
        provider = cls.get_instance()

        # Determine whether to use in-memory implementation
        if use_in_memory is None:
            # Auto-detect based on environment
            testing = os.environ.get("TESTING", "").lower() in ("1", "true", "yes")
            use_in_memory = testing

        # Create the appropriate factory
        if use_in_memory:
            provider._aws_service_factory = InMemoryAWSServiceFactory()
        else:
            provider._aws_service_factory = RealAWSServiceFactory(region_name=region_name)

    def get_service_factory(self) -> AWSServiceFactory:
        """
        Get the configured AWS service factory.

        Returns:
            An implementation of AWSServiceFactory

        Raises:
            RuntimeError: If the provider has not been initialized
        """
        if self._aws_service_factory is None:
            # Auto-initialize with defaults if not explicitly initialized
            AWSServiceFactoryProvider.initialize()

        if self._aws_service_factory is None:
            raise RuntimeError("AWS Service Factory Provider has not been properly initialized")

        return self._aws_service_factory


def get_aws_service_factory() -> AWSServiceFactory:
    """
    Convenience function to get the AWS service factory.

    Returns:
        The configured AWS service factory
    """
    return AWSServiceFactoryProvider.get_instance().get_service_factory()
