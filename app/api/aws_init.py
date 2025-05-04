"""
AWS services initialization for the API layer.

This module provides initialization functions for AWS services 
to be used during application startup.
"""

import logging
import os

from app.infrastructure.aws.service_factory_provider import AWSServiceFactoryProvider

logger = logging.getLogger(__name__)


def initialize_aws_services(
    app_env: str = None, 
    region: str | None = None,
    force_in_memory: bool | None = None
) -> None:
    """
    Initialize AWS services based on environment.
    
    Args:
        app_env: Application environment (development, testing, production)
        region: AWS region to use
        force_in_memory: Override to force in-memory implementation regardless of environment
    """
    # Determine if we should use in-memory implementations
    if force_in_memory is None:
        testing = os.environ.get("TESTING", "").lower() in ("1", "true", "yes")
        app_env = app_env or os.environ.get("APP_ENV", "development")
        
        # Use in-memory for testing or development unless explicitly set
        use_in_memory = testing or app_env.lower() in ("development", "dev", "local")
    else:
        use_in_memory = force_in_memory
    
    # Get region from environment if not provided
    region = region or os.environ.get("AWS_REGION", "us-east-1")
    
    # Initialize the AWS service factory provider
    AWSServiceFactoryProvider.initialize(
        use_in_memory=use_in_memory,
        region_name=region
    )
    
    logger.info(
        f"AWS services initialized with {'in-memory' if use_in_memory else 'real'} "
        f"implementation in region {region}"
    )
