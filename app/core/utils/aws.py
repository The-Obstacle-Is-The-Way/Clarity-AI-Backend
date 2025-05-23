"""
AWS utilities for interacting with AWS services.

This module provides utilities for working with AWS services, including a client factory
and helper functions for processing responses from AWS services. It's designed to
simplify AWS service integration while maintaining testability.
"""

import json
import logging
from typing import Any, Dict, cast

import boto3
from botocore.config import Config

# Set up logging with no PHI
logger = logging.getLogger(__name__)


class AWSClientFactory:
    """Factory for creating AWS service clients.

    This class provides methods for creating AWS service clients with consistent
    configuration. It allows for dependency injection and easier mocking in tests.
    """

    def __init__(
        self,
        region_name: str,
        profile_name: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        **kwargs,
    ):
        """Initialize the AWS client factory.

        Args:
            region_name: AWS region name
            profile_name: AWS profile name to use (optional)
            aws_access_key_id: AWS access key ID (optional)
            aws_secret_access_key: AWS secret access key (optional)
            **kwargs: Additional arguments to pass to boto3.session.Session
        """
        # Create a session with the provided credentials and configuration
        session_args = {"region_name": region_name, **kwargs}

        # Add optional credentials if provided
        if profile_name:
            session_args["profile_name"] = profile_name

        if aws_access_key_id and aws_secret_access_key:
            session_args["aws_access_key_id"] = aws_access_key_id
            session_args["aws_secret_access_key"] = aws_secret_access_key

        # Create the session
        self.session = boto3.session.Session(**session_args)
        self.region_name = region_name

    def get_s3_client(self) -> boto3.client:
        """Get an S3 client.

        Returns:
            Configured S3 client
        """
        return self.session.client("s3")

    def get_dynamodb_client(self) -> boto3.client:
        """Get a DynamoDB client.

        Returns:
            Configured DynamoDB client
        """
        return self.session.client("dynamodb")

    def get_bedrock_runtime_client(self, endpoint_url: str | None = None) -> boto3.client:
        """Get a Bedrock Runtime client.

        Args:
            endpoint_url: Custom endpoint URL for Bedrock (optional)

        Returns:
            Configured Bedrock Runtime client
        """
        client_config = Config(
            retries={"max_attempts": 3, "mode": "standard"},
            read_timeout=300,  # 5 minutes
            connect_timeout=10,
        )

        client_args = {
            "service_name": "bedrock-runtime",
            "region_name": self.region_name,
            "config": client_config,
        }

        # Add custom endpoint if provided
        if endpoint_url:
            client_args["endpoint_url"] = endpoint_url

        return self.session.client(**client_args)

    def get_kms_client(self) -> boto3.client:
        """Get a KMS client.

        Returns:
            Configured KMS client
        """
        return self.session.client("kms")

    def get_comprehend_medical_client(self) -> boto3.client:
        """Get a Comprehend Medical client.

        Returns:
            Configured Comprehend Medical client
        """
        return self.session.client("comprehendmedical")


def format_bedrock_response(response_body: dict[str, Any], analysis_type: str) -> dict[str, Any]:
    """Format a response from Bedrock for actigraphy analysis.

    This function extracts and formats the relevant data from a Bedrock response
    for a specific analysis type. It handles different response formats based on
    the model and analysis type.

    Args:
        response_body: The response body from Bedrock
        analysis_type: The type of analysis (e.g., "sleep_quality")

    Returns:
        Formatted response with the analysis results
    """
    try:
        # Extract the completion from the response
        if "completion" in response_body:
            # Parse the completion as JSON
            completion = json.loads(response_body["completion"])

            # Extract the results for the specific analysis type
            if analysis_type in completion:
                return cast(Dict[str, Any], completion[analysis_type])

            # If the specific analysis type is not found, return the whole completion
            return cast(Dict[str, Any], completion)

        # Some models may use a different response format
        if "predictions" in response_body:
            predictions = response_body["predictions"]

            # Extract the results for the specific analysis type
            if isinstance(predictions, list) and len(predictions) > 0:
                # Get the first prediction
                prediction = predictions[0]

                # Look for the analysis type in the prediction
                if analysis_type in prediction:
                    return cast(Dict[str, Any], prediction[analysis_type])

                # If the specific analysis type is not found, return the whole prediction
                return cast(Dict[str, Any], prediction)

            # If predictions is not a list or is empty, return an empty dict
            return {}

        # If the response doesn't match any expected format, return an empty dict
        logger.warning(f"Unexpected Bedrock response format: {response_body}")
        return {}
    except Exception as e:
        logger.warning(f"Error formatting Bedrock response: {e!s}")
        # Return a generic response to avoid failing the entire analysis
        return {"error": "Failed to parse model response", "status": "incomplete"}
