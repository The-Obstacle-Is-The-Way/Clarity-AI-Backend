# app/core/services/aws/interfaces.py
from typing import Any, Protocol


class AWSServiceFactoryInterface(Protocol):
    """Interface for a factory that provides AWS service clients/resources."""

    def get_service(self, service_name: str) -> Any:
        """
        Retrieves an AWS service client or resource.

        Args:
            service_name: The name of the service (e.g., 's3', 'dynamodb', 'sagemaker-runtime', 'dynamodb_resource').

        Returns:
            An initialized AWS service client or resource object.

        Raises:
            ValueError: If the requested service name is unknown or unsupported.
            Exception: If there's an error creating or configuring the service instance.
        """
        ...
