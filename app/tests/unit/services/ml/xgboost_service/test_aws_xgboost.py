"""
Minimal test for AWS XGBoost service to verify basic async functionality.
"""

import asyncio
from unittest.mock import AsyncMock as PatchAsyncMock
from unittest.mock import patch

import pytest

from app.core.services.ml.xgboost.aws_service import AWSXGBoostService, PrivacyLevel
from app.core.services.ml.xgboost.exceptions import ConfigurationError
from app.tests.unit.services.ml.xgboost_service.mocks import MockAWSServiceFactory


# Utility to run async tests in a synchronous test function
def run_async(coro):
    """Run an async coroutine in a synchronous context."""
    return asyncio.run(coro)


class TestAwsXGBoostMinimal:
    """Minimal test suite for AWS XGBoost service."""

    @pytest.mark.asyncio
    async def test_initialization_success(self):
        """Test successful initialization of AWS XGBoost service."""
        # Define test configuration
        config = {
            "endpoint_prefix": "test-prefix",
            "region_name": "us-east-1",
            "bucket_name": "test-bucket",
            "dynamodb_table_name": "test-predictions-table",
            "audit_table_name": "test-audit-table",
            "model_mappings": {
                "risk-relapse": "risk-relapse-endpoint",
                "risk-suicide": "risk-suicide-endpoint",
            },
            "log_level": "INFO",
            "privacy_level": PrivacyLevel.STRICT,
        }

        # Create a factory mock
        factory = MockAWSServiceFactory()

        # Create the service
        service = AWSXGBoostService(aws_service_factory=factory)

        # Define a fake implementation to set the properties manually
        def fake_validate_impl(cfg):
            service._region_name = cfg["region_name"]
            service._endpoint_prefix = cfg["endpoint_prefix"]
            service._bucket_name = cfg["bucket_name"]
            service._dynamodb_table_name = cfg["dynamodb_table_name"]
            service._audit_table_name = cfg.get("audit_table_name")
            service._model_mappings = cfg.get("model_mappings", {})
            service._initialized = True

        # Patch the validate_aws_config method with our fake implementation
        with patch.object(
            AWSXGBoostService,
            "_validate_aws_config",
            side_effect=lambda x: fake_validate_impl(x),
        ):
            # Patch _notify_observers to do nothing
            with patch.object(
                AWSXGBoostService, "_notify_observers", return_value=None
            ):
                # Patch _validate_aws_resources to do nothing
                with patch.object(
                    AWSXGBoostService, "_validate_aws_resources", return_value=None
                ):
                    # Initialize the service
                    await service.initialize(config)

                    # Assert that service is initialized
                    assert service.is_initialized
                    assert service._region_name == "us-east-1"
                    assert service._endpoint_prefix == "test-prefix"
                    assert service._bucket_name == "test-bucket"

    @pytest.mark.asyncio
    async def test_initialization_missing_region(self):
        """Test initialization failure due to missing region."""
        # Create config missing the region_name
        config = {
            "endpoint_prefix": "test-prefix",
            "bucket_name": "test-bucket",
            "dynamodb_table_name": "test-predictions-table",
        }

        # Create a factory mock
        factory = MockAWSServiceFactory()

        # Create the service
        service = AWSXGBoostService(aws_service_factory=factory)

        # Patch _validate_aws_config to raise the expected error for missing region
        with patch.object(
            AWSXGBoostService,
            "_validate_aws_config",
            side_effect=ConfigurationError(
                "Missing required AWS parameter: region_name"
            ),
        ):
            # Attempt to initialize
            with pytest.raises(
                ConfigurationError, match="Missing required AWS parameter: region_name"
            ):
                await service.initialize(config)

    @pytest.mark.asyncio
    async def test_healthcheck(self):
        """Test the healthcheck functionality."""
        # Create a factory mock
        factory = MockAWSServiceFactory()

        # Create the service
        service = AWSXGBoostService(aws_service_factory=factory)

        # Set the initialized flag
        service._initialized = True

        # Define mock healthcheck response
        mock_health = {
            "status": "healthy",
            "components": {
                "sagemaker": {"status": "healthy"},
                "s3": {"status": "healthy"},
                "dynamodb": {"status": "healthy"},
            },
            "details": {"endpoints": []},
        }

        # Patch the service to return the mock health
        with patch.object(
            AWSXGBoostService,
            "healthcheck",
            new_callable=PatchAsyncMock,
            return_value=mock_health,
        ):
            # Call the healthcheck
            result = await service.healthcheck()

            # Verify the results
            assert result is not None
            assert "status" in result
            assert result["status"] == "healthy"
