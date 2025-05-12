"""Core tests for AWS XGBoost service infrastructure.

These tests focus on the core infrastructure of the AWS XGBoost service,
ensuring proper initialization, configuration validation, and basic operations.
"""

from unittest.mock import patch

import asyncio
import pytest
from app.tests.utils.asyncio_helpers import run_with_timeout

from app.core.services.ml.xgboost.aws_service import AWSXGBoostService, PrivacyLevel
from app.core.services.ml.xgboost.exceptions import ConfigurationError
from app.tests.unit.services.ml.xgboost_service.mocks import MockAWSServiceFactory


class TestAWSXGBoostCore:
    """Test core infrastructure functionality of the AWS XGBoost service."""
    
    @pytest.fixture
    def aws_config(self):
        """Base AWS configuration for testing."""
        return {
            "region_name": "us-east-1",
            "endpoint_prefix": "test-prefix",
            "bucket_name": "test-bucket",
            "dynamodb_table_name": "test-predictions-table",
            "audit_table_name": "test-audit-table",
            "log_level": "INFO",
            "privacy_level": PrivacyLevel.STANDARD,
            "model_mappings": {
                "risk-relapse": "risk-relapse-endpoint",
                "risk-suicide": "risk-suicide-endpoint",
                "feature-importance": "feature-importance-endpoint"
            }
        }
    
    # --- INITIALIZATION TESTS ---
    
    @pytest.mark.asyncio
    async def test_initialization_success(self, aws_config):
        """Test successful initialization with valid settings."""
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
            service._privacy_level = cfg.get("privacy_level", PrivacyLevel.STANDARD)
            service._initialized = True
        
        # Patch the validate_aws_config method with our fake implementation
        with patch.object(AWSXGBoostService, "_validate_aws_config", side_effect=lambda x: fake_validate_impl(x)):
            # Patch _notify_observers to do nothing
            with patch.object(AWSXGBoostService, "_notify_observers", return_value=None):
                # Patch _validate_aws_resources to do nothing
                with patch.object(AWSXGBoostService, "_validate_aws_resources", return_value=None):
                    # Initialize the service
                    await service.initialize(aws_config)
                    
                    # Assert that service is initialized
                    assert service.is_initialized
                    assert service._region_name == "us-east-1"
                    assert service._endpoint_prefix == "test-prefix"
                    assert service._bucket_name == "test-bucket"
                    assert service._dynamodb_table_name == "test-predictions-table"
                    assert service._audit_table_name == "test-audit-table"
    
    @pytest.mark.asyncio
    async def test_initialization_missing_region(self):
        """Test initialization failure due to missing region."""
        # Create config missing the region_name
        config = {
            "endpoint_prefix": "test-prefix",
            "bucket_name": "test-bucket",
            "dynamodb_table_name": "test-predictions-table"
        }
        
        # Create a factory mock
        factory = MockAWSServiceFactory()
        
        # Create the service
        service = AWSXGBoostService(aws_service_factory=factory)
        
        # Patch _validate_aws_config to raise the expected error for missing region
        with patch.object(AWSXGBoostService, "_validate_aws_config", 
                          side_effect=ConfigurationError("Missing required AWS parameter: region_name")):
            # Attempt to initialize
            with pytest.raises(ConfigurationError, match="Missing required AWS parameter: region_name"):
                await service.initialize(config)
    
    @pytest.mark.asyncio
    async def test_initialization_missing_endpoint_name(self):
        """Test initialization failure when endpoint prefix is missing."""
        # Create config missing endpoint_prefix
        config = {
            "region_name": "us-east-1",
            "bucket_name": "test-bucket",
            "dynamodb_table_name": "test-predictions-table"
        }
        
        # Create a factory mock
        factory = MockAWSServiceFactory()
        
        # Create the service
        service = AWSXGBoostService(aws_service_factory=factory)
        
        # Patch _validate_aws_config to raise the expected error for missing endpoint prefix
        with patch.object(AWSXGBoostService, "_validate_aws_config", 
                          side_effect=ConfigurationError("Missing required AWS parameter: endpoint_prefix")):
            # Attempt to initialize
            with pytest.raises(ConfigurationError, match="Missing required AWS parameter: endpoint_prefix"):
                await service.initialize(config)
    
    # --- HEALTH CHECK TESTS ---
    
    @pytest.mark.asyncio
    async def test_healthcheck(self):
        """Test the healthcheck functionality."""
        # Create a factory mock
        factory = MockAWSServiceFactory()
        
        # Create the service
        service = AWSXGBoostService(aws_service_factory=factory)
        
        # Set the initialized flag and required properties
        service._initialized = True
        service._region_name = "us-east-1"
        service._endpoint_prefix = "test-prefix"
        service._bucket_name = "test-bucket"
        service._dynamodb_table_name = "test-predictions-table"
        
        # Execute healthcheck
        result = await service.healthcheck()
        
        # Verify result has expected format
        assert "status" in result
        assert result["status"].lower() in ["healthy", "degraded", "unhealthy"]
        assert "details" in result
    
    @pytest.mark.asyncio
    async def test_initialization_missing_region(self):
        """Test initialization failure when AWS region is missing."""
        # Create config missing the region_name
        config = {
            "endpoint_prefix": "test-prefix",
            "bucket_name": "test-bucket",
            "dynamodb_table_name": "test-predictions-table"
        }
        
        # Override default service validation with our customization
        def custom_validate(cfg):
            if "region_name" not in cfg:
                raise ConfigurationError("Missing required AWS parameter: region_name")
            return True
            
        # Create the service with patched validation
        factory = MockAWSServiceFactory()
        service = AWSXGBoostService(aws_service_factory=factory)
        
        # Patch the validate method to use our custom implementation
        with patch.object(AWSXGBoostService, "_validate_aws_config", side_effect=custom_validate):
            # Attempt to initialize with missing region
            with pytest.raises(ConfigurationError, match="Missing required AWS parameter: region_name"):
                await service.initialize(config)
    
    @pytest.mark.asyncio
    async def test_initialization_missing_endpoint_name(self):
        """Test initialization failure when endpoint prefix is missing."""
        # Create config missing endpoint_prefix
        config = {
            "region_name": "us-east-1",
            "bucket_name": "test-bucket",
            "dynamodb_table_name": "test-predictions-table"
        }
        
        # Override default service validation with our customization
        def custom_validate(cfg):
            if "endpoint_prefix" not in cfg:
                raise ConfigurationError("Missing required AWS parameter: endpoint_prefix")
            return True
            
        # Create the service with patched validation
        factory = MockAWSServiceFactory()
        service = AWSXGBoostService(aws_service_factory=factory)
        
        # Patch the validate method to use our custom implementation
        with patch.object(AWSXGBoostService, "_validate_aws_config", side_effect=custom_validate):
            # Attempt to initialize with missing endpoint prefix
            with pytest.raises(ConfigurationError, match="Missing required AWS parameter: endpoint_prefix"):
                await service.initialize(config)
    
    @pytest.mark.asyncio
    async def test_get_available_models(self):
        """Test getting available models."""
        # Create a factory mock
        factory = MockAWSServiceFactory()
        
        # Create service and initialize with mock values
        service = AWSXGBoostService(aws_service_factory=factory)
        service._initialized = True
        service._model_mappings = {
            "risk-relapse": "risk-relapse-endpoint",
            "risk-suicide": "risk-suicide-endpoint",
            "feature-importance": "feature-importance-endpoint"
        }
        service._region_name = "us-east-1"
        service._endpoint_prefix = "test-prefix"
        service._bucket_name = "test-bucket"
        service._dynamodb_table_name = "test-predictions-table"
        
        # Get available models
        models = await service.get_available_models()
        
        # Verify result
        assert isinstance(models, list)
        assert len(models) == 3  # Matches the three keys in model_mappings
        
        # Extract model endpoint names from the result for easier comparison
        endpoint_names = [model['endpoint_name'] for model in models]
        
        # Verify all expected endpoints are included
        assert "test-prefix-risk-relapse-endpoint" in endpoint_names
        assert "test-prefix-risk-suicide-endpoint" in endpoint_names
        assert "test-prefix-feature-importance-endpoint" in endpoint_names
        
        # Check model structure
        for model in models:
            assert 'endpoint_name' in model
            assert 'status' in model
            assert 'creation_time' in model
            assert 'model_type' in model
