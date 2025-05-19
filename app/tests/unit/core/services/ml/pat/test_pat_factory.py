"""
Unit tests for the PAT factory.

This module contains tests for the PATFactory class which creates
and manages PAT service instances based on configuration.
"""

import tempfile
import unittest
from unittest.mock import MagicMock, patch

from app.core.exceptions import InvalidConfigurationError
from app.core.services.ml.pat.bedrock import BedrockPAT
from app.core.services.ml.pat.factory import PATServiceFactory
from app.core.services.ml.pat.mock import MockPATService


class TestPATServiceFactory(unittest.TestCase):
    """Test cases for PATServiceFactory."""

    def setUp(self) -> None:
        """Set up test fixtures.

        This method runs before each test.
        """
        # Clear the instance cache before each test
        PATServiceFactory._instance_cache = {}

        # Save original registry
        self.original_registry = PATServiceFactory._SERVICE_REGISTRY.copy()

        # Create mocks for service classes
        self.mock_pat_class = MagicMock(spec=MockPATService)
        self.mock_pat_instance = MagicMock(spec=MockPATService)
        self.mock_pat_class.return_value = self.mock_pat_instance

        self.mock_bedrock_class = MagicMock(spec=BedrockPAT)
        self.mock_bedrock_instance = MagicMock(spec=BedrockPAT)
        self.mock_bedrock_class.return_value = self.mock_bedrock_instance

        # Replace registry entries with mocks
        PATServiceFactory._SERVICE_REGISTRY = {
            "mock": self.mock_pat_class,
            "bedrock": self.mock_bedrock_class,
        }

    def tearDown(self) -> None:
        """Clean up after tests.

        This method runs after each test.
        """
        # Restore original service registry
        PATServiceFactory._SERVICE_REGISTRY = self.original_registry

        # Clear the instance cache
        PATServiceFactory._instance_cache = {}

    def test_get_mock_pat(self) -> None:
        """Test getting a MockPAT instance."""
        # Arrange
        config = {"provider": "mock", "storage_path": tempfile.mkdtemp()}

        # Act
        pat = PATServiceFactory.create_pat_service(config)

        # Assert
        self.assertEqual(pat, self.mock_pat_instance)
        self.mock_pat_class.assert_called_once()

        # Check that initialize was called with storage_path and test_mode
        expected_config = {"storage_path": config["storage_path"], "test_mode": True}
        self.mock_pat_instance.initialize.assert_called_once_with(expected_config)

    def test_get_bedrock_pat(self) -> None:
        """Test getting a BedrockPAT instance."""
        # Arrange
        config = {
            "provider": "bedrock",
            "bucket_name": "test-bucket",
            "table_name": "test-table",
            "model_id": "amazon.titan-embed-text-v1",
        }

        # Act
        pat = PATServiceFactory.create_pat_service(config)

        # Assert
        self.assertEqual(pat, self.mock_bedrock_instance)
        self.mock_bedrock_class.assert_called_once()
        expected_config = {k: v for k, v in config.items() if k != "provider"}
        expected_config["test_mode"] = True
        self.mock_bedrock_instance.initialize.assert_called_once()

    def test_get_default_provider(self) -> None:
        """Test getting a PAT instance with the default provider."""
        # Arrange
        config = {"provider": "mock", "storage_path": tempfile.mkdtemp()}

        # Act
        pat = PATServiceFactory.create_pat_service(config)

        # Assert
        self.assertEqual(pat, self.mock_pat_instance)
        self.mock_pat_class.assert_called_once()
        expected_config = {"storage_path": config["storage_path"], "test_mode": True}
        self.mock_pat_instance.initialize.assert_called_once_with(expected_config)

    def test_get_unknown_provider(self) -> None:
        """Test getting a PAT instance with an unknown provider."""
        # Arrange
        config = {"provider": "unknown"}

        # Act & Assert
        with self.assertRaises(InvalidConfigurationError) as context:
            PATServiceFactory.create_pat_service(config)
        self.assertIn("Invalid PAT service provider", str(context.exception))
        self.mock_pat_class.assert_not_called()
        self.mock_bedrock_class.assert_not_called()

    def test_instance_caching(self) -> None:
        """Test that instances are cached."""
        # Arrange
        config = {"provider": "mock", "storage_path": tempfile.mkdtemp()}

        # Act
        pat1 = PATServiceFactory.create_pat_service(config)
        pat2 = PATServiceFactory.create_pat_service(config)

        # Assert
        # Should be the same instance due to caching
        self.assertEqual(pat1, pat2)
        # Constructor should only be called once
        self.mock_pat_class.assert_called_once()
        expected_config = {"storage_path": config["storage_path"], "test_mode": True}
        self.mock_pat_instance.initialize.assert_called_once_with(expected_config)

    def test_different_configs_create_different_instances(self) -> None:
        """Test that different configs create different instances."""
        # Arrange
        config1 = {"provider": "mock", "storage_path": tempfile.mkdtemp()}

        config2 = {"provider": "mock", "storage_path": tempfile.mkdtemp()}

        # Configure mocks for different instances
        mock_instance1 = MagicMock(spec=MockPATService)
        mock_instance2 = MagicMock(spec=MockPATService)
        self.mock_pat_class.side_effect = [mock_instance1, mock_instance2]

        # Act
        pat1 = PATServiceFactory.create_pat_service(config1)
        pat2 = PATServiceFactory.create_pat_service(config2)

        # Assert
        self.assertNotEqual(pat1, pat2)
        self.assertEqual(self.mock_pat_class.call_count, 2)
        expected_config1 = {"storage_path": config1["storage_path"], "test_mode": True}
        expected_config2 = {"storage_path": config2["storage_path"], "test_mode": True}
        mock_instance1.initialize.assert_called_once_with(expected_config1)
        mock_instance2.initialize.assert_called_once_with(expected_config2)

    @patch("app.core.services.ml.pat.factory.PATServiceFactory._instance_cache")
    def test_cache_key_generation(self, mock_cache) -> None:
        """Test that cache keys are generated correctly."""
        # Arrange
        mock_cache.__getitem__.side_effect = KeyError
        mock_cache.__setitem__ = MagicMock()

        config = {
            "provider": "mock",
            "storage_path": "/tmp/path1",
            "option1": "value1",
            "option2": "value2",
        }

        # Act
        PATServiceFactory.create_pat_service(config)

        # Assert
        # Verify that __setitem__ was called exactly once
        self.assertEqual(mock_cache.__setitem__.call_count, 1)

        # Get the key that was used
        key = mock_cache.__setitem__.call_args[0][0]

        # Verify that the key contains the provider
        self.assertTrue(key.startswith("mock-"))

        # Create a different config with the same values but different order
        config2 = {
            "option2": "value2",
            "provider": "mock",
            "option1": "value1",
            "storage_path": "/tmp/path1",
        }

        # Reset the mock
        mock_cache.__setitem__.reset_mock()

        # Act again with the reordered config
        PATServiceFactory.create_pat_service(config2)

        # Assert
        # Verify that __setitem__ was called exactly once
        self.assertEqual(mock_cache.__setitem__.call_count, 1)

        # Get the new key
        key2 = mock_cache.__setitem__.call_args[0][0]

        # Verify that the keys are identical despite different dict order
        self.assertEqual(key, key2)


if __name__ == "__main__":
    unittest.main()
