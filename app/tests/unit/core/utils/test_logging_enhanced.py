"""Unit tests for enhanced logging functionality."""
import logging
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from app.core.utils.logging import get_logger

# Constants for testing
TEST_LOGGER_NAME = "test_logger_configuration"

@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    logger = MagicMock(spec=logging.Logger)
    return logger

@pytest.fixture
def temp_log_file():
    """Create a temporary log file for testing."""
    fd, path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    yield path
    # Cleanup
    try:
        os.remove(path)
    except OSError:
        pass


class TestGetLogger:
    """Test suite for the get_logger function."""

    @patch("app.core.utils.logging.logging.getLogger")
    def test_get_logger_basic(self, mock_get_logger):
        """Test getting a basic logger."""
        # Setup mock
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger

        # Get logger
        logger = get_logger("test_module")

        # Verify correct logger was requested
        mock_get_logger.assert_called_once_with("test_module")

        # Should return the logger from getLogger
        assert logger == mock_logger

    @patch("app.core.utils.logging.logging.getLogger")
    def test_get_logger_configuration(self, mock_get_logger):
        """Test logger configuration within get_logger."""
        # Setup mock logger to simulate no handlers
        mock_logger_instance = MagicMock()
        mock_logger_instance.handlers = [] # Ensure handlers list is empty
        # Set propagate to True initially so it can be verified to be changed to False
        mock_logger_instance.propagate = True
        mock_get_logger.return_value = mock_logger_instance
        
        mock_handler = MagicMock(spec=logging.StreamHandler)
        mock_formatter = MagicMock(spec=logging.Formatter)

        # Mock the PHISanitizingFilter to avoid circular imports
        with patch("app.core.utils.logging.PHISanitizingFilter", return_value=MagicMock()) as mock_phi_filter:
            with patch("app.core.utils.logging.logging.StreamHandler", return_value=mock_handler) as mock_stream_handler:
                with patch("app.core.utils.logging.logging.Formatter", return_value=mock_formatter) as mock_formatter_class:
                    # Act: Call the function
                    result_logger = get_logger(logger_name=TEST_LOGGER_NAME)
                    
                    # Assert: Verify the logger was configured correctly
                    mock_get_logger.assert_called_once_with(TEST_LOGGER_NAME)
                    mock_stream_handler.assert_called_once()
                    mock_formatter_class.assert_called_once()
                    mock_phi_filter.assert_called_once()
                    
                    # Verify handler was added to logger
                    mock_logger_instance.addHandler.assert_called_once_with(mock_handler)
                    
                    # Verify propagate was set to False
                    self.assertFalse(mock_logger_instance.propagate)
                    
                    # Verify PHI filter was added to handler
                    mock_handler.addFilter.assert_called_once()
                    
                    # Verify formatter was set on handler
                    mock_handler.setFormatter.assert_called_once_with(mock_formatter)
                    
                    # Verify the result is the configured logger
                    self.assertEqual(result_logger, mock_logger_instance)
