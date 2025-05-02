"""Unit tests for enhanced logging functionality."""
import logging
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from app.core.utils.logging import get_logger


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
        mock_get_logger.return_value = mock_logger_instance
        
        mock_handler = MagicMock(spec=logging.StreamHandler)
        mock_formatter = MagicMock(spec=logging.Formatter)

        with patch("app.core.utils.logging.logging.StreamHandler", return_value=mock_handler) as mock_stream_handler, \
             patch("app.core.utils.logging.logging.Formatter", return_value=mock_formatter) as mock_formatter_class:

            # Get logger
            logger = get_logger("test_config_module_unique") # Use unique name

            # Verify logger name
            mock_get_logger.assert_called_with("test_config_module_unique") # Verify unique name

            # Verify handler and formatter creation
            mock_stream_handler.assert_called_once_with(sys.stdout)
            mock_formatter_class.assert_called_once()
            
            # Verify handler configuration
            mock_handler.setLevel.assert_called_once_with(logging.INFO) # Assuming default level
            mock_handler.setFormatter.assert_called_once_with(mock_formatter)

            # Verify logger configuration
            mock_logger_instance.setLevel.assert_called_once_with(logging.INFO) # Assuming default level
            mock_logger_instance.addHandler.assert_called_once_with(mock_handler)
            assert logger.propagate is False
