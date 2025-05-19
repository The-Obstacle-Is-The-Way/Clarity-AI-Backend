"""
Unit tests for the core logging utility.
"""

import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from app.core.constants import LogLevel
from app.core.utils.logging import get_logger, log_execution_time, log_method_calls


class TestGetLogger:
    """Tests for the get_logger function."""

    def test_get_logger_returns_logger(self):
        """Test that get_logger returns a Logger instance."""
        logger = get_logger("test_logger")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_logger"

    def test_get_logger_sets_level(self):
        """Test that get_logger sets the log level."""
        with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}):
            logger = get_logger("test_logger_debug")
            assert logger.level == logging.DEBUG

    def test_get_logger_default_level(self):
        """Test that get_logger uses INFO as default level."""
        # Remove LOG_LEVEL from env if it exists
        with patch.dict(os.environ, clear=True):
            logger = get_logger("test_logger_default")
            assert logger.level == logging.INFO

    def test_get_logger_adds_handler(self):
        """Test that get_logger adds a handler."""
        logger = get_logger("test_logger_handler")
        assert len(logger.handlers) > 0
        assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)


class TestLogExecutionTime:
    """Tests for the log_execution_time decorator."""

    def test_log_execution_time_success(self):
        """Test log_execution_time decorator on successful function execution."""
        mock_logger = MagicMock()

        @log_execution_time(logger=mock_logger, level=LogLevel.INFO)
        def test_function(a, b):
            return a + b

        result = test_function(1, 2)
        assert result == 3
        mock_logger.log.assert_called_once()
        assert "executed in" in mock_logger.log.call_args[0][1]

    def test_log_execution_time_error(self):
        """Test log_execution_time decorator on function that raises an exception."""
        mock_logger = MagicMock()

        @log_execution_time(logger=mock_logger)
        def failing_function():
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            failing_function()

        mock_logger.exception.assert_called_once()
        assert "Exception in 'failing_function'" in mock_logger.exception.call_args[0][0]

    def test_log_execution_time_creates_logger(self):
        """Test that log_execution_time creates a logger if none is provided."""

        @log_execution_time()
        def test_function(a, b):
            return a + b

        # Should not raise an exception
        result = test_function(1, 2)
        assert result == 3


class TestLogMethodCalls:
    """Tests for the log_method_calls decorator."""

    def test_log_method_calls(self):
        """Test log_method_calls decorator on a class."""
        mock_logger = MagicMock()

        @log_method_calls(logger=mock_logger, level=LogLevel.INFO)
        class TestClass:
            def test_method(self, a, b):
                return a + b

        instance = TestClass()
        result = instance.test_method(1, 2)

        assert result == 3
        assert mock_logger.log.call_count >= 2  # Entry and exit logs

        # Check entry log
        assert "Calling" in mock_logger.log.call_args_list[0][0][1]

        # Check exit log with return value
        assert "returned:" in mock_logger.log.call_args_list[1][0][1]

    def test_log_method_calls_without_args(self):
        """Test log_method_calls decorator without logging arguments."""
        mock_logger = MagicMock()

        @log_method_calls(logger=mock_logger, log_args=False)
        class TestClass:
            def test_method(self, a, b):
                return a + b

        instance = TestClass()
        result = instance.test_method(1, 2)
        assert result == 3
        assert mock_logger.log.call_count >= 2

        # Check entry log doesn't contain arguments
        call_log = mock_logger.log.call_args_list[0][0][1]
        assert "Calling TestClass.test_method" in call_log
        assert "(1, 2)" not in call_log

    def test_log_method_calls_without_results(self):
        """Test log_method_calls decorator without logging results."""
        mock_logger = MagicMock()

        @log_method_calls(logger=mock_logger, log_results=False)
        class TestClass:
            def test_method(self, a, b):
                return a + b

        instance = TestClass()
        result = instance.test_method(1, 2)
        assert result == 3
        assert mock_logger.log.call_count >= 2

        # Check exit log doesn't contain return value
        call_log = mock_logger.log.call_args_list[1][0][1]
        assert "completed successfully" in call_log
        assert "returned: 3" not in call_log

    def test_log_method_calls_with_error(self):
        """Test log_method_calls decorator with a method that raises an exception."""
        mock_logger = MagicMock()

        @log_method_calls(logger=mock_logger)
        class TestClass:
            def failing_method(self):
                raise ValueError("Test error")

        instance = TestClass()
        with pytest.raises(ValueError):
            instance.failing_method()
        mock_logger.error.assert_called_once()
        assert "Exception in TestClass.failing_method" in mock_logger.error.call_args[0][0]
