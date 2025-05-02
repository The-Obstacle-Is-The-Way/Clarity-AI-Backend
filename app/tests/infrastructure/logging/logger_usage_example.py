"""
Test script for the logger module.
"""

from app.infrastructure.logging.logger import format_log_message, get_logger

# Test get_logger function
logger = get_logger("test_logger")
logger.info("This is a test log message")

# Test format_log_message function
formatted_message = format_log_message(
    message="Test message",
    source="test_logger",
    additional_data={"test_key": "test_value"},
)
print("Formatted log message:")
print(formatted_message)
