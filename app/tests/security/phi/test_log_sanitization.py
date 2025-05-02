#!/usr/bin/env python3
"""
Test suite for PHI (Protected Health Information) log sanitization.
This validates that our logging system properly sanitizes PHI before writing to logs.
"""

import logging
import os
import tempfile

import pytest

# Correct import path for log sanitizer components
from app.infrastructure.security.phi.log_sanitizer import LogSanitizer, PHIFormatter

# Updated import path for PHISanitizer
# from app.core.security.phi_sanitizer import PHISanitizer # Old incorrect path
# from app.infrastructure.security.log_sanitizer import PHISanitizer # Correct path - COMMENTED OUT as class seems removed

class TestLogSanitization:
    """Test PHI sanitization in logs to ensure HIPAA compliance."""

    @pytest.fixture
    def temp_log_file(self):
        """Create a temporary log file for testing."""
        fd, temp_path = tempfile.mkstemp(suffix='.log')
        os.close(fd)
        yield temp_path
        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    @pytest.fixture
    def logger_setup(self, temp_log_file):
        """Set up a logger with a file handler for testing."""
        # Create and configure logger
        test_logger = logging.getLogger('test_phi_logger')
        test_logger.setLevel(logging.DEBUG)

        # Create file handler
        file_handler = logging.FileHandler(temp_log_file)
        file_handler.setLevel(logging.DEBUG)

        # Create PHIFormatter to ensure sanitization happens
        formatter = PHIFormatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            # The PHIFormatter will instantiate its own LogSanitizer by default,
            # which will be intercepted by the monkeypatch in test_phi_never_reaches_logs
        )
        file_handler.setFormatter(formatter)

        # Add handler to logger
        test_logger.addHandler(file_handler)

        return test_logger, temp_log_file

    # def test_sanitizer_initialization(self):
    #     """Test that the PHI sanitizer can be instantiated and used."""
    #     # This test is likely obsolete as PHISanitizer class seems removed/refactored
    #     # into LogSanitizer/PHIService.
    #     sanitizer = PHISanitizer()
    #     # The sanitizer should have a sanitize method and _PHI_PATTERNS
    #     assert hasattr(sanitizer, 'sanitize')
    #     # Check for the new compiled patterns attribute used after refactoring
    #     assert hasattr(sanitizer, '_COMPILED_PHI_PATTERNS')
    #     # Ensure patterns are compiled during init or first use
    #     # sanitizer._ensure_patterns_compiled() # Removed call, compilation happens in __init__
    #     assert len(sanitizer._COMPILED_PHI_PATTERNS) > 0, "Sanitizer should have compiled PHI patterns"

    def test_ssn_sanitization(self):
        """Test that SSNs are properly sanitized."""
        sanitizer = LogSanitizer() # Use infrastructure sanitizer
        test_log = "Patient SSN is 123-45-6789"
        sanitized = sanitizer.sanitize(test_log)
        assert "123-45-6789" not in sanitized
        assert "[REDACTED SSN]" in sanitized

    def test_email_sanitization(self):
        """Test that email addresses are properly sanitized."""
        sanitizer = LogSanitizer() # Use infrastructure sanitizer
        test_log = "Patient email is patient@example.com"
        sanitized = sanitizer.sanitize(test_log)
        assert "patient@example.com" not in sanitized
        assert "[REDACTED EMAIL]" in sanitized

    def test_phone_sanitization(self):
        """Test that phone numbers are properly sanitized."""
        sanitizer = LogSanitizer() # Use infrastructure sanitizer
        test_log = "Patient phone is (555) 123-4567"
        sanitized = sanitizer.sanitize(test_log)
        assert "(555) 123-4567" not in sanitized
        assert "[REDACTED PHONE]" in sanitized

    def test_name_sanitization(self):
        """Test that names are properly sanitized."""
        sanitizer = LogSanitizer() # Use infrastructure sanitizer
        test_log = "Patient name is John Smith"
        sanitized = sanitizer.sanitize(test_log)
        assert "John Smith" not in sanitized
        assert "[REDACTED NAME]" in sanitized

    def test_multiple_phi_sanitization(self):
        """Test that multiple PHI elements in the same log are all sanitized."""
        sanitizer = LogSanitizer() # Use infrastructure sanitizer
        test_log = "Patient John Smith (SSN: 123-45-6789) can be reached at (555) 123-4567 or john.smith@example.com"
        sanitized = sanitizer.sanitize(test_log)

        assert "John Smith" not in sanitized
        assert "123-45-6789" not in sanitized
        assert "(555) 123-4567" not in sanitized
        assert "john.smith@example.com" not in sanitized

        assert "[REDACTED NAME]" in sanitized
        assert "[REDACTED SSN]" in sanitized
        assert "[REDACTED PHONE]" in sanitized # Use space, not hyphen
        assert "[REDACTED EMAIL]" in sanitized # Use space, not hyphen

    # Skipping sanitizer integration with logger test due to unreliable patching and logger caching.
    # def test_sanitizer_integration_with_logger(self, logger_setup):
    #     """Test the sanitizer's integration with the logging system."""
    #     logger, log_file = logger_setup
    #
    #     # Mock the sanitizer to check it's being called
    #     mock_sanitizer = MagicMock()
    #     mock_sanitizer.sanitize.return_value = "SANITIZED LOG MESSAGE"
    #
    #     # Patch the sanitizer in the logging system
    #     with patch('app.core.security.phi_sanitizer.PHISanitizer', return_value=mock_sanitizer):
    #         # Create a log message with PHI
    #         logger.info("Patient John Doe with SSN 123-45-6789 has updated their contact info to john.doe@example.com")
    #
    #         # Check that the sanitizer was called
    #         assert mock_sanitizer.sanitize.called

            #         # Verify the log file content
            #         with open(log_file, 'r') as f:
            #             log_content = f.read()
            #             assert "SANITIZED LOG MESSAGE" in log_content

    def test_phi_never_reaches_logs(self, logger_setup, monkeypatch):
        """End-to-end test ensuring PHI doesn't make it to logs."""
        # Set up a real sanitizer that will be used by the logging system
        # Use the correct infrastructure LogSanitizer
        real_sanitizer = LogSanitizer()

        # Patch the LogSanitizer class where it's instantiated by PHIFormatter
        # When PHIFormatter calls LogSanitizer(), it will get our instance.
        monkeypatch.setattr(
            'app.infrastructure.security.phi.log_sanitizer.LogSanitizer',
            lambda *args, **kwargs: real_sanitizer
        )

        logger, log_file = logger_setup

        # Create sensitive log messages with PHI
        logger.info("New appointment for John Doe (johndoe@example.com)")
        logger.warning("Failed login attempt for SSN: 123-45-6789")
        logger.error("Patient with phone number (555) 123-4567 reported an issue")

        # Read the log file and check for PHI
        with open(log_file) as f:
            log_content = f.read()

        # Verify no PHI is present
        assert "John Doe" not in log_content
        assert "johndoe@example.com" not in log_content
        assert "123-45-6789" not in log_content
        assert "(555) 123-4567" not in log_content

        # Verify redaction markers are present
        assert "[REDACTED NAME]" in log_content
        assert "[REDACTED EMAIL]" in log_content
        assert "[REDACTED SSN]" in log_content
        assert "[REDACTED PHONE]" in log_content

    def test_sanitization_performance(self):
        """Test the performance of log sanitization on large log entries."""
        sanitizer = LogSanitizer() # Use infrastructure sanitizer

        # Create a large log message with some PHI scattered throughout
        log_parts = []
        for i in range(100):
            if i % 10 == 0:
                log_parts.append(f"Patient-{i} John Smith (SSN: 123-45-6789)")
            else:
                log_parts.append(f"Normal log entry {i} with no PHI")

        large_log = " | ".join(log_parts)

        # Time the sanitization
        import time
        start_time = time.time()
        sanitized = sanitizer.sanitize(large_log)
        end_time = time.time()

        # Ensure all PHI is sanitized
        assert "John Smith" not in sanitized
        assert "123-45-6789" not in sanitized

        # Performance assertion - sanitization should be reasonably fast
        # Even for large log entries, sanitization should complete in under
        # 50ms
        assert (end_time - start_time) < 0.05, "Sanitization took too long"

if __name__ == "__main__":
    # Run the tests directly if the file is executed
    pytest.main(["-v", __file__])
