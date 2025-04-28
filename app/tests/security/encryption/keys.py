"""
Test keys for deterministic encryption in unit tests.

These keys are ONLY for test purposes and should never be used in production.
"""

# Standard test key
TEST_KEY = "test_key_for_unit_tests_only_12345678"

# Alternative key for rotation testing
TEST_KEY_2 = "different_test_key_for_unit_tests_456"

# Key for tampering detection tests
TAMPER_TEST_KEY = "tamper_detection_test_key_098765432"

# Fixed sensitive data for tests
TEST_SENSITIVE_DATA = {
    "address": "123 Main St, Anytown, USA",
    "date_of_birth": "1980-01-01",
    "diagnosis": "F41.1",
    "medication": "Sertraline 50mg",
    "patient_id": "12345",
    "provider": "Dr. Smith",
    "treatment_plan": "Weekly therapy",
    "ssn": "123-45-6789",
    "name": "John Smith",
}
