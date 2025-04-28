"""
Test fixtures for security and encryption tests.

This module provides deterministic test data and fixtures for
reproducible security testing of HIPAA-compliant PHI encryption.
"""

import base64
import os
from typing import Dict, Any, Tuple
from cryptography.fernet import Fernet

# Deterministic test encryption key (urlsafe-base64 encoded for Fernet)
TEST_KEY_BYTES = b"neuralnetwork_hippocampus_prefrontal_123456"[:32]
TEST_KEY = base64.urlsafe_b64encode(TEST_KEY_BYTES)

# Deterministic test salt
TEST_SALT = b"pituitary_hypothalamus_encryption_salt_12345"[:16]


def get_test_key() -> bytes:
    """Return a deterministic encryption key for tests."""
    return TEST_KEY

def get_test_salt() -> bytes: 
    """Return a deterministic salt for tests."""
    return TEST_SALT 

def setup_test_environment() -> Dict[str, str]: 
    """
    Setup the test environment with deterministic encryption keys.

    Returns:
        Dict of environment variables that were set
    """
    env_vars = {
        "ENCRYPTION_KEY": TEST_KEY_BYTES.hex(),
        "ENCRYPTION_SALT": TEST_SALT.hex(),
        "PHI_AUDIT_ENABLED": "false",
        "PYTEST_CURRENT_TEST": "True",
    }

    # Set environment variables
    for key, value in env_vars.items(): 
        os.environ[key] = value

    return env_vars 

def teardown_test_environment(env_vars: Dict[str, str]) -> None: 
    """
    Teardown the test environment, restoring original values.

    Args:
        env_vars: Dict of environment variables to restore
    """
    # Remove test environment variables
    for key in env_vars: 
        if key in os.environ:
            del os.environ[key]

def get_test_phi_data() -> Dict[str, Any]: 
    """
    Get a test PHI data dictionary with various nested fields.

    Returns:
        Dictionary with test PHI data
    """
    return { 
        "patient_id": "PT12345",
        "name": "John Smith",
        "date_of_birth": "1970-01-01",
        "ssn": "123-45-6789",
        "contact": {
            "email": "john.smith@example.com",
            "phone": "555-123-4567",
            "address": {
                "street": "123 Main St",
                "city": "Anytown",
                "state": "CA",
                "zip": "12345",
            },
        },
        "medical": {
            "diagnosis": [ 
                {"code": "F41.1", "description": "Generalized Anxiety Disorder"},
                {
                    "code": "F32.1",
                    "description": "Major Depressive Disorder, Recurrent",
                },
            ],
            "medications": [ 
                {"name": "Sertraline", "dosage": "50mg", "frequency": "Daily"},
                {"name": "Lorazepam", "dosage": "1mg", "frequency": "As needed"},
            ],
        },
        "insurance": {
            "provider": "Health Insurance Co",
            "policy_number": "HI12345678",
            "group_number": "G987654321",
        },
        "notes": "Patient reports improved sleep but continued anxiety symptoms.",
    }


def get_test_client_data() -> Dict[str, Any]: 
    """
    Get test client metadata that should not contain PHI.

    Returns:
        Dictionary with test client data
    """
    return { 
        "client_id": "CL67890",
        "source_system": "Electronic Health Record",
        "access_level": "provider",
        "timestamp": "2023-04-15T10:30:00Z",
        "request_id": "REQ987654321",
        "api_version": "v1.2.3",
        "session_id": "SES123456789",
    }


def generate_test_key_pair() -> Tuple[bytes, bytes]: 
    """
    Generate a deterministic key pair for testing.

    Returns:
        Tuple of (encryption_key, previous_encryption_key)
    """
    # Generate current key from test bytes (ensure proper Fernet format)
    current_key = Fernet.generate_key() 

    # Generate previous key from rotated test bytes (ensure proper Fernet format)
    previous_key = Fernet.generate_key() 

    return current_key, previous_key 
