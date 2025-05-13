"""
Audit utilities for HIPAA-compliant access logging.

This module provides audit logging capabilities to track and record
access to Protected Health Information (PHI) and other security-relevant events.
"""

from app.core.utils.audit.logger import audit_logger

__all__ = ["audit_logger"] 