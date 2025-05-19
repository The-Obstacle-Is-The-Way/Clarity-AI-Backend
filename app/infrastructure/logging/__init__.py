"""
Logging infrastructure for the Novamind Digital Twin Platform.

This package provides HIPAA-compliant logging mechanisms, including
audit logging for PHI access and secure error logging.
"""

# Make the *audit_logger* sub‑module easily importable via
# ``app.infrastructure.logging.audit_logger``.  Without explicitly importing
# it here, the attribute lookup performed by ``unittest.mock.patch`` in the
# security/ HIPAA test‑suite fails with *AttributeError* because sub‑modules
# are not automatically added to their parent package’s namespace.

from importlib import import_module as _import_module

# Lazy‑import to avoid unnecessary overhead for production code paths that do
# not touch the audit logger.  The module is imported once on first package
# initialisation which is sufficient for the test‑suite’s reflective access.
_import_module("app.infrastructure.logging.audit_logger")

# Re‑export primary helper so callers can simply do:
#     from app.infrastructure.logging import get_logger
# which is used widely across the code‑base.

from .logger import get_logger  # noqa: F401  (re‑export)
