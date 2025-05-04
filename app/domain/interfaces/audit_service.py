"""Audit service interface.

This minimal interface exists to satisfy runtime imports performed by
``app.infrastructure.logging.audit_logger`` during test collection.  The
full‑fledged implementation lives in the *infrastructure* layer; the domain
layer only needs to expose the abstractions so that higher‑level components
can depend on it without creating an undesirable circular import.

The production codebase does not (yet) depend on this interface directly, so
we purposefully keep it lean – introducing new methods as they become
necessary while refactoring the audit logging vertical.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AuditService(ABC):
    """Contract for audit logging services.

    Concrete implementations are expected to reside in the *infrastructure*
    layer where they can interact with external systems (databases, SIEM,
    cloud logging providers, …) while this domain‑level abstraction shields
    the rest of the application from those details.
    """

    # ---------------------------------------------------------------------
    # PHI / access logging
    # ---------------------------------------------------------------------

    @abstractmethod
    def log_phi_access(
        self,
        *,
        user_id: str,
        patient_id: str,
        action: str,
        details: dict[str, Any] | None = None,
    ) -> None:  # pragma: no cover – interface only
        """Record an access event involving Protected Health Information."""

    # ---------------------------------------------------------------------
    # Security / compliance events
    # ---------------------------------------------------------------------

    @abstractmethod
    def log_security_event(
        self,
        *,
        event_type: str,
        user_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:  # pragma: no cover – interface only
        """Record a security‑relevant event (authentication failure, …)."""
