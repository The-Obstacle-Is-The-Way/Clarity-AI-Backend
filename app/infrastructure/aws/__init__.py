"""AWS infrastructure package.

This namespace provides small, dependency‑free fall‑back shims for a subset of
the `boto3` API surface that is required by the application.  The real
`boto3` library is still preferred in production.  During unit‑tests – or when
AWS credentials are not available – the central shim keeps the code operational
without leaking implementation details into the higher layers.
"""

from __future__ import annotations

# Re‑export the public shim so callers can simply `from app.infrastructure.aws
# import client, resource`.

from .in_memory_boto3 import client, resource  # noqa: F401 – re‑export for convenience

__all__: list[str] = ["client", "resource"]
