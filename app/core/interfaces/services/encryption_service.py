"""Encryption service interface for clean architecture.

Defines the contract for encryption providers used across layers. Keeping it in
`core.interfaces` avoids infrastructure-layer leakage and lets middleware or
services depend on abstractions.
"""

from __future__ import annotations

from typing import Protocol


class IEncryptionService(Protocol):
    """Abstraction over encryption utilities.

    Any concrete implementation must provide symmetric *encrypt* and *decrypt*
    operations that take/return ``str``. Optional ``generate_hash`` supports
    deterministic hashing for deduplication.
    """

    # --- Primary crypto operations -------------------------------------------------
    def encrypt(self, plaintext: str, *, key: str | None = None) -> str:
        """Encrypt *plaintext* returning a base-64-safe cipher-text string."""

    def decrypt(self, ciphertext: str, *, key: str | None = None) -> str:
        """Decrypt *ciphertext* back to UTF-8 text."""

    # --- Optional helpers ----------------------------------------------------------
    def generate_hash(self, value: str, *, salt: str | None = None) -> str:
        """Return a reproducible cryptographic hash for *value*."""
