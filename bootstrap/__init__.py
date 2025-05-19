import os

"""Interpreter customisation *bootstrap* utilities.

This sub‑package contains lightweight shims that **used** to live in the
repository root (``sitecustomize.py`` and ``usercustomize.py``).  Keeping them
inside *backend* avoids polluting the global module namespace while still
allowing developers to opt‑in by importing the wrappers explicitly:

    import bootstrap.sitecustomize_wrapper  # noqa: F401 – side‑effects

The preferred mechanism during automated test runs remains the explicit call
performed in *backend/conftest.py*.
"""

__all__: list[str] = [
    "sitecustomize_wrapper",
    "usercustomize_wrapper",
]

# Check if we are running inside a virtual environment
if "VIRTUAL_ENV" in os.environ:
    # Import the original sitecustomize only inside a venv
    import bootstrap.sitecustomize_wrapper  # noqa: F401 – side‑effects

"""Bootstrap logic to ensure consistent AWS SDK behavior across environments."""
