"""Top‑level *sitecustomize* entry‑point wrapper (relocated).

Originally this file lived in the repository root so that Python would import
it automatically when the test‑runner was started from the same directory.  It
delegates to :pymod:`sitecustomize`, inserting the *backend*
directory into *sys.path* if necessary so the real implementation can be
resolved.

Placing the wrapper inside *backend* keeps the project tidy.  Import it
manually when you need the original behaviour outside the test harness:

    import bootstrap.sitecustomize_wrapper  # noqa: F401 – side‑effects
"""

from __future__ import annotations

import importlib as _importlib
import sys as _sys
from pathlib import Path as _Path

# ---------------------------------------------------------------------------
# Ensure *app* is importable (assuming the main code is now in 'app')
# ---------------------------------------------------------------------------

_repo_root = _Path(__file__).resolve().parent.parent
# No longer need to add 'backend' to sys.path if structure is flattened
# _app_dir = _repo_root / "app" # Adjust if your main package is named differently
# if str(_app_dir) not in _sys.path:
#     _sys.path.insert(0, str(_app_dir))

# ---------------------------------------------------------------------------
# Delegate to the actual implementation and re‑export its public symbols
# ---------------------------------------------------------------------------

_impl = _importlib.import_module("sitecustomize")  # Changed module path

# Guarantee singleton behaviour across alias imports.
_sys.modules.setdefault("sitecustomize", _impl)

# Re‑export to support ``from sitecustomize import X``.
globals().update(_impl.__dict__)
