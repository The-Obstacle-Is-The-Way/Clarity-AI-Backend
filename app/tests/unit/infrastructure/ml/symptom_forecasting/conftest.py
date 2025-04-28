"""Configuration for symptom forecasting tests.

This conftest.py contains hooks to ensure proper test collection and module patching
for symptom forecasting tests.
"""

import pytest
import sys
import os

# Only clean up module imports that might cause issues
for key in list(sys.modules.keys()):
    if key.startswith("xgboost.") and "tests" in key:
        del sys.modules[key]
