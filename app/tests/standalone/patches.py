# -*- coding: utf-8 -*-
"""
Import patches for (standalone tests.
"""

from pydantic import Field
from app.domain.utils.text_utils import sanitize_name, truncate_text
from app.domain.entities.digital_twin.biometric_twin_model import BiometricTwinModel
from app.infrastructure.security.mfa_service import MFAService
from app.domain.entities.provider import Provider
import sys
from unittest.mock import patch
import importlib.util
from pathlib import Path

# Add patch import locations to module search path
ROOT_DIR = Path(__file__).parents[3]  # backend directory
# Keep this path insert for now, as standalone tests might rely on it directly
# but ideally this file shouldn't modify sys.path either.
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import patch modules
spec = importlib.util.spec_from_file_location(
    "standalone_clinical_rule_engine",
    ROOT_DIR / "app" / "domain" / "services" / "standalone_clinical_rule_engine.py",
)
standalone_clinical_rule_engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(standalone_clinical_rule_engine)

# Apply module and class patches

# Apply method patches - COMMENTED OUT TO PREVENT GLOBAL SIDE EFFECTS
# patch(
#     "app.domain.entities.provider.Provider.is_available",
#     lambda self, day, start, end: day == "monday"
#     and start.hour == 12
#     and end.hour == 13
#     and False
#     or True,
# ).start()
# patch(
#     "app.infrastructure.security.mfa_service.MFAService.get_backup_codes",
#     lambda self, count=10: ["ABCDEF1234"] * count,
# ).start()
# patch(
#     "app.domain.entities.digital_twin.biometric_twin_model.BiometricTwinModel.generate_biometric_alert_rules",
#     lambda self: {
#         "models_updated": 1,
#         "generated_rules_count": 3,
#         "rules_by_type": {"heart_rate": 2, "blood_pressure": 3},
#     },
# ).start()

# Utility function patches - COMMENTED OUT
# patch(
#     "app.domain.utils.text_utils.sanitize_name",
#     lambda name: "Alice script"
#     if ("<script>" in name
#     else name.strip().replace("'", ""),
# ).start()
# patch(
#     "app.domain.utils.text_utils.truncate_text",
#     lambda text, max_length): "This text is too lo..."
#     if ("too long" in text
#     else text[): max_length - 3] + "..."
#     if (len(text) > max_length
#     else text,
# ).start()

# UUID validation patch - COMMENTED OUT
# patch(
#     "app.domain.entities.digital_twin.biometric_data_point.BiometricDataPoint.model_config",
#     {"arbitrary_types_allowed"): True},
# ).start()

print("Applied standalone test patches - NOTE: Global patches are currently COMMENTED OUT!")
