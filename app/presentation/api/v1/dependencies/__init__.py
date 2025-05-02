"""Thin dependency‑injection shims for the API v1 layer.

This package exists primarily so that *tests* can import / patch call‑paths
such as

    app.presentation.api.v1.dependencies.ml.get_mentallama_service

without relying on the full DI container.  Each function returns a minimal
stub implementation that fulfils the interface expected by the unit and
integration tests.
"""

from __future__ import annotations

from types import ModuleType
import sys
from typing import Optional

# Added imports
from fastapi import Depends
from sqlalchemy.orm import Session
from app.infrastructure.persistence.sqlalchemy.database import get_db_session
from app.domain.repositories.biometric_alert_rule_repository import BiometricRuleRepository
from app.infrastructure.repositories.sqlalchemy.biometric_alert_rule_repository import SQLAlchemyBiometricRuleRepository


def _lazy_submodule(name: str) -> ModuleType:  # pragma: no cover – helper
    """Create and register an empty module so that dotted imports succeed."""
    module = ModuleType(name)
    sys.modules[name] = module
    return module


# ---------------------------------------------------------------------------
# "ml" pseudo‑sub‑package
# ---------------------------------------------------------------------------

ml = _lazy_submodule(__name__ + ".ml")


def get_mentallama_service():  # noqa: D401 – simple factory
    """Return a stub MentalLLaMA service suitable for tests."""

    try:
        from app.infrastructure.services.mock_mentalllama_service import (  # type: ignore
            MockMentalLLaMAService,
        )
    except ModuleNotFoundError:  # fallback – define a trivial stub

        class MockMentalLLaMAService:  # type: ignore[too-many-public-methods]
            async def process(self, *args, **kwargs):
                return {"result": "ok"}

        return MockMentalLLaMAService()

    return MockMentalLLaMAService()


ml.get_mentallama_service = get_mentallama_service  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# "services" pseudo‑sub‑package
# ---------------------------------------------------------------------------

services = _lazy_submodule(__name__ + ".services")


def get_temporal_neurotransmitter_service():
    try:
        from app.infrastructure.services.mock_enhanced_digital_twin_core_service import (
            MockEnhancedDigitalTwinCoreService,
        )

        return MockEnhancedDigitalTwinCoreService()
    except ModuleNotFoundError:

        class StubService:  # fallback stub
            async def generate_time_series(self, *a, **kw):
                return {}

        return StubService()


services.get_temporal_neurotransmitter_service = (  # type: ignore[attr-defined]
    get_temporal_neurotransmitter_service
)


# Digital‑twin service shim (required by digital_twins endpoints)


def get_digital_twin_service():
    try:
        from app.infrastructure.services.mock_enhanced_digital_twin_core_service import (
            MockEnhancedDigitalTwinCoreService,
        )

        return MockEnhancedDigitalTwinCoreService()
    except ModuleNotFoundError:

        class StubDT:  # pragma: no cover – fallback
            async def generate(self, *_, **__):
                return {}

        return StubDT()


services.get_digital_twin_service = get_digital_twin_service  # type: ignore[attr-defined]
    
# ---------------------------------------------------------------------------
# Stub PAT service for compatibility
# ---------------------------------------------------------------------------
def get_pat_service():
    """Return a stub PAT service suitable for tests."""
    try:
        from app.infrastructure.services.mock_pat_service import MockPATService  # type: ignore
        return MockPATService()
    except ModuleNotFoundError:
        class StubPATService:
            async def initialize(self, *args, **kwargs):
                pass
            async def analyze_actigraphy(self, *args, **kwargs):
                return {}
            def get_model_info(self):
                return {}
        return StubPATService()

services.get_pat_service = get_pat_service  # type: ignore[attr-defined]


# Biometric Alert service shim (required by biometric_alerts endpoint)

def get_biometric_alert_service():
    """Return a stub BiometricAlertService suitable for tests."""
    try:
        # Attempt to import a dedicated mock service if it exists
        from app.infrastructure.services.mock_biometric_alert_service import (
            MockBiometricAlertService,  # type: ignore
        )
        return MockBiometricAlertService()
    except ModuleNotFoundError:
        # Fallback: Define a minimal stub if the mock is not found
        class StubBiometricAlertService:  # pragma: no cover – fallback
            async def create_alert(self, *args, **kwargs):
                return {"id": "stub_alert_id", "message": "Stub Alert"}
            async def get_alert_by_id(self, alert_id: str, *args, **kwargs):
                if alert_id == "stub_alert_id":
                    return {"id": "stub_alert_id", "message": "Stub Alert"}
                return None # Or raise appropriate not found error stub
            async def acknowledge_alert(self, alert_id: str, *args, **kwargs):
                 if alert_id == "stub_alert_id":
                     return {"id": "stub_alert_id", "message": "Acknowledged Stub Alert", "acknowledged": True}
                 return None # Or raise appropriate not found error stub
            async def list_alerts(self, *args, **kwargs):
                return []

        return StubBiometricAlertService()

services.get_biometric_alert_service = get_biometric_alert_service # type: ignore[attr-defined]


# Biometric Alert Rule service shim (required by biometric_alerts endpoint)

def get_biometric_alert_rule_service():
    """Return a stub BiometricAlertRuleService suitable for tests."""
    try:
        # Attempt to import a dedicated mock service if it exists
        from app.infrastructure.services.mock_biometric_alert_rule_service import (
            MockBiometricAlertRuleService,  # type: ignore
        )
        return MockBiometricAlertRuleService()
    except ModuleNotFoundError:
        # Fallback: Define a minimal stub if the mock is not found
        class StubBiometricAlertRuleService:  # pragma: no cover – fallback
            async def create_rule(self, *args, **kwargs):
                return {"id": "stub_rule_id", "name": "Stub Rule"}
            async def get_rule_by_id(self, rule_id: str, *args, **kwargs):
                if rule_id == "stub_rule_id":
                    return {"id": "stub_rule_id", "name": "Stub Rule"}
                return None # Or raise appropriate not found error stub
            async def update_rule(self, rule_id: str, *args, **kwargs):
                 if rule_id == "stub_rule_id":
                     return {"id": "stub_rule_id", "name": "Updated Stub Rule"}
                 return None # Or raise appropriate not found error stub
            async def delete_rule(self, rule_id: str, *args, **kwargs):
                if rule_id == "stub_rule_id":
                    return True
                return False # Or raise appropriate not found error stub
            async def list_rules(self, *args, **kwargs):
                return []

        return StubBiometricAlertRuleService()

services.get_biometric_alert_rule_service = get_biometric_alert_rule_service  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# "repositories" pseudo‑sub‑package
# ---------------------------------------------------------------------------

repositories = _lazy_submodule(__name__ + ".repositories")


def get_patient_repository():
    try:
        from app.infrastructure.repositories.mock_patient_repository import (
            MockPatientRepository,
        )

        return MockPatientRepository()
    except ModuleNotFoundError:

        class StubRepo:  # pragma: no cover – fallback
            async def get_by_id(self, *_, **__):
                return None

        return StubRepo()


repositories.get_patient_repository = get_patient_repository  # type: ignore[attr-defined]

# --- Biometric Rule Repository ---

def get_rule_repository(db: Session = Depends(get_db_session)) -> BiometricRuleRepository:
    """
    Dependency for getting the biometric rule repository.

    Args:
        db: Database session

    Returns:
        BiometricRuleRepository instance
    """
    return SQLAlchemyBiometricRuleRepository(db)

repositories.get_rule_repository = get_rule_repository # type: ignore[attr-defined]
