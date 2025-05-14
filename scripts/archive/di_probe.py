#!/usr/bin/env python3
"""
DI Probe Script

This script verifies the DI container wiring for XGBoostInterface and the
get_xgboost_service alias.
"""
import sys
import os

# Ensure 'app' package is importable by adding backend/ to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

def main():
    # Deferred imports to catch errors during script runtime
    from app.infrastructure.di.container import get_container
    from app.api.routes.xgboost import get_xgboost_service
    from app.core.services.ml.xgboost.mock import MockXGBoostService
    from app.core.services.ml.xgboost.interface import XGBoostInterface

    container = get_container()
    # Create a mock service instance
    mock = MockXGBoostService()
    # Override the XGBoostInterface in the DI container
    container.override(XGBoostInterface, lambda: mock)

    # Probe 1: Direct container.resolve
    resolved = container.resolve(XGBoostInterface)
    print(f"container.resolve(XGBoostInterface) is mock: {resolved is mock}")

    # Probe 2: get_xgboost_service alias
    alias_resolved = get_xgboost_service()
    print(f"get_xgboost_service() is mock: {alias_resolved is mock}")

    # Probe 3: Method invocation count
    # Reset mock if it has call count attributes
    try:
        initial_calls = getattr(mock, 'predict_risk').call_count
    except Exception:
        initial_calls = None
    # Invoke predict_risk via alias
    try:
        service = get_xgboost_service()
        service.predict_risk(patient_id="p1", risk_type="test", clinical_data={"x":1}, time_frame_days=1)
    except Exception:
        pass  # ignore prediction errors
    # Check call count if available
    try:
        final_calls = getattr(mock, 'predict_risk').call_count
    except Exception:
        final_calls = None
    print(f"Mock predict_risk call_count changed: {initial_calls} -> {final_calls}")

if __name__ == '__main__':
    try:
        main()
    except Exception:
        import traceback
        traceback.print_exc()
