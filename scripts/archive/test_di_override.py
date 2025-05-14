#!/usr/bin/env python3
"""
Smoke test for DI override of XGBoostInterface.
"""
import os
import sys
import asyncio

# Ensure backend/ is on the import path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASE_DIR)

from unittest.mock import MagicMock

from app.infrastructure.di.container import get_container, get_service
from app.core.services.ml.xgboost.interface import XGBoostInterface


def main():
    # Create and register a fresh mock
    mock_svc = MagicMock(spec=XGBoostInterface)
    mock_svc.predict_risk = MagicMock(return_value={'foo': 'bar'})

    container = get_container()
    container.override(XGBoostInterface, lambda: mock_svc)

    # 1. Direct resolve
    raw = container.resolve(XGBoostInterface)
    print("1) container.resolve -> mock?", raw is mock_svc)

    # 2. Using get_service(...) to simulate FastAPI Depends
    provider = get_service(XGBoostInterface)
    provided = provider() if callable(provider) else provider
    print("2) get_service -> mock?", provided is mock_svc)

    # 3. Call predict_risk and inspect call_count
    before = mock_svc.predict_risk.call_count
    out = provided.predict_risk(patient_id='x', risk_type='y', clinical_data={})
    # handle coroutine
    result = asyncio.get_event_loop().run_until_complete(out) if asyncio.iscoroutine(out) else out
    after = mock_svc.predict_risk.call_count
    print("3) predict_risk invoked?", after == before + 1)
    print("   result:", result)

if __name__ == '__main__':
    main()