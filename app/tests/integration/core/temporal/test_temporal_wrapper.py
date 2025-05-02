"""
Integration test wrapper for temporal neurotransmitter system.

This wrapper avoids directly importing the router to prevent
FastAPI from analyzing AsyncSession dependencies at module import time.
"""
import pytest

pytest.skip("Skipping temporal wrapper integration tests: pending refactor", allow_module_level=True)
from unittest.mock import AsyncMock, patch
from uuid import UUID

# Import the service directly (no router import)
from app.application.services.temporal_neurotransmitter_service import (
    TemporalNeurotransmitterService,
)
from app.domain.entities.digital_twin_enums import BrainRegion, Neurotransmitter


@pytest.mark.asyncio
@pytest.mark.db_required
async def test_temporal_endpoints_integration(
    test_client,
    mock_current_user,
    temporal_service: TemporalNeurotransmitterService,
    patient_id: UUID
):
    """
    Test API integration with the neurotransmitter service.

    This test verifies that the API layer correctly integrates with the service layer
    without directly importing the router module.
    """
    # Setup - patch dependencies to use our service instance
    with mock_current_user, patch(
        "app.api.routes.temporal_neurotransmitter.get_temporal_neurotransmitter_service",
        new=AsyncMock(return_value=temporal_service)
    ):
        # Test 1: Generate time series
        time_series_response = test_client.post(
            "/api/v1/temporal-neurotransmitter/time-series",
            json={
                "patient_id": str(patient_id),
                "brain_region": BrainRegion.PREFRONTAL_CORTEX.value,
                "neurotransmitter": Neurotransmitter.SEROTONIN.value,
                "time_range_days": 14,
                "time_step_hours": 6
            }
        )
        
        # Verify response
        assert time_series_response.status_code == 201
        assert "sequence_id" in time_series_response.json()
        
        # Test 2: Simulate treatment
        treatment_response = test_client.post(
            "/api/v1/temporal-neurotransmitter/simulate-treatment",
            json={
                "patient_id": str(patient_id),
                "brain_region": BrainRegion.PREFRONTAL_CORTEX.value,
                "target_neurotransmitter": Neurotransmitter.SEROTONIN.value,
                "treatment_effect": 0.5,
                "simulation_days": 14
            }
        )
        
        # Verify response
        assert treatment_response.status_code == 200
        assert "sequence_ids" in treatment_response.json()
        
        # Extract a sequence ID for visualization test
        first_sequence_id = list(treatment_response.json()["sequence_ids"].values())[0]
        
        # Test 3: Get visualization data
        viz_response = test_client.post(
            "/api/v1/temporal-neurotransmitter/visualization-data",
            json={
                "sequence_id": first_sequence_id
            }
        )
        
        # Verify response
        assert viz_response.status_code == 200
        assert "time_points" in viz_response.json()
        assert "features" in viz_response.json()
        assert "values" in viz_response.json()