"""
API endpoints for the Temporal Neurotransmitter System.

Provides FastAPI routes for generating and analyzing neurotransmitter time series,
simulating treatments, and retrieving visualization data.
"""
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Body
from pydantic import BaseModel

from app.api.routes.temporal_neurotransmitter import (
    get_temporal_neurotransmitter_service,
    get_current_user,
    verify_provider_access,
)
from app.application.services.temporal_neurotransmitter_service import TemporalNeurotransmitterService
from app.domain.entities.digital_twin_enums import BrainRegion, Neurotransmitter

router = APIRouter(tags=["Temporal Neurotransmitter"])

class TimeSeriesGenerateRequest(BaseModel):
    patient_id: UUID
    brain_region: BrainRegion
    neurotransmitter: Neurotransmitter
    time_range_days: int = 14
    time_step_hours: int = 6

class TimeSeriesGenerateResponse(BaseModel):
    sequence_id: UUID
    patient_id: UUID
    brain_region: str
    neurotransmitter: str
    time_range_days: int
    time_step_hours: int

class TreatmentSimulationRequest(BaseModel):
    patient_id: UUID
    brain_region: BrainRegion
    target_neurotransmitter: Neurotransmitter
    treatment_effect: float
    simulation_days: int = 14

class TreatmentSimulationResponse(BaseModel):
    sequence_ids: Dict[str, UUID]
    patient_id: UUID
    brain_region: str
    target_neurotransmitter: str
    treatment_effect: float
    simulation_days: int

class VisualizationDataRequest(BaseModel):
    sequence_id: UUID
    focus_features: Optional[List[str]] = None

class VisualizationDataResponse(BaseModel):
    time_points: List[str]
    features: List[str]
    values: List[List[float]]
    metadata: Optional[Dict[str, Any]] = None

class AnalyzeNeurotransmitterRequest(BaseModel):
    patient_id: UUID
    brain_region: BrainRegion
    neurotransmitter: Neurotransmitter

class AnalysisResponse(BaseModel):
    neurotransmitter: str
    brain_region: str
    effect_size: float
    confidence_interval: Optional[List[float]]
    p_value: Optional[float]
    is_statistically_significant: bool
    clinical_significance: Optional[str]
    time_series_data: List[List[Any]]
    comparison_periods: Dict[str, List[str]]

class CascadeVisualizationRequest(BaseModel):
    patient_id: UUID
    starting_region: BrainRegion
    neurotransmitter: Neurotransmitter
    time_steps: int = 3

class CascadeVisualizationResponse(BaseModel):
    nodes: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    time_steps: List[Dict[str, Any]]
    metadata: Optional[Dict[str, Any]] = None

@router.post(
    "/time-series",
    response_model=TimeSeriesGenerateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate neurotransmitter time series",
)
async def generate_time_series(
    request: TimeSeriesGenerateRequest = Body(...),
    service: TemporalNeurotransmitterService = Depends(get_temporal_neurotransmitter_service),
    current_user: dict = Depends(get_current_user),
) -> Any:
    sequence_id = await service.generate_neurotransmitter_time_series(
        patient_id=request.patient_id,
        brain_region=request.brain_region,
        neurotransmitter=request.neurotransmitter,
        time_range_days=request.time_range_days,
        time_step_hours=request.time_step_hours,
    )
    return {
        "sequence_id": sequence_id,
        "patient_id": request.patient_id,
        "brain_region": request.brain_region.value,
        "neurotransmitter": request.neurotransmitter.value,
        "time_range_days": request.time_range_days,
        "time_step_hours": request.time_step_hours,
    }

@router.post(
    "/simulate-treatment",
    response_model=TreatmentSimulationResponse,
    status_code=status.HTTP_200_OK,
    summary="Simulate treatment response",
)
async def simulate_treatment(
    request: TreatmentSimulationRequest = Body(...),
    service: TemporalNeurotransmitterService = Depends(get_temporal_neurotransmitter_service),
    current_user: dict = Depends(get_current_user),
) -> Any:
    sequence_ids = await service.simulate_treatment_response(
        patient_id=request.patient_id,
        brain_region=request.brain_region,
        target_neurotransmitter=request.target_neurotransmitter,
        treatment_effect=request.treatment_effect,
        simulation_days=request.simulation_days,
    )
    return {
        "sequence_ids": {k: v for k, v in sequence_ids.items()} if isinstance(sequence_ids, dict) else sequence_ids,
        "patient_id": request.patient_id,
        "brain_region": request.brain_region.value,
        "target_neurotransmitter": request.target_neurotransmitter.value,
        "treatment_effect": request.treatment_effect,
        "simulation_days": request.simulation_days,
    }

@router.post(
    "/visualization-data",
    response_model=VisualizationDataResponse,
    status_code=status.HTTP_200_OK,
    summary="Get visualization data",
)
async def get_visualization_data(
    request: VisualizationDataRequest = Body(...),
    service: TemporalNeurotransmitterService = Depends(get_temporal_neurotransmitter_service),
    current_user: dict = Depends(get_current_user),
) -> Any:
    data = await service.get_visualization_data(
        sequence_id=request.sequence_id,
        focus_features=request.focus_features,
    )
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No data found for sequence {request.sequence_id}",
        )
    return data

@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze neurotransmitter levels",
)
async def analyze_neurotransmitter(
    request: AnalyzeNeurotransmitterRequest = Body(...),
    service: TemporalNeurotransmitterService = Depends(get_temporal_neurotransmitter_service),
    current_user: dict = Depends(get_current_user),
) -> Any:
    effect = await service.analyze_patient_neurotransmitter_levels(
        patient_id=request.patient_id,
        brain_region=request.brain_region,
        neurotransmitter=request.neurotransmitter,
    )
    if not effect:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No data found for patient {request.patient_id} with {request.neurotransmitter.value} in {request.brain_region.value}",
        )
    # Format response
    time_series_data = [[ts.isoformat(), val] for ts, val in effect.time_series_data]
    comparison_periods: Dict[str, List[str]] = {}
    if effect.baseline_period:
        comparison_periods["baseline"] = [
            effect.baseline_period[0].isoformat(),
            effect.baseline_period[1].isoformat(),
        ]
    if effect.comparison_period:
        comparison_periods["comparison"] = [
            effect.comparison_period[0].isoformat(),
            effect.comparison_period[1].isoformat(),
        ]
    return {
        "neurotransmitter": effect.neurotransmitter.value,
        "brain_region": effect.brain_region.value,
        "effect_size": effect.effect_size,
        "confidence_interval": effect.confidence_interval,
        "p_value": effect.p_value,
        "is_statistically_significant": effect.p_value is not None and effect.p_value < 0.05,
        "clinical_significance": effect.clinical_significance.value if effect.clinical_significance else None,
        "time_series_data": time_series_data,
        "comparison_periods": comparison_periods,
    }

@router.post(
    "/cascade-visualization",
    response_model=CascadeVisualizationResponse,
    status_code=status.HTTP_200_OK,
    summary="Get cascade visualization",
)
async def get_cascade_visualization(
    request: CascadeVisualizationRequest = Body(...),
    service: TemporalNeurotransmitterService = Depends(get_temporal_neurotransmitter_service),
    current_user: dict = Depends(get_current_user),
) -> Any:
    data = await service.get_cascade_visualization(
        patient_id=request.patient_id,
        starting_region=request.starting_region,
        neurotransmitter=request.neurotransmitter,
        time_steps=request.time_steps,
    )
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No cascade data found for patient {request.patient_id} with {request.neurotransmitter.value} in {request.starting_region.value}",
        )
    return data