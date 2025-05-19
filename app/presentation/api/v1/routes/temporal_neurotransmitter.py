"""
Temporal Neurotransmitter Endpoints Module.

Provides API endpoints related to temporal neurotransmitter analysis.
"""

from typing import Any, Dict, List
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.application.services.temporal_neurotransmitter_service import (
    TemporalNeurotransmitterService,
)
from app.domain.entities.digital_twin_enums import BrainRegion, Neurotransmitter
from app.presentation.api.dependencies.auth import (
    get_current_user,
    verify_provider_access,
)
from app.infrastructure.di.dependencies import get_service_factory

router = APIRouter(
    prefix="/temporal-neurotransmitter",
    tags=["temporal-neurotransmitter"],
    dependencies=[Depends(get_current_user)],
)


# Request/Response Models
class TimeSeriesRequest(BaseModel):
    """Request model for time series generation."""

    patient_id: UUID
    brain_region: BrainRegion
    neurotransmitter: Neurotransmitter
    time_range_days: int = Field(ge=1, le=90, default=14)
    time_step_hours: int = Field(ge=1, le=24, default=6)


class TimeSeriesResponse(BaseModel):
    """Response model for time series generation."""

    sequence_id: UUID


class TreatmentSimulationRequest(BaseModel):
    """Request model for treatment simulation."""

    patient_id: UUID
    brain_region: BrainRegion
    target_neurotransmitter: Neurotransmitter
    treatment_effect: float = Field(ge=-1.0, le=1.0)
    simulation_days: int = Field(ge=1, le=90, default=14)


class TreatmentSimulationResponse(BaseModel):
    """Response model for treatment simulation."""

    sequence_ids: Dict[str, str]


class VisualizationDataRequest(BaseModel):
    """Request model for visualization data."""

    sequence_id: UUID


class VisualizationDataResponse(BaseModel):
    """Response model for visualization data."""

    time_points: List[str]
    features: List[str]
    values: List[List[float]]
    metadata: Dict[str, Any] = {}


class AnalyzeNeurotransmitterRequest(BaseModel):
    patient_id: UUID
    brain_region: BrainRegion
    neurotransmitter: Neurotransmitter


class AnalysisResponse(BaseModel):
    neurotransmitter: str
    brain_region: str
    effect_size: float
    confidence_interval: List[float] = None
    p_value: float = None
    is_statistically_significant: bool
    clinical_significance: str = None
    time_series_data: List[List[Any]] = []
    comparison_periods: Dict[str, List[str]] = {}


class CascadeVisualizationRequest(BaseModel):
    patient_id: UUID
    starting_region: BrainRegion
    neurotransmitter: Neurotransmitter
    time_steps: int = 10


class CascadeVisualizationResponse(BaseModel):
    regions: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    time_steps: int
    starting_region: str
    neurotransmitter: str


async def get_temporal_neurotransmitter_service() -> TemporalNeurotransmitterService:
    """Dependency provider for TemporalNeurotransmitter service."""
    service_factory = get_service_factory()
    return await service_factory.get_temporal_neurotransmitter_service()


@router.post(
    "/time-series",
    response_model=TimeSeriesResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a neurotransmitter time series",
    description="Generate a time series for a specific neurotransmitter in a brain region.",
)
async def generate_time_series(
    request: TimeSeriesRequest,
    service_factory=Depends(get_service_factory),
    _verify_access=Depends(verify_provider_access),
) -> TimeSeriesResponse:
    """Generate a neurotransmitter time series."""
    try:
        # Get service from factory
        service = await service_factory.create_temporal_neurotransmitter_service()

        # Generate time series
        sequence_id = await service.generate_neurotransmitter_time_series(
            patient_id=request.patient_id,
            brain_region=request.brain_region,
            neurotransmitter=request.neurotransmitter,
            time_range_days=request.time_range_days,
            time_step_hours=request.time_step_hours,
        )

        return TimeSeriesResponse(sequence_id=sequence_id)
    except Exception as e:
        # HIPAA-compliant error message with no PHI
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error generating time series: {str(e)}",
        )


@router.post(
    "/simulate-treatment",
    response_model=TreatmentSimulationResponse,
    summary="Simulate treatment effect on neurotransmitters",
    description="Simulate how a treatment affects neurotransmitter levels over time.",
)
async def simulate_treatment(
    request: TreatmentSimulationRequest,
    service_factory=Depends(get_service_factory),
    _verify_access=Depends(verify_provider_access),
) -> TreatmentSimulationResponse:
    """Simulate treatment effect on neurotransmitters."""
    try:
        # Get service from factory
        service = await service_factory.create_temporal_neurotransmitter_service()

        # Simulate treatment
        sequence_ids = await service.simulate_treatment_response(
            patient_id=request.patient_id,
            brain_region=request.brain_region,
            target_neurotransmitter=request.target_neurotransmitter,
            treatment_effect=request.treatment_effect,
            simulation_days=request.simulation_days,
        )

        # Convert UUIDs to strings for JSON serialization
        sequence_ids_str = {
            nt.value: str(seq_id) for nt, seq_id in sequence_ids.items()
        }

        return TreatmentSimulationResponse(sequence_ids=sequence_ids_str)
    except Exception as e:
        # HIPAA-compliant error message with no PHI
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error simulating treatment: {str(e)}",
        )


@router.post(
    "/visualization-data",
    response_model=VisualizationDataResponse,
    summary="Get data for visualization",
    description="Get processed data for visualizing a temporal sequence.",
)
async def get_visualization_data(
    request: VisualizationDataRequest,
    service_factory=Depends(get_service_factory),
    _verify_access=Depends(verify_provider_access),
) -> VisualizationDataResponse:
    """Get data for visualization."""
    try:
        # Get service from factory
        service = await service_factory.create_temporal_neurotransmitter_service()

        # Get sequence
        sequence = await service.sequence_repository.get_by_id(request.sequence_id)
        if not sequence:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Sequence with ID {request.sequence_id} not found",
            )

        # Prepare data for visualization
        time_points = [tp.time_value for tp in sequence.time_points]

        # Ensure we have feature names
        if not sequence.feature_names:
            # Use the keys from the first time point
            feature_names = (
                list(sequence.time_points[0].data.keys())
                if sequence.time_points
                else []
            )
        else:
            feature_names = sequence.feature_names

        # Extract values for each feature at each time point
        values = []
        for feature in feature_names:
            feature_values = [tp.data.get(feature, 0.0) for tp in sequence.time_points]
            values.append(feature_values)

        return VisualizationDataResponse(
            time_points=[str(tp) for tp in time_points],
            features=feature_names,
            values=values,
            metadata=sequence.metadata,
        )
    except HTTPException:
        raise
    except Exception as e:
        # HIPAA-compliant error message with no PHI
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting visualization data: {str(e)}",
        )


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze neurotransmitter levels",
)
async def analyze_neurotransmitter(
    request: AnalyzeNeurotransmitterRequest = Body(...),
    service: TemporalNeurotransmitterService = Depends(
        get_temporal_neurotransmitter_service
    ),
    current_user: dict = Depends(get_current_user),
) -> Any:
    """Analyze neurotransmitter levels for a patient."""
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
        "is_statistically_significant": effect.p_value is not None
        and effect.p_value < 0.05,
        "clinical_significance": effect.clinical_significance.value
        if effect.clinical_significance
        else None,
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
    service: TemporalNeurotransmitterService = Depends(
        get_temporal_neurotransmitter_service
    ),
    current_user: dict = Depends(get_current_user),
) -> Any:
    """Get visualization data for neurotransmitter cascade effects."""
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


__all__ = [
    "get_current_user",
    "get_temporal_neurotransmitter_service",
    "router",
    "verify_provider_access",
]
