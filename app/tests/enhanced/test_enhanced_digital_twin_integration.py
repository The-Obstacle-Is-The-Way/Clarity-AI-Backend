"""
Integration tests for the Enhanced Digital Twin components.

These tests verify that the Enhanced Digital Twin components work together
correctly, including the core service, knowledge graph, belief network,
and event system.
"""
import datetime
import uuid
from uuid import UUID

import pytest

from app.domain.entities.digital_twin.temporal_neurotransmitter_sequence import (
    TemporalNeurotransmitterSequence,
)
from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    ClinicalInsightType,
    ClinicalSignificance,
    Neurotransmitter,
)
from app.domain.entities.knowledge_graph import (
    NodeType,
)
from app.domain.services.enhanced_digital_twin_core_service import (
    EnhancedDigitalTwinCoreService,
)
from app.domain.services.enhanced_mentalllama_service import EnhancedMentalLLaMAService
from app.domain.services.enhanced_pat_service import EnhancedPATService
from app.domain.services.enhanced_xgboost_service import EnhancedXGBoostService

# Commented out imports for missing schemas - requires further investigation
# from app.presentation.api.schemas.ml_schemas import (
#     DigitalTwinCreateRequest,
#     DigitalTwinResponse,
# )
from app.infrastructure.factories.enhanced_mock_digital_twin_factory import (
    EnhancedMockDigitalTwinFactory,
)


@pytest.fixture
def enhanced_services() -> (
    tuple[
        EnhancedDigitalTwinCoreService,
        EnhancedMentalLLaMAService,
        EnhancedXGBoostService,
        EnhancedPATService,
    ]
):
    """Fixture to create enhanced mock services for testing."""
    return EnhancedMockDigitalTwinFactory.create_enhanced_mock_services()


@pytest.fixture
def patient_id() -> UUID:
    """Fixture to create a consistent patient ID for tests."""
    return uuid.UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def initial_data() -> dict:
    """Fixture to provide initial patient data for testing."""
    return {
        "diagnoses": ["Major Depressive Disorder", "Generalized Anxiety Disorder"],
        "medications": [
            {
                "name": "Escitalopram",
                "dosage": "10mg",
                "frequency": "daily",
                "start_date": datetime.datetime.now() - datetime.timedelta(days=90),
            }
        ],
        "symptoms": [
            {"name": "depressed mood", "severity": 3},
            {"name": "anxiety", "severity": 2},
            {"name": "insomnia", "severity": 2},
        ],
        "assessments": [
            {
                "type": "PHQ-9",
                "score": 14,
                "date": datetime.datetime.now() - datetime.timedelta(days=30),
            },
            {
                "type": "GAD-7",
                "score": 12,
                "date": datetime.datetime.now() - datetime.timedelta(days=30),
            },
        ],
        "neurotransmitter_baseline": {
            "serotonin": 0.4,
            "dopamine": 0.5,
            "norepinephrine": 0.6,
            "gaba": 0.4,
            "glutamate": 0.7,
        },
    }


@pytest.mark.asyncio
async def test_digital_twin_initialization(enhanced_services, patient_id, initial_data) -> None:
    """Test initialization of the Enhanced Digital Twin."""
    digital_twin_service, _, _, _ = enhanced_services

    # Initialize the Digital Twin
    result = await digital_twin_service.initialize_digital_twin(
        patient_id=patient_id, initial_data=initial_data
    )

    # Verify initialization was successful
    assert result is not None
    assert result["patient_id"] == patient_id
    assert "status" in result
    assert result["status"] == "initialized"
    assert "knowledge_graph" in result
    assert "belief_network" in result

    # Verify the Digital Twin exists in the service
    twin_exists = await digital_twin_service.digital_twin_exists(patient_id)
    assert twin_exists is True


@pytest.mark.asyncio
async def test_knowledge_graph_operations(enhanced_services, patient_id, initial_data) -> None:
    """Test operations on the knowledge graph component."""
    digital_twin_service, _, _, _ = enhanced_services

    # Initialize the Digital Twin
    await digital_twin_service.initialize_digital_twin(
        patient_id=patient_id, initial_data=initial_data
    )

    # Add a new node to the knowledge graph
    node_id = await digital_twin_service.add_knowledge_node(
        patient_id=patient_id,
        node_type=NodeType.SYMPTOM,
        node_data={
            "name": "fatigue",
            "severity": 3,
            "onset_date": datetime.datetime.now() - datetime.timedelta(days=14),
        },
    )

    # Verify node was added
    assert node_id is not None

    # Add a relationship between nodes
    relationship_id = await digital_twin_service.add_knowledge_relationship(
        patient_id=patient_id,
        source_node_id=node_id,
        target_node_type=NodeType.DIAGNOSIS,
        relationship_type="symptom_of",
        relationship_data={"strength": 0.8, "evidence": "clinical_observation"},
    )

    # Verify relationship was added
    assert relationship_id is not None

    # Query the knowledge graph
    query_result = await digital_twin_service.query_knowledge_graph(
        patient_id=patient_id,
        query_type="node_relationships",
        parameters={"node_id": node_id, "relationship_types": ["symptom_of"]},
    )

    # Verify query results
    assert query_result is not None
    assert "relationships" in query_result
    assert len(query_result["relationships"]) > 0


@pytest.mark.asyncio
async def test_belief_network_operations(enhanced_services, patient_id, initial_data) -> None:
    """Test operations on the Bayesian belief network component."""
    digital_twin_service, _, _, _ = enhanced_services

    # Initialize the Digital Twin
    await digital_twin_service.initialize_digital_twin(
        patient_id=patient_id, initial_data=initial_data
    )

    # Update a belief in the network
    await digital_twin_service.update_belief(
        patient_id=patient_id,
        belief_node="treatment_response",
        evidence={"medication": "Escitalopram", "duration_weeks": 6},
        probability=0.75,
    )

    # Query the belief network
    query_result = await digital_twin_service.query_belief_network(
        patient_id=patient_id,
        query_node="remission",
        evidence={"treatment_response": "positive", "adherence": "high"},
    )

    # Verify query results
    assert query_result is not None
    assert "probability" in query_result
    assert 0 <= query_result["probability"] <= 1


@pytest.mark.asyncio
async def test_neurotransmitter_simulation(enhanced_services, patient_id, initial_data) -> None:
    """Test neurotransmitter simulation capabilities."""
    digital_twin_service, _, xgboost_service, _ = enhanced_services

    # Initialize the Digital Twin
    await digital_twin_service.initialize_digital_twin(
        patient_id=patient_id, initial_data=initial_data
    )

    # Run a neurotransmitter simulation
    simulation_result = await digital_twin_service.simulate_neurotransmitter_dynamics(
        patient_id=patient_id,
        intervention={
            "type": "medication",
            "target": Neurotransmitter.SEROTONIN,
            "effect": 0.3,
            "region": BrainRegion.PREFRONTAL_CORTEX,
        },
        duration_days=28,
        time_resolution_hours=24,
    )

    # Verify simulation results
    assert simulation_result is not None
    assert "timeline" in simulation_result
    assert len(simulation_result["timeline"]) > 0
    assert "neurotransmitter_levels" in simulation_result["timeline"][0]
    assert "clinical_effects" in simulation_result

    # Test the cascade effect analysis
    cascade_result = await xgboost_service.simulate_treatment_cascade(
        patient_id=patient_id,
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        treatment_effect=0.3,
        baseline_data=initial_data["neurotransmitter_baseline"],
    )

    # Verify cascade results
    assert cascade_result is not None
    assert "direct_effects" in cascade_result
    assert "indirect_effects" in cascade_result
    assert len(cascade_result["indirect_effects"]) > 0


@pytest.mark.asyncio
async def test_temporal_sequence_analysis(enhanced_services, patient_id, initial_data) -> None:
    """Test temporal sequence analysis capabilities."""
    digital_twin_service, _, _, _ = enhanced_services

    # Initialize the Digital Twin
    await digital_twin_service.initialize_digital_twin(
        patient_id=patient_id, initial_data=initial_data
    )

    # Create a temporal sequence
    sequence = TemporalNeurotransmitterSequence(
        patient_id=patient_id,
        start_time=datetime.datetime.now() - datetime.timedelta(days=30),
        end_time=datetime.datetime.now(),
        resolution_hours=24,
    )

    # Add data points to the sequence
    for day in range(30):
        timestamp = datetime.datetime.now() - datetime.timedelta(days=30 - day)
        sequence.add_data_point(
            timestamp=timestamp,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            value=0.4 + (day * 0.01),  # Gradually increasing
        )

    # Add the sequence to the Digital Twin
    await digital_twin_service.add_temporal_sequence(
        patient_id=patient_id,
        sequence=sequence,
    )

    # Analyze the temporal sequence
    analysis_result = await digital_twin_service.analyze_temporal_patterns(
        patient_id=patient_id,
        sequence_id=sequence.id,
        analysis_type="trend",
        parameters={"smoothing": "moving_average", "window_size": 3},
    )

    # Verify analysis results
    assert analysis_result is not None
    assert "trend" in analysis_result
    assert "significance" in analysis_result
    assert "correlation" in analysis_result


@pytest.mark.asyncio
async def test_clinical_insight_generation(enhanced_services, patient_id, initial_data) -> None:
    """Test generation of clinical insights from the Digital Twin."""
    digital_twin_service, mental_llama_service, _, _ = enhanced_services

    # Initialize the Digital Twin
    await digital_twin_service.initialize_digital_twin(
        patient_id=patient_id, initial_data=initial_data
    )

    # Generate clinical insights
    insights = await digital_twin_service.generate_clinical_insights(
        patient_id=patient_id,
        insight_types=[
            ClinicalInsightType.TREATMENT_RESPONSE,
            ClinicalInsightType.SYMPTOM_TRAJECTORY,
        ],
        time_range=(
            datetime.datetime.now() - datetime.timedelta(days=30),
            datetime.datetime.now(),
        ),
    )

    # Verify insights
    assert insights is not None
    assert len(insights) > 0

    # Check insight structure
    insight = insights[0]
    assert "type" in insight
    assert "description" in insight
    assert "significance" in insight
    assert "confidence" in insight
    assert "supporting_evidence" in insight

    # Verify significance is valid
    assert insight["significance"] in [
        ClinicalSignificance.HIGH.value,
        ClinicalSignificance.MEDIUM.value,
        ClinicalSignificance.LOW.value,
    ]

    # Test LLM-generated explanation
    explanation = await mental_llama_service.generate_insight_explanation(
        patient_id=patient_id,
        insight=insight,
        detail_level="detailed",
    )

    # Verify explanation
    assert explanation is not None
    assert "explanation" in explanation
    assert len(explanation["explanation"]) > 0


@pytest.mark.asyncio
async def test_treatment_response_prediction(enhanced_services, patient_id, initial_data) -> None:
    """Test prediction of treatment response using the Digital Twin."""
    digital_twin_service, _, xgboost_service, _ = enhanced_services

    # Initialize the Digital Twin
    await digital_twin_service.initialize_digital_twin(
        patient_id=patient_id, initial_data=initial_data
    )

    # Predict treatment response
    prediction = await digital_twin_service.predict_treatment_response(
        patient_id=patient_id,
        treatment={
            "type": "medication",
            "name": "Sertraline",
            "dosage": "50mg",
            "frequency": "daily",
        },
        prediction_timeframe_weeks=8,
    )

    # Verify prediction
    assert prediction is not None
    assert "response_probability" in prediction
    assert "confidence" in prediction
    assert "expected_symptom_changes" in prediction
    assert "expected_neurotransmitter_changes" in prediction

    # Verify XGBoost service integration
    xgboost_prediction = await xgboost_service.predict_treatment_response(
        patient_id=patient_id,
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        treatment_effect=0.4,
    )

    # Verify XGBoost prediction
    assert xgboost_prediction is not None
    assert "predicted_response" in xgboost_prediction
    assert "confidence" in xgboost_prediction
    assert "timeframe_days" in xgboost_prediction


@pytest.mark.asyncio
async def test_digital_twin_event_processing(enhanced_services, patient_id, initial_data) -> None:
    """Test event processing in the Digital Twin."""
    digital_twin_service, _, _, _ = enhanced_services

    # Initialize the Digital Twin
    await digital_twin_service.initialize_digital_twin(
        patient_id=patient_id, initial_data=initial_data
    )

    # Process a clinical event
    event_result = await digital_twin_service.process_clinical_event(
        patient_id=patient_id,
        event_type="medication_change",
        event_data={
            "medication": "Escitalopram",
            "change_type": "dosage_increase",
            "new_dosage": "20mg",
            "reason": "inadequate response",
            "timestamp": datetime.datetime.now(),
        },
    )

    # Verify event processing
    assert event_result is not None
    assert "event_id" in event_result
    assert "status" in event_result
    assert "effects" in event_result
    assert len(event_result["effects"]) > 0

    # Verify the event was recorded in the Digital Twin
    events = await digital_twin_service.get_clinical_events(
        patient_id=patient_id,
        event_types=["medication_change"],
        time_range=(
            datetime.datetime.now() - datetime.timedelta(hours=1),
            datetime.datetime.now() + datetime.timedelta(hours=1),
        ),
    )

    # Check events
    assert events is not None
    assert len(events) > 0
    assert events[0]["event_type"] == "medication_change"
    assert events[0]["event_data"]["medication"] == "Escitalopram"


@pytest.mark.asyncio
async def test_clinical_summary_generation(enhanced_services, patient_id, initial_data) -> None:
    """Test generation of a comprehensive clinical summary."""
    digital_twin_service, _, _, _ = enhanced_services

    # Initialize the Digital Twin
    await digital_twin_service.initialize_digital_twin(
        patient_id=patient_id, initial_data=initial_data
    )

    # Generate the summary
    summary = await digital_twin_service.generate_multimodal_clinical_summary(
        patient_id=patient_id,
        summary_types=["status", "trajectory"],
        time_range=(
            datetime.datetime.now() - datetime.timedelta(days=30),
            datetime.datetime.now(),
        ),
        detail_level="standard",
    )

    # Check summary structure
    assert summary is not None
    assert "metadata" in summary
    assert "sections" in summary
    assert "integrated_summary" in summary

    # Check that requested sections are present
    assert "status" in summary["sections"]
    assert "trajectory" in summary["sections"]


@pytest.mark.asyncio
async def test_visualization_data_generation(enhanced_services, patient_id, initial_data) -> None:
    """Test generation of visualization data."""
    digital_twin_service, _, _, _ = enhanced_services

    # Initialize the Digital Twin
    await digital_twin_service.initialize_digital_twin(
        patient_id=patient_id, initial_data=initial_data
    )

    # Generate brain model visualization data
    brain_viz = await digital_twin_service.generate_visualization_data(
        patient_id=patient_id,
        visualization_type="brain_model",
        parameters={"highlight_significant": True, "show_connections": True},
    )

    # Check visualization data
    assert brain_viz is not None
    assert "regions" in brain_viz
    assert len(brain_viz["regions"]) > 0

    # Check region data structure
    region = brain_viz["regions"][0]
    assert "id" in region
    assert "name" in region
    assert "activation" in region
