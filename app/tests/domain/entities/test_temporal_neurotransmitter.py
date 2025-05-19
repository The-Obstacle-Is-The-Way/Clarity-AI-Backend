"""
Tests for the temporal neurotransmitter mapping components.
Ensures proper functionality of the temporal extensions to the Digital Twin.
"""
import math
import uuid

import pytest

from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    ClinicalSignificance,
    ConnectionType,
    Neurotransmitter,
)
from app.domain.entities.neurotransmitter_effect import NeurotransmitterEffect
from app.domain.entities.neurotransmitter_mapping import (
    ReceptorProfile,
    ReceptorSubtype,
    ReceptorType,
    create_default_neurotransmitter_mapping,
)
from app.domain.entities.temporal_events import CorrelatedEvent, EventChain
from app.domain.entities.temporal_neurotransmitter_mapping import (
    extend_neurotransmitter_mapping,
)
from app.domain.entities.temporal_sequence import TemporalSequence
from app.domain.services.visualization_preprocessor import (
    NeurotransmitterEffectVisualizer,
    NeurotransmitterVisualizationPreprocessor,
)


@pytest.mark.db_required
class TestTemporalEvents:
    """Test suite for temporal event correlation tracking."""

    def test_correlated_event_creation(self):
        """Test creation of correlated events."""
        # Create a root event
        root_event = CorrelatedEvent(event_type="test_event", metadata={"test_key": "test_value"})

        # Verify root event properties
        assert root_event.event_type == "test_event"
        assert root_event.metadata["test_key"] == "test_value"
        assert root_event.parent_event_id is None
        assert root_event.id is not None
        assert root_event.correlation_id is not None

        # Create a child event
        child_event = CorrelatedEvent.create_child_event(
            parent_event=root_event,
            event_type="child_event",
            metadata={"additional_data": "child_data"},
        )

        # Verify child event properties
        assert child_event.event_type == "child_event"
        assert child_event.metadata["additional_data"] == "child_data"
        assert child_event.parent_event_id == root_event.id
        assert child_event.correlation_id == root_event.correlation_id

    def test_event_chain_creation(self):
        """Test creation and management of event chains."""
        # Create an event chain
        chain = EventChain(name="test_chain", description="Test event chain")

        # Add events to the chain
        event1 = CorrelatedEvent(event_type="start_event")
        event2 = CorrelatedEvent.create_child_event(parent_event=event1, event_type="middle_event")
        event3 = CorrelatedEvent.create_child_event(parent_event=event2, event_type="end_event")

        chain.add_event(event1)
        chain.add_event(event2)
        chain.add_event(event3)

        # Verify chain properties
        assert chain.name == "test_chain"
        assert len(chain.events) == 3
        assert chain.root_event_id == event1.id
        assert chain.last_event_id == event3.id

        # Test serialization
        chain_dict = chain.to_dict()
        assert chain_dict["name"] == "test_chain"
        assert len(chain_dict["events"]) == 3
        assert chain_dict["root_event_id"] == event1.id

        # Test finding events
        found_event = chain.find_event_by_type("middle_event")
        assert found_event is not None
        assert found_event.id == event2.id

        # Test getting event path
        path = chain.get_event_path(event3.id)
        assert len(path) == 3
        assert path[0].id == event1.id
        assert path[2].id == event3.id


@pytest.mark.db_required
class TestTemporalSequence:
    """Test suite for temporal sequences of neurotransmitter changes."""

    def test_temporal_sequence_creation(self):
        """Test creation of temporal sequences."""
        # Create a sequence
        sequence = TemporalSequence(
            name="test_sequence",
            description="Test temporal sequence",
            time_unit="hours",
        )

        # Add time points
        sequence.add_time_point(
            time_value=0,
            data={
                "serotonin": 0.5,
                "dopamine": 0.6,
                "norepinephrine": 0.4,
            },
        )
        sequence.add_time_point(
            time_value=24,
            data={
                "serotonin": 0.6,
                "dopamine": 0.7,
                "norepinephrine": 0.5,
            },
        )
        sequence.add_time_point(
            time_value=48,
            data={
                "serotonin": 0.7,
                "dopamine": 0.8,
                "norepinephrine": 0.6,
            },
        )

        # Verify sequence properties
        assert sequence.name == "test_sequence"
        assert len(sequence.time_points) == 3
        assert sequence.time_unit == "hours"

        # Test getting time point data
        point_0 = sequence.get_time_point(0)
        assert point_0 is not None
        assert point_0.data["serotonin"] == 0.5

        # Test getting data series
        serotonin_series = sequence.get_data_series("serotonin")
        assert len(serotonin_series) == 3
        assert serotonin_series[0] == 0.5
        assert serotonin_series[2] == 0.7

        # Test interpolation
        interpolated = sequence.interpolate_at_time(36)
        assert interpolated is not None
        assert "serotonin" in interpolated
        # Should be halfway between 0.6 and 0.7
        assert math.isclose(interpolated["serotonin"], 0.65, abs_tol=0.01)

        # Test serialization
        sequence_dict = sequence.to_dict()
        assert sequence_dict["name"] == "test_sequence"
        assert len(sequence_dict["time_points"]) == 3
        assert sequence_dict["time_unit"] == "hours"


@pytest.mark.db_required
class TestTemporalNeurotransmitterMapping:
    """Test suite for temporal neurotransmitter mapping."""

    def test_extend_neurotransmitter_mapping(self):
        """Test extending a neurotransmitter mapping with temporal capabilities."""
        # Create a base mapping
        patient_id = uuid.uuid4()
        base_mapping = create_default_neurotransmitter_mapping(patient_id)

        # Extend the mapping
        extended_mapping = extend_neurotransmitter_mapping(base_mapping)

        # Verify extended mapping
        assert extended_mapping.patient_id == patient_id
        assert hasattr(extended_mapping, "temporal_sequences")
        assert hasattr(extended_mapping, "event_chains")
        assert len(extended_mapping.receptor_profiles) == len(base_mapping.receptor_profiles)

    def test_temporal_receptor_response(self):
        """Test temporal response of receptors to neurotransmitter changes."""
        # Create a patient and mapping
        patient_id = uuid.uuid4()
        mapping = create_default_neurotransmitter_mapping(patient_id)
        extended_mapping = extend_neurotransmitter_mapping(mapping)

        # Add a receptor profile for testing
        profile = ReceptorProfile(
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            receptor_type=ReceptorType.EXCITATORY,
            receptor_subtype=ReceptorSubtype.SEROTONIN_5HT2A,
            density=0.7,
            sensitivity=0.8,
            clinical_relevance=ClinicalSignificance.HIGH,
        )
        mapping.add_receptor_profile(profile)

        # Create a temporal sequence for serotonin changes
        sequence = TemporalSequence(
            name="serotonin_response",
            description="Serotonin response over time",
            time_unit="hours",
        )
        sequence.add_time_point(
            time_value=0,
            data={Neurotransmitter.SEROTONIN.value: 0.5},
        )
        sequence.add_time_point(
            time_value=24,
            data={Neurotransmitter.SEROTONIN.value: 0.7},
        )
        sequence.add_time_point(
            time_value=48,
            data={Neurotransmitter.SEROTONIN.value: 0.9},
        )

        # Add the sequence to the extended mapping
        extended_mapping.add_temporal_sequence(sequence)

        # Test receptor response calculation
        response = extended_mapping.calculate_receptor_response(
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            time_point=24,
            sequence_name="serotonin_response",
        )

        # Verify response
        assert response is not None
        assert "activation_level" in response
        assert "clinical_significance" in response
        assert response["activation_level"] > 0.5  # Should be activated by increased serotonin

    def test_temporal_cascade_effects(self):
        """Test cascade effects over time between connected neurotransmitter systems."""
        # Create a patient and mapping
        patient_id = uuid.uuid4()
        mapping = create_default_neurotransmitter_mapping(patient_id)
        extended_mapping = extend_neurotransmitter_mapping(mapping)

        # Define a connection between serotonin and dopamine
        extended_mapping.add_neurotransmitter_connection(
            source=Neurotransmitter.SEROTONIN,
            target=Neurotransmitter.DOPAMINE,
            connection_type=ConnectionType.INHIBITORY,
            strength=0.6,
            delay_hours=12,
        )

        # Create a temporal sequence for serotonin changes
        sequence = TemporalSequence(
            name="serotonin_increase",
            description="Serotonin increase over time",
            time_unit="hours",
        )
        sequence.add_time_point(
            time_value=0,
            data={
                Neurotransmitter.SEROTONIN.value: 0.5,
                Neurotransmitter.DOPAMINE.value: 0.5,
            },
        )
        sequence.add_time_point(
            time_value=24,
            data={
                Neurotransmitter.SEROTONIN.value: 0.8,
                Neurotransmitter.DOPAMINE.value: 0.5,  # Not yet affected
            },
        )

        # Add the sequence to the extended mapping
        extended_mapping.add_temporal_sequence(sequence)

        # Simulate cascade effects
        cascade_result = extended_mapping.simulate_cascade_effects(
            sequence_name="serotonin_increase",
            simulation_duration_hours=48,
            time_step_hours=6,
        )

        # Verify cascade results
        assert cascade_result is not None
        assert "result_sequence" in cascade_result
        result_sequence = cascade_result["result_sequence"]

        # Check that dopamine was affected after the delay
        dopamine_at_36h = result_sequence.interpolate_at_time(36)
        assert dopamine_at_36h[Neurotransmitter.DOPAMINE.value] < 0.5  # Should be inhibited

        # Verify the event chain was created
        assert "event_chain" in cascade_result
        event_chain = cascade_result["event_chain"]
        assert event_chain.name.startswith("cascade_")
        assert len(event_chain.events) > 0


@pytest.mark.db_required
class TestNeurotransmitterVisualization:
    """Test suite for neurotransmitter visualization preprocessing."""

    def test_visualization_preprocessor(self):
        """Test the visualization preprocessor for neurotransmitter data."""
        # Create a preprocessor
        preprocessor = NeurotransmitterVisualizationPreprocessor()

        # Create test data
        neurotransmitter_levels = {
            Neurotransmitter.SEROTONIN.value: 0.7,
            Neurotransmitter.DOPAMINE.value: 0.8,
            Neurotransmitter.GABA.value: 0.5,
            Neurotransmitter.GLUTAMATE.value: 0.6,
        }

        # Process the data
        processed_data = preprocessor.process_neurotransmitter_levels(
            neurotransmitter_levels,
            normalize=True,
            include_metadata=True,
        )

        # Verify processed data
        assert processed_data is not None
        assert "neurotransmitters" in processed_data
        assert "metadata" in processed_data

        # Check neurotransmitter data
        nt_data = processed_data["neurotransmitters"]
        assert len(nt_data) == 4

        # Check normalization
        max_value = max(level["level"] for level in nt_data)
        assert math.isclose(max_value, 1.0, abs_tol=0.01)

        # Check metadata
        metadata = processed_data["metadata"]
        assert "max_original_value" in metadata
        assert "min_original_value" in metadata
        assert "normalization_applied" in metadata
        assert metadata["normalization_applied"] is True

    def test_effect_visualizer(self):
        """Test the neurotransmitter effect visualizer."""
        # Create a visualizer
        visualizer = NeurotransmitterEffectVisualizer()

        # Create test effects
        effects = [
            NeurotransmitterEffect(
                neurotransmitter=Neurotransmitter.DOPAMINE,
                effect_size=0.8,
                confidence_interval=(0.6, 1.0),
                p_value=0.01,
                sample_size=40,
                clinical_significance=ClinicalSignificance.MODERATE,
            ),
            NeurotransmitterEffect(
                neurotransmitter=Neurotransmitter.SEROTONIN,
                effect_size=0.5,
                confidence_interval=(0.3, 0.7),
                p_value=0.04,
                sample_size=40,
                clinical_significance=ClinicalSignificance.MILD,
            ),
            NeurotransmitterEffect(
                neurotransmitter=Neurotransmitter.GABA,
                effect_size=-0.3,
                confidence_interval=(-0.5, -0.1),
                p_value=0.06,  # Not significant
                sample_size=40,
                clinical_significance=ClinicalSignificance.MINIMAL,
            ),
        ]

        # Generate comparison visualization
        comparison = visualizer.generate_effect_comparison(effects)

        # Verify the comparison
        assert "effects" in comparison
        assert "comparison_metrics" in comparison
        assert len(comparison["effects"]) == 3

        # Check rankings
        metrics = comparison["comparison_metrics"]
        assert metrics["most_significant"] == Neurotransmitter.DOPAMINE.value
        assert metrics["largest_effect"] == Neurotransmitter.DOPAMINE.value
        assert metrics["magnitude_ranking"][0] == Neurotransmitter.DOPAMINE.value

        # Test timeline visualization
        timeline = visualizer.generate_effect_timeline(effects[0])

        # Verify the timeline
        assert "neurotransmitter" in timeline
        assert "timeline" in timeline
        assert "metrics" in timeline
        # Should have multiple time points
        assert len(timeline["timeline"]) > 1
        # Initial effect size
        assert timeline["timeline"][0]["effect_size"] == 0.8
        assert timeline["timeline"][-1]["is_prediction"] is True  # Last point is a prediction
