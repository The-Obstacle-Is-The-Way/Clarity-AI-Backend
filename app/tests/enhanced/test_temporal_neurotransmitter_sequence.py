"""
Standalone test for the TemporalNeurotransmitterSequence class.
"""
import datetime
import sys
import uuid
from pathlib import Path

# Add backend to the sys.path
backend_dir = str(Path(__file__).resolve().parent.parent.parent.parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.domain.entities.digital_twin.temporal_neurotransmitter_sequence import (
    TemporalNeurotransmitterSequence,
)
from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    Neurotransmitter,
)


def test_temporal_neurotransmitter_sequence_creation():
    """Test basic creation of a TemporalNeurotransmitterSequence."""
    patient_id = uuid.uuid4()
    start_time = datetime.datetime.now() - datetime.timedelta(days=30)
    end_time = datetime.datetime.now()
    
    # Create a sequence
    sequence = TemporalNeurotransmitterSequence(
        patient_id=patient_id,
        start_time=start_time,
        end_time=end_time,
        resolution_hours=24,
    )
    
    # Verify basic properties
    assert sequence.patient_id == patient_id
    assert sequence.start_time == start_time
    assert sequence.end_time == end_time
    assert sequence.resolution_hours == 24
    
    # Check that we have the expected number of timestamps
    expected_days = 30 + 1  # 30 days plus the current day
    assert len(sequence.timestamps) == expected_days


def test_add_data_point_and_retrieval():
    """Test adding data points to a sequence and retrieving them."""
    patient_id = uuid.uuid4()
    start_time = datetime.datetime.now() - datetime.timedelta(days=10)
    end_time = datetime.datetime.now()
    
    # Create a sequence
    sequence = TemporalNeurotransmitterSequence(
        patient_id=patient_id,
        start_time=start_time,
        end_time=end_time,
        resolution_hours=24,
    )
    
    # Add data points
    for day in range(10):
        timestamp = start_time + datetime.timedelta(days=day)
        value = 0.4 + (day * 0.05)  # Gradually increasing values
        
        result = sequence.add_data_point(
            timestamp=timestamp,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            value=value,
        )
        assert result is True
    
    # Retrieve the values
    serotonin_levels = sequence.get_neurotransmitter_levels(
        neurotransmitter=Neurotransmitter.SEROTONIN,
        brain_region=BrainRegion.PREFRONTAL_CORTEX
    )
    
    # Verify the values
    assert len(serotonin_levels) == 11  # 10 days + current day
    
    # Check the first and last data points (should have our values)
    assert abs(serotonin_levels[0][1] - 0.4) < 0.01
    assert abs(serotonin_levels[9][1] - 0.85) < 0.01


def test_trend_analysis():
    """Test trend analysis on sequence data."""
    patient_id = uuid.uuid4()
    start_time = datetime.datetime.now() - datetime.timedelta(days=10)
    end_time = datetime.datetime.now()
    
    # Create a sequence
    sequence = TemporalNeurotransmitterSequence(
        patient_id=patient_id,
        start_time=start_time,
        end_time=end_time,
        resolution_hours=24,
    )
    
    # Add increasing data points
    for day in range(10):
        timestamp = start_time + datetime.timedelta(days=day)
        value = 0.3 + (day * 0.05)  # Clear increasing trend
        
        sequence.add_data_point(
            timestamp=timestamp,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            value=value,
        )
    
    # Analyze the trend
    trend_result = sequence.analyze_trend(
        neurotransmitter=Neurotransmitter.SEROTONIN,
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
    )
    
    # Verify trend analysis results
    assert trend_result["trend"] == "increasing"
    assert trend_result["significance"] in ["medium", "high"]
    
    # Now test a decreasing trend
    sequence2 = TemporalNeurotransmitterSequence(
        patient_id=patient_id,
        start_time=start_time,
        end_time=end_time,
        resolution_hours=24,
    )
    
    # Add decreasing data points
    for day in range(10):
        timestamp = start_time + datetime.timedelta(days=day)
        value = 0.8 - (day * 0.05)  # Clear decreasing trend
        
        sequence2.add_data_point(
            timestamp=timestamp,
            neurotransmitter=Neurotransmitter.DOPAMINE,
            brain_region=BrainRegion.STRIATUM,
            value=value,
        )
    
    # Analyze the trend
    trend_result2 = sequence2.analyze_trend(
        neurotransmitter=Neurotransmitter.DOPAMINE,
        brain_region=BrainRegion.STRIATUM,
    )
    
    # Verify trend analysis results
    assert trend_result2["trend"] == "decreasing"
    assert trend_result2["significance"] in ["medium", "high"]


if __name__ == "__main__":
    # Run the tests manually
    print("Running test_temporal_neurotransmitter_sequence_creation...")
    test_temporal_neurotransmitter_sequence_creation()
    print("Test passed!")
    
    print("Running test_add_data_point_and_retrieval...")
    test_add_data_point_and_retrieval()
    print("Test passed!")
    
    print("Running test_trend_analysis...")
    test_trend_analysis()
    print("Test passed!")
    
    print("All tests passed successfully!") 