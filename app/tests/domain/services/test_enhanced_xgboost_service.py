"""
Unit tests for EnhancedXGBoostService.

Tests the treatment response prediction and interaction analysis capabilities
of the XGBoost-based machine learning service.
"""

import uuid

import numpy as np
import pytest

from app.domain.entities.digital_twin_enums import BrainRegion, Neurotransmitter
from app.domain.services.enhanced_xgboost_service import EnhancedXGBoostService


@pytest.mark.venv_only()
class TestEnhancedXGBoostService:
    """Test suite for the EnhancedXGBoostService."""

    @pytest.fixture
    def xgboost_service(self):
        """Create an EnhancedXGBoostService instance for testing."""
        return EnhancedXGBoostService()

    @pytest.fixture
    def test_patient_id(self):
        """Generate a test patient ID."""
        return uuid.uuid4()

    @pytest.fixture
    def test_baseline_data(self):
        """Create test baseline data."""
        return {
            "baseline_serotonin": 0.4,
            "baseline_dopamine": 0.6,
            "baseline_gaba": 0.5,
            "baseline_glutamate": 0.3,
            "sleep_quality": 0.7,
            "stress_level": 0.6,
        }

    def test_predict_treatment_response_basic(self, xgboost_service, test_patient_id) -> None:
        """Test basic treatment response prediction."""
        # Test prediction for increasing serotonin
        prediction = xgboost_service.predict_treatment_response(
            patient_id=test_patient_id,
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            treatment_effect=0.5,
        )

        # Verify prediction structure
        assert "predicted_response" in prediction
        assert "confidence" in prediction
        assert "timeframe_days" in prediction
        assert "feature_importance" in prediction

        # Verify prediction values are within expected ranges
        assert 0 <= prediction["predicted_response"] <= 1.0
        assert 0 <= prediction["confidence"] <= 1.0
        assert prediction["timeframe_days"] > 0

    def test_predict_treatment_response_multiple_regions(
        self, xgboost_service, test_patient_id
    ) -> None:
        """Test treatment response prediction across multiple brain regions."""
        # Test predictions for different brain regions
        regions = [
            BrainRegion.PREFRONTAL_CORTEX,
            BrainRegion.AMYGDALA,
            BrainRegion.HIPPOCAMPUS,
            BrainRegion.PITUITARY,  # Added as per memory record
        ]

        predictions = []
        for region in regions:
            prediction = xgboost_service.predict_treatment_response(
                patient_id=test_patient_id,
                brain_region=region,
                neurotransmitter=Neurotransmitter.SEROTONIN,
                treatment_effect=0.5,
            )
            predictions.append(prediction)

        # Verify all predictions have valid structure
        for prediction in predictions:
            assert "predicted_response" in prediction
            assert "confidence" in prediction
            assert "timeframe_days" in prediction

        # Verify predictions differ by brain region
        response_values = [p["predicted_response"] for p in predictions]
        assert len(set(response_values)) > 1, "Predictions should vary by brain region"

    def test_predict_treatment_response_multiple_neurotransmitters(
        self, xgboost_service, test_patient_id
    ) -> None:
        """Test treatment response prediction for different neurotransmitters."""
        # Test predictions for different neurotransmitters
        neurotransmitters = [
            Neurotransmitter.SEROTONIN,
            Neurotransmitter.DOPAMINE,
            Neurotransmitter.GABA,
            Neurotransmitter.GLUTAMATE,
        ]

        predictions = []
        for nt in neurotransmitters:
            prediction = xgboost_service.predict_treatment_response(
                patient_id=test_patient_id,
                brain_region=BrainRegion.PREFRONTAL_CORTEX,
                neurotransmitter=nt,
                treatment_effect=0.5,
            )
            predictions.append(prediction)

        # Verify all predictions have valid structure
        for prediction in predictions:
            assert "predicted_response" in prediction
            assert "confidence" in prediction
            assert "timeframe_days" in prediction

        # Verify predictions differ by neurotransmitter
        response_values = [p["predicted_response"] for p in predictions]
        assert len(set(response_values)) > 1, "Predictions should vary by neurotransmitter"

    def test_predict_treatment_response_effect_magnitude(
        self, xgboost_service, test_patient_id
    ) -> None:
        """Test that treatment effect magnitude influences prediction."""
        # Test predictions for different effect magnitudes
        effect_magnitudes = [0.1, 0.3, 0.5, 0.7, 0.9]

        predictions = []
        for effect in effect_magnitudes:
            prediction = xgboost_service.predict_treatment_response(
                patient_id=test_patient_id,
                brain_region=BrainRegion.PREFRONTAL_CORTEX,
                neurotransmitter=Neurotransmitter.SEROTONIN,
                treatment_effect=effect,
            )
            predictions.append(prediction)

        # Verify predictions increase with effect magnitude
        response_values = [p["predicted_response"] for p in predictions]
        assert (
            response_values[0] < response_values[-1]
        ), "Higher effect should yield stronger response"

        # Check for monotonic increase (or at least non-decrease)
        for i in range(1, len(response_values)):
            assert (
                response_values[i] >= response_values[i - 1]
            ), "Response should not decrease with higher effect"

    def test_analyze_neurotransmitter_interactions(
        self, xgboost_service, test_patient_id, test_baseline_data
    ) -> None:
        """Test analysis of interactions between neurotransmitters."""
        # Test interaction analysis
        interactions = xgboost_service.analyze_neurotransmitter_interactions(
            patient_id=test_patient_id,
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            baseline_data=test_baseline_data,
        )

        # Verify interaction analysis structure
        assert "primary_interactions" in interactions
        assert "secondary_interactions" in interactions
        assert "confidence" in interactions
        assert "timestamp" in interactions

        # Verify primary interactions structure
        primary = interactions["primary_interactions"]
        assert isinstance(primary, list)
        assert len(primary) > 0

        # Check first primary interaction
        first_interaction = primary[0]
        assert "source" in first_interaction
        assert "target" in first_interaction
        assert "effect_type" in first_interaction
        assert "effect_magnitude" in first_interaction

        # Verify effect magnitude is a string like 'large' or 'medium'
        assert first_interaction["effect_magnitude"] in ["large", "medium", "small"]

    def test_simulate_treatment_cascade(
        self, xgboost_service, test_patient_id, test_baseline_data
    ) -> None:
        """Test simulation of treatment cascade effects."""
        # Test cascade simulation
        cascade = xgboost_service.simulate_treatment_cascade(
            patient_id=test_patient_id,
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            treatment_effect=0.5,
            baseline_data=test_baseline_data,
        )

        # Verify cascade simulation structure
        assert "direct_effects" in cascade
        assert "indirect_effects" in cascade
        assert "temporal_progression" in cascade
        assert "confidence" in cascade

        # Verify direct effects
        direct = cascade["direct_effects"]
        assert isinstance(direct, dict)
        assert len(direct) > 0

        # Verify indirect effects
        indirect = cascade["indirect_effects"]
        assert isinstance(indirect, list)
        assert len(indirect) > 0

        # Check first indirect effect
        first_indirect = indirect[0]
        assert "pathway" in first_indirect
        assert "effect_magnitude" in first_indirect
        assert "timeframe_days" in first_indirect

        # Verify temporal progression
        temporal = cascade["temporal_progression"]
        assert isinstance(temporal, list)
        assert len(temporal) > 0

        # Check temporal progression structure
        first_timepoint = temporal[0]
        assert "day" in first_timepoint
        assert "neurotransmitter_levels" in first_timepoint
        assert "predicted_symptom_change" in first_timepoint

    def test_temporal_response_analysis(self, xgboost_service, test_patient_id) -> None:
        """Test analysis of temporal response patterns."""
        # Test temporal analysis
        temporal_analysis = xgboost_service.analyze_temporal_response(
            patient_id=test_patient_id,
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            treatment_effect=0.5,
        )

        # Verify temporal analysis structure
        assert "response_curve" in temporal_analysis
        assert "peak_response_day" in temporal_analysis
        assert "stabilization_day" in temporal_analysis
        assert "confidence" in temporal_analysis

        # Verify response curve
        curve = temporal_analysis["response_curve"]
        assert isinstance(curve, list)
        assert len(curve) > 0

        # Check response curve structure
        first_point = curve[0]
        assert "day" in first_point
        assert "response_level" in first_point

        # Verify peak and stabilization days are reasonable
        assert temporal_analysis["peak_response_day"] > 0
        assert temporal_analysis["stabilization_day"] >= temporal_analysis["peak_response_day"]

    def test_response_curve_shape(self, xgboost_service, test_patient_id) -> None:
        """Test that the response curve has a reasonable shape."""
        # Get temporal analysis
        temporal_analysis = xgboost_service.analyze_temporal_response(
            patient_id=test_patient_id,
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            treatment_effect=0.5,
        )

        # Extract response curve
        curve = temporal_analysis["response_curve"]
        time_points = len(curve)

        # Convert to numpy arrays for analysis
        np.array([point["day"] for point in curve])
        responses = np.array([point["response_level"] for point in curve])

        # Verify curve starts near zero
        assert responses[0] < 0.1, "Response should start near zero"

        # Verify curve has a peak
        peak_idx = np.argmax(responses)
        assert peak_idx > 0, "Peak should not be at the first time point"
        assert peak_idx < time_points - 1, "Peak should not be at the last time point"

    def test_feature_encoding(self, xgboost_service) -> None:
        """Test that features are correctly encoded."""
        # Test encoding brain region
        region_encoding1 = xgboost_service._encode_brain_region(BrainRegion.PREFRONTAL_CORTEX)
        region_encoding2 = xgboost_service._encode_brain_region(BrainRegion.AMYGDALA)

        # Test encoding neurotransmitter
        nt_encoding1 = xgboost_service._encode_neurotransmitter(Neurotransmitter.SEROTONIN)
        nt_encoding2 = xgboost_service._encode_neurotransmitter(Neurotransmitter.DOPAMINE)

        # Verify encodings are valid numbers in expected range
        assert 0 <= region_encoding1 <= 1
        assert 0 <= region_encoding2 <= 1
        assert 0 <= nt_encoding1 <= 1
        assert 0 <= nt_encoding2 <= 1

        # Different values should have different encodings
        assert region_encoding1 != region_encoding2
        assert nt_encoding1 != nt_encoding2

    def test_consistency_of_predictions(self, xgboost_service, test_patient_id) -> None:
        """Test that predictions are consistent for the same inputs."""
        # Make prediction twice with same inputs
        prediction1 = xgboost_service.predict_treatment_response(
            patient_id=test_patient_id,
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            treatment_effect=0.5,
        )

        prediction2 = xgboost_service.predict_treatment_response(
            patient_id=test_patient_id,
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            treatment_effect=0.5,
        )

        # Predictions should be identical for identical inputs
        assert prediction1["predicted_response"] == prediction2["predicted_response"]
        assert prediction1["confidence"] == prediction2["confidence"]
