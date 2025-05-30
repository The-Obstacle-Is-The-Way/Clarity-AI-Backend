"""
Unit tests for the Digital Twin entity.

This module contains tests for the core Digital Twin entity, verifying its
initialization and state/configuration updates.
"""

import time
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

# Import the entities to test
from app.domain.entities.digital_twin.digital_twin import (
    DigitalTwin,
    DigitalTwinConfiguration,
    DigitalTwinState,
)

# Import enums if needed for configuration/state values
# from app.domain.entities.digital_twin_enums import ...


@pytest.fixture
def patient_id() -> UUID:
    """Provides a consistent patient UUID."""
    return uuid4()


@pytest.fixture
def digital_twin(patient_id: UUID) -> DigitalTwin:
    """Provides a basic DigitalTwin instance."""
    return DigitalTwin(patient_id=patient_id)


@pytest.mark.venv_only()
class TestDigitalTwin:
    """Tests for the DigitalTwin entity."""

    def test_init_default_values(self, patient_id: UUID) -> None:
        """Test that default values are correctly initialized."""
        twin = DigitalTwin(patient_id=patient_id)

        assert twin.patient_id == patient_id
        assert isinstance(twin.id, UUID)
        assert isinstance(twin.configuration, DigitalTwinConfiguration)
        assert isinstance(twin.state, DigitalTwinState)
        assert isinstance(twin.created_at, datetime)
        assert isinstance(twin.last_updated, datetime)
        assert twin.created_at == twin.last_updated  # Initially should be same
        assert twin.version == 1

        # Check default config values
        assert twin.configuration.simulation_granularity_hours == 1
        assert twin.configuration.prediction_models_enabled == [
            "risk_relapse",
            "treatment_response",
        ]
        assert twin.configuration.data_sources_enabled == [
            "actigraphy",
            "symptoms",
            "sessions",
        ]
        assert twin.configuration.alert_thresholds == {}

        # Check default state values
        assert twin.state.last_sync_time is None
        assert twin.state.overall_risk_level is None
        assert twin.state.dominant_symptoms == []
        assert twin.state.current_treatment_effectiveness is None
        assert twin.state.predicted_phq9_trajectory is None

    def test_init_custom_values(self, patient_id: UUID) -> None:
        """Test initialization with custom configuration and state."""
        custom_id = uuid4()
        created_time = datetime.now(timezone.utc) - timedelta(days=1)
        custom_config = DigitalTwinConfiguration(
            simulation_granularity_hours=2,
            prediction_models_enabled=["risk_suicide"],
            alert_thresholds={"phq9_change": 3.0},
        )
        custom_state = DigitalTwinState(
            last_sync_time=created_time,
            overall_risk_level="moderate",
            dominant_symptoms=["anhedonia", "insomnia"],
        )

        twin = DigitalTwin(
            id=custom_id,
            patient_id=patient_id,
            configuration=custom_config,
            state=custom_state,
            created_at=created_time,
            last_updated=created_time,  # Initial last_updated matches created_at
            version=5,  # Test custom version
        )

        assert twin.id == custom_id
        assert twin.patient_id == patient_id
        assert twin.configuration == custom_config
        assert twin.state == custom_state
        assert twin.created_at == created_time
        assert twin.last_updated == created_time
        assert twin.version == 5

    def test_update_state(self, digital_twin: DigitalTwin) -> None:
        """Test updating the digital twin state."""
        original_updated_at = digital_twin.last_updated
        original_version = digital_twin.version
        time.sleep(0.01)  # Ensure time difference

        new_state_data = {
            "overall_risk_level": "high",
            "dominant_symptoms": ["anhedonia", "fatigue", "suicidal_ideation"],
            "current_treatment_effectiveness": "worsening",
            "predicted_phq9_trajectory": [{"week": 1, "score": 18.5}],
            # "last_sync_time" is updated automatically
        }

        digital_twin.update_state(new_state_data)

        assert digital_twin.state.overall_risk_level == "high"
        assert digital_twin.state.dominant_symptoms == [
            "anhedonia",
            "fatigue",
            "suicidal_ideation",
        ]
        assert digital_twin.state.current_treatment_effectiveness == "worsening"
        assert digital_twin.state.predicted_phq9_trajectory == [{"week": 1, "score": 18.5}]
        assert isinstance(digital_twin.state.last_sync_time, datetime)
        assert digital_twin.state.last_sync_time > original_updated_at  # Sync time updated
        assert digital_twin.last_updated > original_updated_at  # Entity updated time
        assert digital_twin.version == original_version + 1  # Version incremented

    def test_update_state_partial(self, digital_twin: DigitalTwin) -> None:
        """Test partially updating the digital twin state."""
        original_updated_at = digital_twin.last_updated
        original_version = digital_twin.version
        time.sleep(0.01)

        new_state_data = {
            "overall_risk_level": "moderate",
        }
        digital_twin.update_state(new_state_data)

        assert digital_twin.state.overall_risk_level == "moderate"
        assert digital_twin.state.dominant_symptoms == []  # Unchanged
        assert digital_twin.last_updated > original_updated_at
        assert digital_twin.version == original_version + 1

    def test_update_state_invalid_key(self, digital_twin: DigitalTwin) -> None:
        """Test updating state with an invalid key does not change state."""
        original_state_dict = digital_twin.state.__dict__.copy()
        original_updated_at = digital_twin.last_updated
        original_version = digital_twin.version
        time.sleep(0.01)

        new_state_data = {
            "invalid_state_key": "some_value",
            "overall_risk_level": "low",  # Include a valid key too
        }
        digital_twin.update_state(new_state_data)

        # Check valid key was updated
        assert digital_twin.state.overall_risk_level == "low"
        # Check other keys remain unchanged
        assert digital_twin.state.dominant_symptoms == original_state_dict["dominant_symptoms"]
        # Check timestamp and version updated
        assert digital_twin.last_updated > original_updated_at
        assert digital_twin.version == original_version + 1

    def test_update_configuration(self, digital_twin: DigitalTwin) -> None:
        """Test updating the digital twin configuration."""
        original_config = digital_twin.configuration
        original_updated_at = digital_twin.last_updated
        original_version = digital_twin.version
        time.sleep(0.01)

        new_config_data = {
            "simulation_granularity_hours": 4,
            "prediction_models_enabled": ["risk_relapse", "risk_suicide"],
            "alert_thresholds": {"phq9_change": 4.0},
        }

        digital_twin.update_configuration(new_config_data)

        assert digital_twin.configuration.simulation_granularity_hours == 4
        assert digital_twin.configuration.prediction_models_enabled == [
            "risk_relapse",
            "risk_suicide",
        ]
        assert digital_twin.configuration.alert_thresholds == {"phq9_change": 4.0}
        # Check unchanged config value
        assert (
            digital_twin.configuration.data_sources_enabled == original_config.data_sources_enabled
        )
        assert digital_twin.last_updated > original_updated_at
        assert digital_twin.version == original_version + 1

    def test_update_configuration_partial(self, digital_twin: DigitalTwin) -> None:
        """Test partially updating the digital twin configuration."""
        original_granularity = digital_twin.configuration.simulation_granularity_hours
        original_updated_at = digital_twin.last_updated
        original_version = digital_twin.version
        time.sleep(0.01)

        new_config_data = {
            "prediction_models_enabled": ["risk_hospitalization"],
        }
        digital_twin.update_configuration(new_config_data)

        assert digital_twin.configuration.prediction_models_enabled == ["risk_hospitalization"]
        assert (
            digital_twin.configuration.simulation_granularity_hours == original_granularity
        )  # Unchanged
        assert digital_twin.last_updated > original_updated_at
        assert digital_twin.version == original_version + 1

    def test_update_configuration_invalid_key(self, digital_twin: DigitalTwin) -> None:
        """Test updating configuration with an invalid key."""
        original_config_dict = digital_twin.configuration.__dict__.copy()
        original_updated_at = digital_twin.last_updated
        original_version = digital_twin.version
        time.sleep(0.01)

        new_config_data = {
            "invalid_config_key": "some_value",
            "simulation_granularity_hours": 8,  # Include a valid key
        }
        digital_twin.update_configuration(new_config_data)

        # Check valid key was updated
        assert digital_twin.configuration.simulation_granularity_hours == 8
        # Check other keys remain unchanged
        assert (
            digital_twin.configuration.prediction_models_enabled
            == original_config_dict["prediction_models_enabled"]
        )
        # Check timestamp and version updated
        assert digital_twin.last_updated > original_updated_at
        assert digital_twin.version == original_version + 1

    def test_touch_method(self, digital_twin: DigitalTwin) -> None:
        """Test the touch method updates timestamp and version."""
        original_updated_at = digital_twin.last_updated
        original_version = digital_twin.version
        time.sleep(0.01)  # Ensure time difference

        digital_twin.touch()

        assert digital_twin.last_updated > original_updated_at
        assert digital_twin.version == original_version + 1

    # Removed tests related to old state structure and non-existent methods
    # (e.g., _update_neurotransmitter_state, detect_patterns, calibrate, evaluate_accuracy)
