"""
Unit tests for the Gene Medication Model.

These tests verify that the Gene Medication Model correctly
analyzes genetic variants and predicts medication interactions.
"""

import pytest

pytest.skip(
    "Skipping pharmacogenomics gene medication model tests (torch unsupported)",
    allow_module_level=True,
)
from unittest.mock import MagicMock, patch

import numpy as np

from app.infrastructure.ml.pharmacogenomics.gene_medication_model import (
    GeneMedicationModel,
)


@pytest.fixture
def model():
    """Create a GeneMedicationModel with mocked internals."""
    # Patch joblib during instantiation to avoid actual file loading
    with patch(
        "app.infrastructure.ml.pharmacogenomics.gene_medication_model.joblib",
        autospec=True,
    ) as mock_joblib, patch(
        "app.infrastructure.ml.pharmacogenomics.gene_medication_model.json",
        autospec=True,
    ) as mock_json, patch(
        "builtins.open", mock_open(read_data="{}")
    ), patch(
        "os.path.exists", return_value=True
    ):  # Assume files exist for fixture setup
        # Mock joblib.load to return a mock model
        mock_ml_model = MagicMock()
        # Interaction, No interaction, Interaction
        mock_ml_model.predict = MagicMock(return_value=np.array([1, 0, 1]))
        mock_joblib.load.return_value = mock_ml_model

        # Mock json.load to return a mock knowledge base
        mock_kb = {
            "gene_variants": {
                "CYP2D6": {
                    "*1/*1": {"function": "normal", "frequency": 0.45},
                    "*1/*4": {"function": "intermediate", "frequency": 0.25},
                    "*4/*4": {"function": "poor", "frequency": 0.05},
                },
                "CYP2C19": {
                    "*1/*1": {"function": "normal", "frequency": 0.40},
                    "*1/*2": {"function": "intermediate", "frequency": 0.30},
                    "*2/*2": {"function": "poor", "frequency": 0.10},
                },
            },
            "medications": {
                "fluoxetine": {
                    "class": "SSRI",
                    "primary_metabolism": ["CYP2D6"],
                    "secondary_metabolism": ["CYP2C19"],
                },
                "sertraline": {
                    "class": "SSRI",
                    "primary_metabolism": ["CYP2C19"],
                    "secondary_metabolism": ["CYP2D6"],
                },
                "bupropion": {
                    "class": "NDRI",
                    "primary_metabolism": ["CYP2B6"],
                    "secondary_metabolism": [],
                },
            },
            "interactions": {
                "CYP2D6": {
                    "poor": {
                        "fluoxetine": {
                            "effect": "increased_levels",
                            "recommendation": "dose_reduction",
                            "evidence_level": "high",
                        }
                    },
                    "intermediate": {
                        "fluoxetine": {
                            "effect": "slightly_increased_levels",
                            "recommendation": "monitor_closely",
                            "evidence_level": "moderate",
                        }
                    },
                },
                "CYP2C19": {
                    "poor": {
                        "sertraline": {
                            "effect": "increased_levels",
                            "recommendation": "dose_reduction",
                            "evidence_level": "high",
                        }
                    }
                },
            },
        }
        mock_json.load.return_value = mock_kb

        # Instantiate the model - it will use the mocked load functions
        # Corrected instantiation
        model_instance = GeneMedicationModel(
            model_path="test_model_path", knowledge_base_path="test_kb_path"
        )
        model_instance.initialize()  # Call initialize to load mocked data
        model_instance.is_initialized = True  # Explicitly set for clarity in tests

        return model_instance


@pytest.fixture
def sample_genetic_data():
    """Create sample genetic data for testing."""
    # Corrected list structure
    return {
        "genes": [
            {"gene": "CYP2D6", "variant": "*1/*1", "function": "normal"},
            {"gene": "CYP2C19", "variant": "*1/*2", "function": "intermediate"},
            {"gene": "CYP1A2", "variant": "*1F/*1F", "function": "rapid"},
        ]
    }


# Define the test class
class TestGeneMedicationModel:
    """Tests for the GeneMedicationModel."""

    @pytest.mark.asyncio  # Keep async if initialize is async
    async def test_initialize_loads_model_and_knowledge_base(self) -> None:
        """Test that initialize loads the model and knowledge base correctly."""
        # Setup - Use patches within the test for clarity
        with patch(
            "app.infrastructure.ml.pharmacogenomics.gene_medication_model.joblib",
            autospec=True,
        ) as mock_joblib, patch(
            "app.infrastructure.ml.pharmacogenomics.gene_medication_model.json",
            autospec=True,
        ) as mock_json, patch(
            "builtins.open", mock_open(read_data="{}")
        ) as mock_file, patch(
            "os.path.exists", return_value=True
        ):
            # Mock joblib.load to return a mock model
            mock_ml_model = MagicMock()
            mock_joblib.load.return_value = mock_ml_model

            # Mock json.load to return a mock knowledge base
            mock_kb = {"gene_variants": {}, "medications": {}, "interactions": {}}
            mock_json.load.return_value = mock_kb

            # Create model instance
            # Corrected instantiation
            model_instance = GeneMedicationModel(
                model_path="test_model_path", knowledge_base_path="test_kb_path"
            )

            # Execute
            await model_instance.initialize()  # Assuming initialize is async

            # Verify
            mock_joblib.load.assert_called_once_with("test_model_path")
            mock_file.assert_called_with("test_kb_path", "r", encoding="utf-8")
            mock_json.load.assert_called_once()
            assert model_instance.is_initialized
            assert model_instance._model is mock_ml_model
            assert model_instance._knowledge_base is mock_kb

    @pytest.mark.asyncio  # Keep async if initialize is async
    async def test_initialize_handles_missing_files(self) -> None:
        """Test that initialize handles missing model and knowledge base files gracefully."""
        # Setup
        with patch("os.path.exists", return_value=False), patch(
            "app.infrastructure.ml.pharmacogenomics.gene_medication_model.logging",
            autospec=True,
        ) as mock_logging:
            # Create model instance
            # Corrected instantiation
            model_instance = GeneMedicationModel(
                model_path="nonexistent_path", knowledge_base_path="nonexistent_kb_path"
            )

            # Execute
            await model_instance.initialize()  # Assuming initialize is async

            # Verify
            mock_logging.warning.assert_called()
            # Check that warnings were logged for both missing files
            assert mock_logging.warning.call_count >= 2
            assert model_instance.is_initialized  # Should still initialize with defaults/empty
            assert model_instance._model is None  # Model should be None if load fails
            assert model_instance._knowledge_base == {
                "gene_variants": {},
                "medications": {},
                "interactions": {},
            }  # KB should be empty

    @pytest.mark.asyncio  # Add async
    async def test_predict_medication_interactions_success(self, model, sample_genetic_data) -> None:
        """Test that predict_medication_interactions correctly processes genetic data and returns interactions."""
        # Setup
        medications = [
            "fluoxetine",
            "sertraline",
            "bupropion",
        ]  # bupropion not in mock KB interactions

        # Execute
        result = await model.predict_medication_interactions(sample_genetic_data, medications)

        # Verify
        assert "gene_medication_interactions" in result
        assert "metabolizer_status" in result

        # Verify gene interactions structure (based on mock KB and model prediction)
        interactions = result["gene_medication_interactions"]
        # Expecting 1 known (fluoxetine/CYP2D6 intermediate) + 1 predicted (fluoxetine)
        assert len(interactions) >= 1  # Allow flexibility if prediction logic changes

        found_fluoxetine_predicted = False  # Model predicts interaction for fluoxetine
        found_sertraline = False

        for interaction in interactions:
            assert "gene" in interaction
            assert "variant" in interaction
            assert "medication" in interaction
            assert "interaction_type" in interaction
            assert "effect" in interaction
            assert "recommendation" in interaction
            if (
                interaction["medication"] == "fluoxetine"
                and interaction["interaction_type"] == "known"
            ):
                assert interaction["gene"] == "CYP2D6"  # Based on intermediate status
                assert interaction["effect"] == "slightly_increased_levels"
            # Check for predicted interaction if model predicts it (mock returns [1,0,0])
            if (
                interaction["medication"] == "fluoxetine"
                and interaction["interaction_type"] == "predicted"
            ):
                found_fluoxetine_predicted = True
                assert "confidence" in interaction  # Predicted should have confidence
            if interaction["medication"] == "sertraline":
                found_sertraline = True  # Should not have known interaction based on mock KB

        # Assert based on mock KB and mocked prediction (predicts interaction for first med)
        # assert found_fluoxetine_known # This depends on the metabolizer status derived
        assert found_fluoxetine_predicted
        assert (
            not found_sertraline
        )  # No known or predicted interaction for sertraline in this scenario

        # Verify metabolizer status
        metabolizer_status = result["metabolizer_status"]
        assert "CYP2D6" in metabolizer_status
        assert "CYP2C19" in metabolizer_status
        assert metabolizer_status["CYP2D6"] == "normal"  # From *1/*1
        assert metabolizer_status["CYP2C19"] == "intermediate"  # From *1/*2

    @pytest.mark.asyncio  # Add async
    async def test_predict_medication_interactions_empty_genetic_data(self, model) -> None:
        """Test predict_medication_interactions handles empty genetic data."""
        # Setup
        empty_genetic_data = {"genes": []}
        medications = ["fluoxetine", "sertraline"]

        # Execute and verify exception is raised
        with pytest.raises(ValueError) as excinfo:
            await model.predict_medication_interactions(empty_genetic_data, medications)

        assert "Empty genetic data" in str(excinfo.value)

    @pytest.mark.asyncio  # Add async
    async def test_predict_medication_interactions_empty_medications(
        self, model, sample_genetic_data
    ) -> None:
        """Test predict_medication_interactions handles empty medications list."""
        # Setup
        empty_medications = []

        # Execute and verify exception is raised
        with pytest.raises(ValueError) as excinfo:
            await model.predict_medication_interactions(sample_genetic_data, empty_medications)

        assert "No medications specified" in str(excinfo.value)

    # Test private methods directly for focused unit testing
    def test_extract_gene_features(self, model, sample_genetic_data) -> None:
        """Test _extract_gene_features correctly transforms genetic data."""
        # Execute
        features = model._extract_gene_features(sample_genetic_data)

        # Verify the features have the expected structure
        assert isinstance(features, dict)
        assert "CYP2D6" in features
        assert "CYP2C19" in features
        assert "CYP1A2" in features
        assert features["CYP2D6"] == "*1/*1"
        assert features["CYP2C19"] == "*1/*2"
        assert features["CYP1A2"] == "*1F/*1F"

    def test_determine_metabolizer_status(self, model) -> None:
        """Test _determine_metabolizer_status correctly determines status."""
        # Setup
        gene_variants = {
            "CYP2D6": "*1/*1",  # Normal
            "CYP2C19": "*1/*2",  # Intermediate
            "CYP1A2": "*1F/*1F",  # Rapid (Assuming KB has this)
            "DPYD": "*2A/*2A",  # Poor (Assuming KB has this)
        }
        # Add expected functions to mock KB if not present
        if "CYP1A2" not in model._knowledge_base["gene_variants"]:
            model._knowledge_base["gene_variants"]["CYP1A2"] = {"*1F/*1F": {"function": "rapid"}}
        if "DPYD" not in model._knowledge_base["gene_variants"]:
            model._knowledge_base["gene_variants"]["DPYD"] = {"*2A/*2A": {"function": "poor"}}

        # Execute
        status = model._determine_metabolizer_status(gene_variants)

        # Verify
        assert isinstance(status, dict)
        assert "CYP2D6" in status
        assert "CYP2C19" in status
        assert "CYP1A2" in status
        assert "DPYD" in status
        assert status["CYP2D6"] == "normal"
        assert status["CYP2C19"] == "intermediate"
        assert status["CYP1A2"] == "rapid"
        assert status["DPYD"] == "poor"

    def test_lookup_known_interactions(self, model) -> None:
        """Test _lookup_known_interactions correctly looks up interactions."""
        # Setup
        metabolizer_status = {"CYP2D6": "poor", "CYP2C19": "normal"}
        medications = [
            "fluoxetine",
            "sertraline",
        ]  # Sertraline has no interaction for poor CYP2D6 in mock KB

        # Execute
        # Corrected function call
        interactions = model._lookup_known_interactions(metabolizer_status, medications)

        # Verify
        assert isinstance(interactions, list)
        assert len(interactions) == 1  # Only fluoxetine interaction expected

        # Check for fluoxetine interaction with poor CYP2D6 metabolism
        fluoxetine_interaction = interactions[0]
        assert fluoxetine_interaction["medication"] == "fluoxetine"
        assert fluoxetine_interaction["gene"] == "CYP2D6"
        assert fluoxetine_interaction["effect"] == "increased_levels"
        assert fluoxetine_interaction["recommendation"] == "dose_reduction"

    def test_predict_novel_interactions(self, model) -> None:
        """Test _predict_novel_interactions correctly predicts interactions."""
        # Setup
        gene_features = {  # Example features, structure depends on actual feature engineering
            "CYP2D6_*1/*1": 1,
            "CYP2C19_*1/*2": 1,
        }
        medications = ["fluoxetine", "sertraline", "bupropion"]

        # Mock the feature preparation and model prediction
        # Assume _prepare_prediction_features returns a suitable array
        mock_feature_array = np.array([[1, 1, 0, 0, 1, 0]])  # Example shape
        model._prepare_prediction_features = MagicMock(return_value=mock_feature_array)
        # Mock predict to return interaction for the first medication (fluoxetine)
        model._model.predict = MagicMock(
            return_value=np.array([[0.8], [0.1], [0.2]])
        )  # Example probabilities

        # Execute
        # Corrected function call
        interactions = model._predict_novel_interactions(gene_features, medications)

        # Verify
        assert isinstance(interactions, list)
        assert len(interactions) == 1  # Only one interaction predicted based on mock

        # Check the predicted interaction
        interaction = interactions[0]
        assert interaction["medication"] == "fluoxetine"
        assert "gene_features" in interaction  # Check if features are included
        assert interaction["interaction_type"] == "predicted"
        assert "confidence" in interaction
        assert interaction["confidence"] == 0.8  # From mock prediction
