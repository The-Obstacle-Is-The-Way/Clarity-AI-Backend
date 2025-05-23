"""
Unit tests for the Pharmacogenomics Model Service.

These tests verify that the Pharmacogenomics Model Service correctly
analyzes genetic data and predicts medication responses.
"""

import pytest

pytest.skip(
    "Skipping pharmacogenomics model service tests (torch unsupported)",
    allow_module_level=True,
)
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from pytest_mock import MockerFixture

# Corrected exception imports based on definitive source location
from app.core.exceptions import ValidationError
from app.core.exceptions.base_exceptions import ModelExecutionError
from app.domain.entities.patient import Patient
from app.domain.entities.pgx import PGXReport  # Correct import path
from app.domain.utils.datetime_utils import UTC

# Corrected import
from app.infrastructure.ml.pharmacogenomics.gene_medication_model import (
    GeneMedicationModel,
)
from app.infrastructure.ml.pharmacogenomics.model_service import PharmacogenomicsService


# Define test class
class TestPharmacogenomicsService:
    """Tests for the PharmacogenomicsService."""

    @pytest.fixture
    def mock_gene_medication_model(self):
        """Create a mock GeneMedicationModel."""
        model = AsyncMock(spec=GeneMedicationModel)
        model.is_initialized = True
        # Corrected return value dictionary structure
        model.predict_medication_interactions = AsyncMock(
            return_value={
                "gene_medication_interactions": [
                    {
                        "gene": "CYP2D6",
                        "variant": "*1/*1",
                        "medication": "fluoxetine",
                        "interaction_type": "metabolism",
                        "effect": "normal",
                        "evidence_level": "high",
                        "recommendation": "standard_dosing",
                    },
                    {
                        "gene": "CYP2C19",
                        "variant": "*1/*2",
                        "medication": "escitalopram",  # Corrected medication name if intended
                        "interaction_type": "metabolism",
                        "effect": "reduced",
                        "evidence_level": "high",
                        "recommendation": "dose_reduction",
                    },
                ],
                "metabolizer_status": {
                    "CYP2D6": "normal",
                    "CYP2C19": "intermediate",
                    "CYP1A2": "rapid",
                },
            }
        )
        return model

    @pytest.fixture
    def mock_treatment_model(self):
        """Create a mock TreatmentResponseModel."""
        model = AsyncMock(spec=PharmacogenomicsModel)
        model.is_initialized = True
        # Corrected return value dictionary structure
        model.predict_treatment_response = AsyncMock(
            return_value={
                "medication_predictions": {
                    "fluoxetine": {
                        "efficacy": {
                            "score": 0.72,
                            "confidence": 0.85,
                            "percentile": 75,
                        },
                        "side_effects": [
                            {
                                "name": "nausea",
                                "risk": 0.35,
                                "severity": "mild",
                                "onset_days": 7,
                            },
                            {
                                "name": "insomnia",
                                "risk": 0.28,
                                "severity": "mild",
                                "onset_days": 14,
                            },
                        ],
                    },
                    "sertraline": {
                        "efficacy": {
                            "score": 0.65,
                            "confidence": 0.80,
                            "percentile": 65,
                        },
                        "side_effects": [
                            {
                                "name": "nausea",
                                "risk": 0.42,
                                "severity": "moderate",
                                "onset_days": 5,
                            }
                        ],
                    },
                },
                "comparative_analysis": {
                    "highest_efficacy": {"medication": "fluoxetine", "score": 0.72},
                    "lowest_side_effects": {
                        "medication": "bupropion",  # Assuming bupropion might be compared even if not predicted
                        "highest_risk": 0.25,
                    },
                },
            }
        )
        return model

    @pytest.fixture
    def service(self, mock_gene_medication_model, mock_treatment_model):
        """Create a PharmacogenomicsService with mock dependencies."""
        # Corrected instantiation
        service_instance = PharmacogenomicsService(
            gene_medication_model=mock_gene_medication_model,
            treatment_model=mock_treatment_model,
        )
        # Ensure models are marked as initialized for tests relying on this state
        service_instance.gene_medication_model.is_initialized = True
        service_instance.treatment_model.is_initialized = True
        return service_instance

    @pytest.fixture
    def sample_genetic_data(self):
        """Create sample genetic data for testing."""
        # Corrected list structure
        return {
            "genes": [
                {"gene": "CYP2D6", "variant": "*1/*1", "function": "normal"},
                {"gene": "CYP2C19", "variant": "*1/*2", "function": "intermediate"},
                {"gene": "CYP1A2", "variant": "*1F/*1F", "function": "rapid"},
            ]
        }

    @pytest.fixture
    def sample_patient_data(self):
        """Create sample patient data for testing."""
        # Corrected dictionary structure
        return {
            "id": str(uuid4()),
            "demographics": {"age": 42, "gender": "female", "ethnicity": "caucasian"},
            "conditions": ["major_depressive_disorder", "generalized_anxiety_disorder"],
            "medication_history": [
                {
                    "name": "citalopram",
                    "dosage": "20mg",
                    "start_date": "2024-01-15",
                    "end_date": "2024-03-01",
                    "efficacy": "moderate",
                    "side_effects": ["nausea", "insomnia"],
                    "reason_for_discontinuation": "insufficient_efficacy",
                }
            ],
        }

    @pytest.fixture
    def sample_patient_id(self):
        """Create a sample patient ID."""
        return str(uuid4())

    @pytest.mark.asyncio
    async def test_predict_medication_response_success(
        self,
        service,
        mock_gene_medication_model,
        mock_treatment_model,
        sample_genetic_data,
        sample_patient_data,
        sample_patient_id,
    ) -> None:
        """Test that predict_medication_response correctly processes data and returns predictions."""
        # Setup
        medications = ["fluoxetine", "sertraline", "bupropion"]

        # Execute
        # Corrected function call
        result = await service.predict_medication_response(
            patient_id=sample_patient_id,
            genetic_data=sample_genetic_data,
            patient_data=sample_patient_data,
            medications=medications,
        )

        # Verify
        assert "patient_id" in result
        assert result["patient_id"] == sample_patient_id
        assert "medication_predictions" in result
        assert "gene_medication_interactions" in result
        assert "metabolizer_status" in result
        assert "comparative_analysis" in result

        # Verify models were called
        mock_gene_medication_model.predict_medication_interactions.assert_called_once()
        mock_treatment_model.predict_treatment_response.assert_called_once()

        # Verify model arguments
        # Corrected argument access
        gene_model_call_args = mock_gene_medication_model.predict_medication_interactions.call_args[
            0
        ]
        assert gene_model_call_args[0] == sample_genetic_data
        assert gene_model_call_args[1] == medications

        treatment_model_call_args = mock_treatment_model.predict_treatment_response.call_args[0]
        assert treatment_model_call_args[0] == sample_patient_data
        assert treatment_model_call_args[1] == medications
        assert "metabolizer_status" in treatment_model_call_args[2]  # Status passed as third arg

    @pytest.mark.asyncio
    async def test_predict_medication_response_no_genetic_data(
        self, service, sample_patient_data, sample_patient_id
    ) -> None:
        """Test that predict_medication_response handles missing genetic data."""
        # Setup
        medications = ["fluoxetine", "sertraline"]

        # Execute/Assert
        with pytest.raises(ValueError) as excinfo:
            # Corrected function call
            await service.predict_medication_response(
                patient_id=sample_patient_id,
                genetic_data=None,
                patient_data=sample_patient_data,
                medications=medications,
            )

        assert "genetic data is required" in str(excinfo.value).lower()

    @pytest.mark.asyncio
    async def test_predict_medication_response_no_patient_data(
        self, service, sample_genetic_data, sample_patient_id
    ) -> None:
        """Test that predict_medication_response handles missing patient data."""
        # Setup
        medications = ["fluoxetine", "sertraline"]

        # Execute/Assert
        with pytest.raises(ValueError) as excinfo:
            # Corrected function call
            await service.predict_medication_response(
                patient_id=sample_patient_id,
                genetic_data=sample_genetic_data,
                patient_data=None,
                medications=medications,
            )

        assert "patient data is required" in str(excinfo.value).lower()

    @pytest.mark.asyncio
    async def test_predict_medication_response_no_medications(
        self, service, sample_genetic_data, sample_patient_data, sample_patient_id
    ) -> None:
        """Test that predict_medication_response handles empty medications list."""
        # Execute/Assert
        with pytest.raises(ValueError) as excinfo:
            # Corrected function call
            await service.predict_medication_response(
                patient_id=sample_patient_id,
                genetic_data=sample_genetic_data,
                patient_data=sample_patient_data,
                medications=[],
            )

        assert "medications list cannot be empty" in str(excinfo.value).lower()

    @pytest.mark.asyncio
    async def test_predict_medication_response_model_error(
        self,
        service,
        mock_gene_medication_model,
        sample_genetic_data,
        sample_patient_data,
        sample_patient_id,
    ) -> None:
        """Test that predict_medication_response handles model errors correctly."""
        # Setup
        medications = ["fluoxetine", "sertraline"]
        # Corrected side_effect assignment
        mock_gene_medication_model.predict_medication_interactions.side_effect = Exception(
            "Model error"
        )

        # Execute/Assert
        # Expecting RuntimeError or a custom service error
        with pytest.raises(RuntimeError) as excinfo:
            # Corrected function call
            await service.predict_medication_response(
                patient_id=sample_patient_id,
                genetic_data=sample_genetic_data,
                patient_data=sample_patient_data,
                medications=medications,
            )

        assert "prediction failed" in str(excinfo.value).lower()

    @patch("app.infrastructure.ml.pharmacogenomics.model_service.log_phi_access")
    @pytest.mark.asyncio  # Add async
    async def test_phi_access_logging(
        self,
        mock_log_phi_access,
        service,
        sample_genetic_data,
        sample_patient_data,
        sample_patient_id,
    ) -> None:
        """Test that PHI access is properly logged."""
        # Setup
        medications = ["fluoxetine", "sertraline"]

        # Execute
        # Corrected function call
        await service.predict_medication_response(
            patient_id=sample_patient_id,
            genetic_data=sample_genetic_data,
            patient_data=sample_patient_data,
            medications=medications,
        )

        # Verify PHI access logging
        mock_log_phi_access.assert_called_once()
        # Corrected argument access
        log_args = mock_log_phi_access.call_args[0]
        assert log_args[0] == "PharmacogenomicsService.predict_medication_response"
        assert log_args[1] == sample_patient_id

    @pytest.mark.asyncio  # Add async
    async def test_analyze_medication_interactions(
        self, service, mock_gene_medication_model, sample_genetic_data
    ) -> None:
        """Test the analyze_medication_interactions method."""
        # Setup
        medications = ["fluoxetine", "sertraline"]

        # Execute
        # Corrected function call
        result = await service.analyze_medication_interactions(
            genetic_data=sample_genetic_data, medications=medications
        )

        # Verify
        assert "gene_medication_interactions" in result
        assert "metabolizer_status" in result
        mock_gene_medication_model.predict_medication_interactions.assert_called_once()

    @pytest.mark.asyncio  # Add async
    async def test_analyze_medication_interactions_no_genetic_data(
        self, service
    ) -> None:  # Removed unused parameter
        """Test analyze_medication_interactions with no genetic data."""
        # Setup
        medications = ["fluoxetine", "sertraline"]

        # Execute/Assert
        with pytest.raises(ValueError) as excinfo:
            # Corrected function call
            await service.analyze_medication_interactions(
                genetic_data=None, medications=medications
            )

        assert "genetic data is required" in str(excinfo.value).lower()

    @pytest.mark.asyncio  # Add async
    async def test_is_model_healthy(
        self, service, mock_gene_medication_model, mock_treatment_model
    ) -> None:
        """Test the is_model_healthy method."""
        # Both models are healthy (as set in fixtures)
        assert await service.is_model_healthy() is True

        # Gene medication model is not initialized
        mock_gene_medication_model.is_initialized = False
        assert await service.is_model_healthy() is False

        # Gene medication model is initialized, but treatment model is not
        mock_gene_medication_model.is_initialized = True
        mock_treatment_model.is_initialized = False
        assert await service.is_model_healthy() is False

        # Both models are initialized again
        mock_treatment_model.is_initialized = True
        assert await service.is_model_healthy() is True

    @pytest.mark.asyncio  # Add async
    async def test_get_model_info(self, service, mock_gene_medication_model, mock_treatment_model) -> None:
        """Test the get_model_info method."""
        # Setup mock responses
        # Corrected return value structure
        mock_gene_medication_model.get_model_info = AsyncMock(
            return_value={
                "name": "GeneMedicationModel",
                "version": "1.0.0",
                "description": "Predicts medication interactions based on genetic variants",
            }
        )

        mock_treatment_model.get_model_info = AsyncMock(
            return_value={
                "name": "PharmacogenomicsModel",
                "version": "1.0.0",
                "description": "Predicts treatment response based on genetic and patient data",
            }
        )

        # Execute
        result = await service.get_model_info()

        # Verify
        assert "service_info" in result
        assert result["service_info"]["name"] == "PharmacogenomicsService"
        assert "gene_medication_model" in result
        assert "treatment_model" in result
        assert result["gene_medication_model"]["name"] == "GeneMedicationModel"
        assert result["treatment_model"]["name"] == "PharmacogenomicsModel"

    @pytest.mark.asyncio
    async def test_predict_treatment_response_success(
        self,
        pharmacogenomics_service: PharmacogenomicsService,
        mocker: MockerFixture,
        test_patient: Patient,
        test_report: PGXReport,
    ) -> None:
        # Mock the model's predict method
        mock_predict = mocker.patch.object(
            pharmacogenomics_service.model,
            "predict_treatment_response",
            new_callable=AsyncMock,
        )
        mock_predict.return_value = {
            "medication_recommendations": [
                {"medication": "fluoxetine", "recommendation": "Recommended"},
                {"medication": "sertraline", "recommendation": "Consider"},
            ],
            "prediction_generated_at": datetime.now(UTC).isoformat(),
        }

        # Mock the report service
        mock_report_service = mocker.patch(
            "app.infrastructure.ml.pharmacogenomics.model_service.PharmacogenomicReportService",
            autospec=True,
        )
        mock_report_service.get_latest_report_by_patient_id.return_value = test_report

        # Mock the patient service
        mock_patient_service = mocker.patch(
            "app.infrastructure.ml.pharmacogenomics.model_service.PatientService",
            autospec=True,
        )
        mock_patient_service.get_patient_by_id.return_value = test_patient

        # Create mock patient data (simplified)
        patient_data = {
            "age": 30,
            "sex": "Female",
            "genetic_markers": test_report.genetic_markers,
        }

        result = await pharmacogenomics_service.predict_treatment_response(
            test_patient.id, patient_data
        )

        assert "medication_recommendations" in result
        assert len(result["medication_recommendations"]) > 0
        assert "prediction_generated_at" in result
        mock_predict.assert_called_once()
        # Check that the model's predict was called with the combined data
        call_args, _ = mock_predict.call_args
        assert call_args[0] == test_patient.id
        # Ensure the model received the expected structure
        assert "age" in call_args[1]
        assert "sex" in call_args[1]
        assert "genetic_markers" in call_args[1]

    @pytest.mark.asyncio
    async def test_analyze_gene_medication_interactions_success(
        self,
        pharmacogenomics_service: PharmacogenomicsService,
        mocker: MockerFixture,
        test_patient: Patient,
        test_report: PGXReport,
    ) -> None:
        # Mock the model's analyze method
        mock_analyze = mocker.patch.object(
            pharmacogenomics_service.model,
            "analyze_gene_medication_interactions",
            new_callable=AsyncMock,
        )
        mock_analyze.return_value = {
            "gene_medication_interactions": [
                {
                    "gene": "CYP2D6",
                    "variant": "poor_metabolizer",
                    "medication": "fluoxetine",
                    "recommendation": "Consider dose adjustment",
                }
            ],
            "analysis_generated_at": datetime.now(UTC).isoformat(),
        }

        # Mock the report service
        mock_report_service = mocker.patch(
            "app.infrastructure.ml.pharmacogenomics.model_service.PharmacogenomicReportService",
            autospec=True,
        )
        mock_report_service.get_latest_report_by_patient_id.return_value = test_report

        # Mock the patient service
        mock_patient_service = mocker.patch(
            "app.infrastructure.ml.pharmacogenomics.model_service.PatientService",
            autospec=True,
        )
        mock_patient_service.get_patient_by_id.return_value = test_patient

        # Create mock patient data
        patient_data = {"genetic_markers": test_report.genetic_markers}

        result = await pharmacogenomics_service.analyze_gene_medication_interactions(
            test_patient.id, patient_data
        )

        assert "gene_medication_interactions" in result
        assert len(result["gene_medication_interactions"]) > 0
        assert "analysis_generated_at" in result
        mock_analyze.assert_called_once_with(test_report.genetic_markers)

    @pytest.mark.asyncio
    async def test_predict_side_effects_success(
        self,
        pharmacogenomics_service: PharmacogenomicsService,
        mocker: MockerFixture,
        test_patient: Patient,
        test_report: PGXReport,
    ) -> None:
        # Mock the model's predict_side_effects method
        mock_predict_se = mocker.patch.object(
            pharmacogenomics_service.model,
            "predict_side_effects",
            new_callable=AsyncMock,
        )
        mock_predict_se.return_value = {
            "medication": "fluoxetine",
            "side_effects": [
                {"side_effect": "nausea", "probability": 0.3},
                {"side_effect": "insomnia", "probability": 0.2},
            ],
            "prediction_generated_at": datetime.now(UTC).isoformat(),
        }

        # Mock the report service and patient service (as before)
        mocker.patch(
            "app.infrastructure.ml.pharmacogenomics.model_service.PharmacogenomicReportService",
            autospec=True,
        ).get_latest_report_by_patient_id.return_value = test_report
        mocker.patch(
            "app.infrastructure.ml.pharmacogenomics.model_service.PatientService",
            autospec=True,
        ).get_patient_by_id.return_value = test_patient

        # Create mock patient data
        patient_data = {
            "age": 30,
            "sex": "Female",
            "genetic_markers": test_report.genetic_markers,
        }
        medication_name = "fluoxetine"

        result = await pharmacogenomics_service.predict_side_effects(
            test_patient.id, patient_data, medication_name
        )

        assert "medication" in result
        assert result["medication"] == medication_name
        assert "side_effects" in result
        assert len(result["side_effects"]) > 0
        assert "prediction_generated_at" in result
        mock_predict_se.assert_called_once()
        call_args, _ = mock_predict_se.call_args
        assert call_args[0] == test_patient.id
        assert "genetic_markers" in call_args[1]  # Check patient_data arg
        assert call_args[2] == medication_name  # Check medication arg

    @pytest.mark.asyncio
    async def test_pharmacogenomics_service_handles_model_execution_error(
        self,
        pharmacogenomics_service: PharmacogenomicsService,
        mocker: MockerFixture,
        test_patient: Patient,
    ) -> None:
        # Mock the model's predict method to raise ModelExecutionError
        mock_predict = mocker.patch.object(
            pharmacogenomics_service.model,
            "predict_treatment_response",
            new_callable=AsyncMock,
        )
        mock_predict.side_effect = ModelExecutionError("Model prediction failed")

        # Mock services (as before)
        mocker.patch(
            "app.infrastructure.ml.pharmacogenomics.model_service.PharmacogenomicReportService",
            autospec=True,
        ).get_latest_report_by_patient_id.return_value = MagicMock(spec=PGXReport)
        mocker.patch(
            "app.infrastructure.ml.pharmacogenomics.model_service.PatientService",
            autospec=True,
        ).get_patient_by_id.return_value = test_patient

        patient_data = {"age": 30, "sex": "Female", "genetic_markers": {}}

        with pytest.raises(ModelExecutionError, match="Model prediction failed"):
            await pharmacogenomics_service.predict_treatment_response(test_patient.id, patient_data)

    @pytest.mark.asyncio
    async def test_pharmacogenomics_service_handles_validation_error(
        self,
        pharmacogenomics_service: PharmacogenomicsService,
        mocker: MockerFixture,
        test_patient: Patient,
    ) -> None:
        # No need to mock the model itself, validation happens before model call
        # Mock services (as before)
        mocker.patch(
            "app.infrastructure.ml.pharmacogenomics.model_service.PharmacogenomicReportService",
            autospec=True,
        ).get_latest_report_by_patient_id.return_value = MagicMock(spec=PGXReport)
        mocker.patch(
            "app.infrastructure.ml.pharmacogenomics.model_service.PatientService",
            autospec=True,
        ).get_patient_by_id.return_value = test_patient

        # Provide invalid patient data (e.g., missing genetic_markers for analysis)
        invalid_patient_data = {"age": 30, "sex": "Female"}

        with pytest.raises(ValidationError, match="Patient data must include genetic markers"):
            await pharmacogenomics_service.analyze_gene_medication_interactions(
                test_patient.id, invalid_patient_data
            )

    # Test cases for the helper methods could be added here if they were complex
    # e.g., _extract_patient_features, _validate_patient_data
