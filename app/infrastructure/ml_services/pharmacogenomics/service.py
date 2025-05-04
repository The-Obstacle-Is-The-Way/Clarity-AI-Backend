"""
/mnt/c/Users/JJ/Desktop/NOVAMIND-WEB/Novamind-Backend/app/infrastructure/ml_services/pharmacogenomics/service.py

Implementation of the Pharmacogenomics Service that connects to ML models
for predicting medication responses based on genetic markers and patient history.
"""

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

# Use canonical config path
from app.domain.interfaces.ml_services import PharmacogenomicsService
from app.infrastructure.ml.pharmacogenomics.gene_medication_model import (
    GeneMedicationModel,
)
from app.infrastructure.ml.pharmacogenomics.treatment_model import (
    TreatmentResponseModel,
)
from app.infrastructure.ml.utils.preprocessing import (
    preprocess_genetic_data,
    preprocess_medication_history,
)

logger = logging.getLogger(__name__)


class PharmacogenomicsServiceImpl(PharmacogenomicsService):
    """
    Implementation of the Pharmacogenomics Service.

    This service connects to ML models for predicting medication responses
    based on genetic markers and patient history, supporting personalized
    treatment planning.

    Attributes:
        gene_medication_model: Model for gene-medication interaction analysis
        treatment_model: Model for treatment response prediction
    """

    def __init__(self):
        """Initialize the Pharmacogenomics Service with required models."""
        self.gene_medication_model = GeneMedicationModel()
        self.treatment_model = TreatmentResponseModel()

        # Load models
        self._load_models()

        logger.info("Pharmacogenomics Service initialized successfully")

    def _load_models(self) -> None:
        """Load all required models from storage."""
        try:
            model_path = settings.PHARMACOGENOMICS_MODEL_PATH

            # Load individual models
            self.gene_medication_model.load(f"{model_path}/gene_medication_model.pkl")
            self.treatment_model.load(f"{model_path}/treatment_response_model.pkl")

            logger.info("All pharmacogenomics models loaded successfully")
        except Exception as e:
            logger.error(f"Error loading pharmacogenomics models: {e!s}")
            raise RuntimeError(f"Failed to load pharmacogenomics models: {e!s}")

    async def predict_medication_response(
        self, patient_id: UUID, genetic_data: dict[str, Any], medication_id: str
    ) -> dict[str, Any]:
        """
        Predict patient's response to a specific medication based on genetic markers.

        Args:
            patient_id: UUID of the patient
            genetic_data: Dictionary containing patient's genetic markers
            medication_id: Identifier for the medication

        Returns:
            Dictionary containing predicted response with confidence scores
        """
        logger.info(
            f"Predicting medication response for patient {patient_id}, medication: {medication_id}"
        )

        try:
            # Preprocess the genetic data
            processed_genetic_data = preprocess_genetic_data(genetic_data)

            # Predict medication response
            response_prediction = self.gene_medication_model.predict_response(
                processed_genetic_data, medication_id
            )

            # Format the results
            result = {
                "patient_id": str(patient_id),
                "medication_id": medication_id,
                "prediction_generated_at": datetime.now().isoformat(),
                "predicted_response": response_prediction["response_category"],
                "response_probability": response_prediction["probability"],
                "confidence_score": response_prediction["confidence"],
                "relevant_genetic_markers": response_prediction["relevant_markers"],
                "recommendation": self._generate_medication_recommendation(
                    response_prediction
                ),
            }

            logger.info(
                f"Medication response prediction completed for patient {patient_id}"
            )
            return result

        except Exception as e:
            logger.error(
                f"Error predicting medication response for patient {patient_id}: {e!s}"
            )
            raise RuntimeError(f"Failed to predict medication response: {e!s}")

    async def analyze_gene_interactions(
        self, patient_id: UUID, genetic_data: dict[str, Any], medications: list[str]
    ) -> dict[str, Any]:
        """
        Analyze interactions between genetic markers and multiple medications.

        Args:
            patient_id: UUID of the patient
            genetic_data: Dictionary containing patient's genetic markers
            medications: List of medication identifiers

        Returns:
            Dictionary containing interaction analysis for each medication
        """
        logger.info(
            f"Analyzing gene interactions for patient {patient_id}, medications: {medications}"
        )

        try:
            # Preprocess the genetic data
            processed_genetic_data = preprocess_genetic_data(genetic_data)

            # Analyze interactions for each medication
            interactions = {}
            for medication_id in medications:
                interaction = self.gene_medication_model.analyze_interaction(
                    processed_genetic_data, medication_id
                )
                interactions[medication_id] = interaction

            # Identify potential contraindications
            contraindications = self._identify_contraindications(interactions)

            # Format the results
            result = {
                "patient_id": str(patient_id),
                "analysis_generated_at": datetime.now().isoformat(),
                "medications_analyzed": medications,
                "gene_interactions": interactions,
                "contraindications": contraindications,
                "summary": self._generate_interaction_summary(
                    interactions, contraindications
                ),
            }

            logger.info(f"Gene interaction analysis completed for patient {patient_id}")
            return result

        except Exception as e:
            logger.error(
                f"Error analyzing gene interactions for patient {patient_id}: {e!s}"
            )
            raise RuntimeError(f"Failed to analyze gene interactions: {e!s}")

    async def generate_treatment_plan(
        self,
        patient_id: UUID,
        genetic_data: dict[str, Any],
        medication_history: dict[str, Any],
        condition: str,
    ) -> dict[str, Any]:
        """
        Generate personalized treatment plan based on genetic data and medication history.

        Args:
            patient_id: UUID of the patient
            genetic_data: Dictionary containing patient's genetic markers
            medication_history: Dictionary containing patient's medication history
            condition: The psychiatric condition to generate treatment plan for

        Returns:
            Dictionary containing personalized treatment plan recommendations
        """
        logger.info(
            f"Generating treatment plan for patient {patient_id}, condition: {condition}"
        )

        try:
            # Preprocess the input data
            processed_genetic_data = preprocess_genetic_data(genetic_data)
            processed_history = preprocess_medication_history(medication_history)

            # Generate treatment plan
            treatment_plan = self.treatment_model.generate_plan(
                processed_genetic_data, processed_history, condition
            )

            # Format the results
            result = {
                "patient_id": str(patient_id),
                "plan_generated_at": datetime.now().isoformat(),
                "condition": condition,
                "recommended_medications": treatment_plan["medications"],
                "dosage_recommendations": treatment_plan["dosages"],
                "expected_efficacy": treatment_plan["efficacy_scores"],
                "potential_side_effects": treatment_plan["side_effects"],
                "monitoring_recommendations": treatment_plan["monitoring"],
                "summary": treatment_plan["summary"],
            }

            logger.info(f"Treatment plan generated for patient {patient_id}")
            return result

        except Exception as e:
            logger.error(
                f"Error generating treatment plan for patient {patient_id}: {e!s}"
            )
            raise RuntimeError(f"Failed to generate treatment plan: {e!s}")

    def _identify_contraindications(
        self, interactions: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Identify contraindications from gene-medication interactions."""
        contraindications = []

        for medication_id, interaction in interactions.items():
            if interaction["risk_level"] >= 3:  # High risk level
                contraindications.append(
                    {
                        "medication_id": medication_id,
                        "risk_level": interaction["risk_level"],
                        "reason": interaction["risk_reason"],
                        "recommendation": "Avoid use",
                    }
                )

        return contraindications

    def _generate_medication_recommendation(
        self, response_prediction: dict[str, Any]
    ) -> str:
        """Generate a recommendation based on predicted medication response."""
        # Implementation would create a recommendation based on the prediction
        # This is a placeholder for the actual implementation
        return "Medication recommendation would be generated here."

    def _generate_interaction_summary(
        self, interactions: dict[str, Any], contraindications: list[dict[str, Any]]
    ) -> str:
        """Generate a human-readable summary of gene-medication interactions."""
        # Implementation would create a natural language summary of interactions
        # This is a placeholder for the actual implementation
        return "Gene-medication interaction summary would be generated here."
