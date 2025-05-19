"""
Digital Twin Integration Service implementation.

This service coordinates various ML microservices and integrates their outputs
to provide a unified interface for digital twin functionality.
"""

import logging
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

# Core imports
from app.domain.entities.digital_twin.digital_twin import DigitalTwin

logger = logging.getLogger(__name__)


class DigitalTwinIntegrationService:
    """
    Service that integrates multiple ML microservices to provide comprehensive
    patient insights through a digital twin.
    """

    def __init__(
        self,
        symptom_forecasting_service: Any,
        biometric_correlation_service: Any,
        pharmacogenomics_service: Any,
        recommendation_engine: Any,
        patient_repository: Any = None,
    ):
        """
        Initialize the integration service with its dependencies.

        Args:
            symptom_forecasting_service: Service for forecasting symptom trajectory
            biometric_correlation_service: Service for analyzing biometric correlations
            pharmacogenomics_service: Service for predicting pharmacogenomic responses
            recommendation_engine: Service for generating recommendations
            patient_repository: Optional repository for patient data
        """
        self.symptom_forecasting_service = symptom_forecasting_service
        self.biometric_correlation_service = biometric_correlation_service
        self.pharmacogenomics_service = pharmacogenomics_service
        self.recommendation_engine = recommendation_engine
        self.patient_repository = patient_repository
        self._digital_twins = {}  # Cache for digital twins
        logger.info("Digital Twin Integration Service initialized")

    async def create_digital_twin(
        self, patient_id: str, init_data: dict = None
    ) -> DigitalTwin:
        """
        Create a new digital twin for a patient.

        Args:
            patient_id: Patient identifier
            init_data: Optional initialization data

        Returns:
            New DigitalTwin instance
        """
        init_data = init_data or {}
        digital_twin = DigitalTwin(
            id=f"dt-{patient_id}-{uuid4()}",
            patient_id=patient_id,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            **init_data,
        )
        self._digital_twins[digital_twin.id] = digital_twin
        logger.info(f"Created digital twin {digital_twin.id} for patient {patient_id}")
        return digital_twin

    async def get_digital_twin(self, digital_twin_id: str) -> DigitalTwin | None:
        """
        Retrieve a digital twin by its ID.

        Args:
            digital_twin_id: Digital twin identifier

        Returns:
            DigitalTwin instance if found, None otherwise
        """
        if digital_twin_id in self._digital_twins:
            return self._digital_twins[digital_twin_id]
        logger.warning(f"Digital twin not found: {digital_twin_id}")
        return None

    async def get_digital_twin_by_patient(
        self, patient_id: str
    ) -> DigitalTwin | None:
        """
        Retrieve a digital twin by patient ID.

        Args:
            patient_id: Patient identifier

        Returns:
            DigitalTwin instance if found, None otherwise
        """
        for dt in self._digital_twins.values():
            if dt.patient_id == patient_id:
                return dt
        logger.info(f"No digital twin found for patient {patient_id}")
        return None

    async def update_digital_twin(
        self, digital_twin_id: str, updates: dict
    ) -> DigitalTwin | None:
        """
        Update a digital twin with new data.

        Args:
            digital_twin_id: Digital twin identifier
            updates: Dictionary of attributes to update

        Returns:
            Updated DigitalTwin instance if found, None otherwise
        """
        if digital_twin_id not in self._digital_twins:
            logger.warning(
                f"Cannot update non-existent digital twin: {digital_twin_id}"
            )
            return None

        digital_twin = self._digital_twins[digital_twin_id]
        for key, value in updates.items():
            if hasattr(digital_twin, key):
                setattr(digital_twin, key, value)

        digital_twin.updated_at = datetime.now()
        self._digital_twins[digital_twin_id] = digital_twin
        logger.info(f"Updated digital twin {digital_twin_id}")
        return digital_twin

    async def simulate_intervention(
        self, digital_twin_id: str, intervention: dict
    ) -> dict:
        """
        Simulate the effect of an intervention on a digital twin.

        Args:
            digital_twin_id: Digital twin identifier
            intervention: Intervention details

        Returns:
            Dictionary containing simulation results
        """
        if digital_twin_id not in self._digital_twins:
            logger.warning(
                f"Cannot simulate on non-existent digital twin: {digital_twin_id}"
            )
            return {"error": "Digital twin not found"}

        digital_twin = self._digital_twins[digital_twin_id]

        # Example simulation logic
        intervention_type = intervention.get("type", "unknown")
        intervention_params = intervention.get("params", {})

        result = {
            "digital_twin_id": digital_twin_id,
            "patient_id": digital_twin.patient_id,
            "intervention_type": intervention_type,
            "simulation_time": datetime.now().isoformat(),
            "projected_outcomes": {},
        }

        if intervention_type == "medication":
            # Simulate medication effect using medication response service
            try:
                med_name = intervention_params.get("medication_name")
                med_dose = intervention_params.get("dose")

                if med_name and med_dose:
                    response = (
                        await self.pharmacogenomics_service.analyze_medication_response(
                            patient_id=digital_twin.patient_id,
                            medication_name=med_name,
                            dose=med_dose,
                        )
                    )

                    result["projected_outcomes"] = {
                        "efficacy": response.get("efficacy", {"score": 0.0}),
                        "side_effects": response.get("side_effects", []),
                        "projected_symptom_changes": response.get(
                            "symptom_changes", {}
                        ),
                    }
            except Exception as e:
                logger.error(f"Error simulating medication effect: {e}")
                result["error"] = f"Simulation error: {e!s}"

        elif intervention_type == "therapy":
            # Example therapy simulation
            result["projected_outcomes"] = {
                "efficacy": {"score": 0.75},
                "engagement": 0.8,
                "projected_symptom_changes": {"anxiety": -0.3, "depression": -0.25},
            }

        logger.info(
            f"Simulated {intervention_type} intervention on digital twin {digital_twin_id}"
        )
        return result

    async def generate_comprehensive_patient_insights(
        self, patient_id: UUID, patient_data: dict
    ) -> dict:
        """
        Generate comprehensive insights for a patient by integrating outputs from all services.

        Args:
            patient_id: Patient identifier
            patient_data: Dictionary containing patient data for analysis

        Returns:
            Dictionary containing integrated insights
        """
        logger.info(f"Generating comprehensive insights for patient {patient_id}")

        # Sanitize the patient data to ensure no PHI is present
        sanitized_data = self._sanitize_patient_data(patient_data)

        # Initialize the results dictionary
        result = {}
        error_occurred = False

        # Try to get symptom forecasting insights
        try:
            forecast_result = await self.symptom_forecasting_service.forecast_symptoms(
                patient_id=str(patient_id),
                symptom_history=sanitized_data.get("symptom_history", {}),
                mental_health_indicators=sanitized_data.get(
                    "mental_health_indicators", {}
                ),
            )
            # Only add to result if successful
            result["symptom_forecasting"] = forecast_result
        except Exception as e:
            logger.error(f"Error in symptom forecasting service: {e}")
            error_occurred = True
            # Do not add symptom_forecasting to result

        # Try to get biometric correlation insights
        try:
            correlation_result = (
                await self.biometric_correlation_service.analyze_correlations(
                    patient_id=str(patient_id),
                    biometric_data=sanitized_data.get("biometric_data", {}),
                    symptom_history=sanitized_data.get("symptom_history", {}),
                )
            )
            # Only add to result if successful
            result["biometric_correlation"] = correlation_result
        except Exception as e:
            logger.error(f"Error in biometric correlation service: {e}")
            error_occurred = True

        # Try to get pharmacogenomics insights
        try:
            pharma_result = (
                await self.pharmacogenomics_service.analyze_medication_response(
                    patient_id=str(patient_id),
                    genetic_markers=sanitized_data.get("genetic_markers", {}),
                    medications=sanitized_data.get("medications", []),
                )
            )
            # Only add to result if successful
            result["pharmacogenomics"] = pharma_result
        except Exception as e:
            logger.error(f"Error in pharmacogenomics service: {e}")
            error_occurred = True

        # Generate integrated recommendations if we have enough data
        if len(result) > 0:
            try:
                recommendations = (
                    await self.recommendation_engine.generate_recommendations(
                        patient_id=str(patient_id), insights=result
                    )
                )
                result["integrated_recommendations"] = recommendations
            except Exception as e:
                logger.error(f"Error in recommendation engine: {e}")
                error_occurred = True

        # Add error status if any service failed
        if error_occurred:
            result["partial_results"] = True
            result["error"] = "One or more services failed to generate insights"

        return result

    def _sanitize_patient_data(self, patient_data: dict) -> dict:
        """
        Sanitize patient data to ensure no PHI is included.

        Args:
            patient_data: Dictionary containing patient data

        Returns:
            Sanitized copy of patient data
        """
        # Create a deep copy to avoid modifying the original
        sanitized = patient_data.copy()

        # List of PHI fields to remove at top level and within nested dictionaries
        phi_fields = [
            "name",
            "address",
            "phone",
            "email",
            "dob",
            "ssn",
            "date_of_birth",
            "personal_info",
            "contact_info",
            "location",
        ]

        # Remove PHI fields at the top level
        for field in phi_fields:
            if field in sanitized:
                del sanitized[field]

        # Remove PHI fields in nested dictionaries
        for key, value in list(sanitized.items()):
            if isinstance(value, dict):
                for field in phi_fields:
                    if field in value:
                        del value[field]

        return sanitized

    async def generate_comprehensive_insights(
        self, patient_id: str, options: dict
    ) -> dict:
        """
        Generate comprehensive insights for a patient by integrating outputs from all services.

        Args:
            patient_id: Patient identifier
            options: Dictionary of options controlling which insights to generate

        Returns:
            Dictionary containing integrated insights
        """
        logger.info(f"Generating comprehensive insights for patient {patient_id}")

        result = {
            "patient_id": patient_id,
            "generated_at": datetime.now().isoformat(),
            "integrated_recommendations": [],
        }

        errors = {}

        # Generate symptom forecast if requested
        if options.get("include_symptom_forecast", True):
            try:
                forecast_days = options.get("forecast_days", 30)
                forecast = await self.symptom_forecasting_service.generate_forecast(
                    patient_id=patient_id, horizon_days=forecast_days
                )
                result["symptom_forecast"] = forecast
            except Exception as e:
                logger.error(f"Error generating symptom forecast: {e}")
                errors["symptom_forecast"] = str(e)

        # Analyze biometric correlations if requested
        if options.get("include_biometric_correlations", True):
            try:
                lookback_days = options.get("biometric_lookback_days", 30)
                correlations = (
                    await self.biometric_correlation_service.analyze_correlations(
                        patient_id=patient_id, lookback_days=lookback_days
                    )
                )
                result["biometric_correlations"] = correlations
            except Exception as e:
                logger.error(f"Error analyzing biometric correlations: {e}")
                errors["biometric_correlations"] = str(e)

        # Predict medication responses if requested
        if options.get("include_medication_predictions", True):
            try:
                medication_predictions = (
                    await self.pharmacogenomics_service.analyze_medication_response(
                        patient_id=patient_id
                    )
                )
                result["medication_predictions"] = medication_predictions
            except Exception as e:
                logger.error(f"Error predicting medication responses: {e}")
                errors["medication_predictions"] = str(e)

        # Add integrated recommendations
        if "symptom_forecast" in result or "biometric_correlations" in result:
            # Pass the entire result dictionary as insights
            result[
                "integrated_recommendations"
            ] = await self._generate_integrated_recommendations(result)

        # Include errors if any
        if errors:
            result["errors"] = errors

        return result

    async def _generate_integrated_recommendations(self, insights: dict) -> list:
        """
        Generate integrated recommendations based on combined insights.

        This internal method combines insights from different services to create
        unified, prioritized recommendations.

        Args:
            insights: Combined insights dictionary containing symptom forecasts,
                     biometric correlations, and medication predictions

        Returns:
            List of integrated recommendations
        """
        recommendations = []

        # Extract the individual insight components
        symptom_forecast = insights.get("symptom_forecast", {})
        biometric_correlations = insights.get("biometric_correlations", {})
        medication_predictions = insights.get("medication_predictions", {})

        # Process biometric correlations
        if biometric_correlations and "correlations" in biometric_correlations:
            for correlation in biometric_correlations["correlations"]:
                coefficient = correlation.get("coefficient", 0)
                if abs(coefficient) > 0.6:
                    biometric_type = correlation.get("biometric_type", "biometric")
                    symptom_type = correlation.get("symptom_type", "symptom")
                    direction = "negatively" if coefficient < 0 else "positively"

                    recommendations.append(
                        {
                            "type": "biometric_monitoring",
                            "recommendation": f"Monitor {biometric_type} closely as it correlates {direction} with {symptom_type}",
                            "confidence": min(abs(coefficient), 0.95),
                            "supporting_evidence": [
                                f"{biometric_type} correlation coefficient: {coefficient:.2f}",
                                f"Lag hours: {correlation.get('lag_hours', 0)}",
                            ],
                            "priority": "high" if abs(coefficient) > 0.7 else "medium",
                        }
                    )

        # Process symptom forecasts
        if symptom_forecast and "forecasts" in symptom_forecast:
            for symptom, values in symptom_forecast["forecasts"].items():
                if len(values) >= 2:
                    trend = values[0] - values[-1]
                    if abs(trend) > 0.3:
                        direction = "improving" if trend > 0 else "worsening"
                        confidence = symptom_forecast.get("reliability", "medium")
                        confidence_value = 0.8 if confidence == "high" else 0.6

                        recommendations.append(
                            {
                                "type": "behavioral",
                                "recommendation": f"{symptom.title()} symptoms show {direction} trend. "
                                + (
                                    "Continue current treatment plan."
                                    if trend > 0
                                    else "Consider treatment adjustment."
                                ),
                                "confidence": confidence_value,
                                "supporting_evidence": [
                                    f"{symptom.title()} forecast: {', '.join([str(round(v, 2)) for v in values])}",
                                    f"Forecast reliability: {confidence}",
                                ],
                                "priority": "medium" if trend > 0 else "high",
                            }
                        )

        # Process medication predictions
        if (
            medication_predictions
            and "medication_predictions" in medication_predictions
        ):
            for med_name, med_data in medication_predictions[
                "medication_predictions"
            ].items():
                if (
                    "efficacy" in med_data
                    and med_data["efficacy"].get("score", 0) > 0.7
                ):
                    efficacy_score = med_data["efficacy"].get("score", 0)
                    confidence = med_data["efficacy"].get("confidence", 0.8)

                    side_effects_text = []
                    if "side_effects" in med_data:
                        for se in med_data["side_effects"]:
                            side_effects_text.append(
                                f"{se.get('name', 'Unknown')} ({se.get('risk', 0):.2f} risk, {se.get('severity', 'unknown')})"
                            )

                    recommendations.append(
                        {
                            "type": "medication",
                            "recommendation": f"{med_name.title()} shows high predicted efficacy"
                            + (
                                f" with {len(side_effects_text)} potential side effects."
                                if side_effects_text
                                else "."
                            ),
                            "confidence": confidence,
                            "supporting_evidence": [
                                f"Efficacy score: {efficacy_score:.2f}",
                                f"Confidence: {confidence:.2f}",
                            ]
                            + (
                                ["Side effects: " + ", ".join(side_effects_text)]
                                if side_effects_text
                                else []
                            ),
                            "priority": "medium",
                        }
                    )

        # Sort recommendations by priority
        priority_order = {"high": 0, "medium": 1, "low": 2}
        recommendations.sort(
            key=lambda x: priority_order.get(x.get("priority", "low"), 99)
        )

        return recommendations

    async def _get_patient_data(self, patient_id: str) -> dict:
        """
        Internal method to retrieve patient data from the repository.

        Args:
            patient_id: Patient identifier

        Returns:
            Dictionary containing patient data

        Raises:
            ValueError: If patient not found
        """
        if not self.patient_repository:
            raise ValueError("Patient repository not available")

        try:
            patient = await self.patient_repository.get_by_id(patient_id)
            if not patient:
                raise ValueError(f"Patient not found: {patient_id}")
            return patient
        except Exception as e:
            logger.error(f"Error retrieving patient data: {e}")
            raise ValueError(f"Error retrieving patient data: {e!s}")

    async def get_patient_data(self, patient_id: str) -> dict:
        """
        Get patient data from the repository.

        Args:
            patient_id: Patient identifier

        Returns:
            Dictionary containing patient data
        """
        if not self.patient_repository:
            logger.warning("Patient repository not available")
            return {"id": patient_id}

        try:
            patient = await self.patient_repository.get_by_id(patient_id)
            if not patient:
                logger.warning(f"Patient not found: {patient_id}")
                return {"id": patient_id}
            return patient
        except Exception as e:
            logger.error(f"Error retrieving patient data: {e}")
            return {"id": patient_id, "error": str(e)}
