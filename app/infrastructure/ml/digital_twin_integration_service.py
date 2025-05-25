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
from app.domain.interfaces.ml_services import IDigitalTwinIntegrationService

logger = logging.getLogger(__name__)


class DigitalTwinIntegrationService(IDigitalTwinIntegrationService):
    """
    Service that integrates multiple ML microservices to provide comprehensive
    patient insights through a digital twin.
    
    This class implements the IDigitalTwinIntegrationService interface from the domain layer.
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
        self._digital_twins: dict[UUID, DigitalTwin] = {}  # Cache for digital twins
        logger.info("Digital Twin Integration Service initialized")

    async def create_digital_twin(self, patient_id: UUID, init_data: dict[str, Any] | None = None) -> DigitalTwin:
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
            id=uuid4(),
            patient_id=patient_id,
            created_at=datetime.now(),
            last_updated=datetime.now(),
            **init_data,
        )
        self._digital_twins[digital_twin.id] = digital_twin
        logger.info(f"Created digital twin {digital_twin.id} for patient {patient_id}")
        return digital_twin

    async def get_digital_twin(self, digital_twin_id: UUID) -> DigitalTwin | None:
        """
        Retrieve a digital twin by its ID.

        Args:
            digital_twin_id: Digital twin identifier

        Returns:
            DigitalTwin instance if found, None otherwise
        """
        if digital_twin_id in self._digital_twins:
            twin: DigitalTwin = self._digital_twins[digital_twin_id]
            return twin
        logger.warning(f"Digital twin not found: {digital_twin_id}")
        return None

    async def get_digital_twin_by_patient(self, patient_id: UUID) -> DigitalTwin | None:
        """
        Retrieve a digital twin by patient ID.

        Args:
            patient_id: Patient identifier

        Returns:
            DigitalTwin instance if found, None otherwise
        """
        for dt in self._digital_twins.values():
            if dt.patient_id == patient_id:
                twin: DigitalTwin = dt
                return twin
        logger.info(f"No digital twin found for patient {patient_id}")
        return None

    async def update_digital_twin(self, patient_id: UUID, patient_data: dict[str, Any]) -> dict[str, Any]:
        """
        Update the Digital Twin with new patient data.

        Args:
            patient_id: UUID of the patient
            patient_data: New patient data

        Returns:
            Dictionary containing update status
        """
        # Find the digital twin for this patient
        digital_twin = await self.get_digital_twin_by_patient(patient_id)
        if not digital_twin:
            logger.warning(f"Cannot update non-existent digital twin for patient: {patient_id}")
            return {"success": False, "error": "Digital twin not found"}

        # Extract updates from patient data
        updates = {}
        if "clinical_data" in patient_data:
            updates["clinical_data"] = patient_data["clinical_data"]
        if "biometric_data" in patient_data:
            updates["biometric_data"] = patient_data["biometric_data"]
        
        # Apply updates to the digital twin
        for key, value in updates.items():
            if hasattr(digital_twin, key):
                setattr(digital_twin, key, value)

        digital_twin.last_updated = datetime.now()
        self._digital_twins[digital_twin.id] = digital_twin
        logger.info(f"Updated digital twin for patient {patient_id}")
        
        return {
            "success": True,
            "digital_twin_id": str(digital_twin.id),
            "updated_at": digital_twin.last_updated.isoformat()
        }

    async def simulate_intervention(self, digital_twin_id: UUID, intervention: dict[str, Any]) -> dict[str, Any]:
        """
        Simulate the effect of an intervention on a digital twin.

        Args:
            digital_twin_id: Digital twin identifier
            intervention: Intervention details

        Returns:
            Dictionary containing simulation results
        """
        if digital_twin_id not in self._digital_twins:
            logger.warning(f"Cannot simulate on non-existent digital twin: {digital_twin_id}")
            return {"error": "Digital twin not found"}

        digital_twin = self._digital_twins[digital_twin_id]

        # Example simulation logic
        intervention_type = intervention.get("type", "unknown")
        intervention_params = intervention.get("params", {})

        result = {
            "digital_twin_id": str(digital_twin_id),
            "patient_id": str(digital_twin.patient_id),
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
                    response = await self.pharmacogenomics_service.analyze_medication_response(
                        patient_id=digital_twin.patient_id,
                        medication_name=med_name,
                        dose=med_dose,
                    )

                    result["projected_outcomes"] = {
                        "efficacy": response.get("efficacy", {"score": 0.0}),
                        "side_effects": response.get("side_effects", []),
                        "projected_symptom_changes": response.get("symptom_changes", {}),
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

        logger.info(f"Simulated {intervention_type} intervention on digital twin {digital_twin_id}")
        return result

    async def generate_comprehensive_patient_insights(
        self, patient_id: UUID, patient_data: dict[str, Any]
    ) -> dict[str, Any]:
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
                mental_health_indicators=sanitized_data.get("mental_health_indicators", {}),
            )
            # Only add to result if successful
            result["symptom_forecasting"] = forecast_result
        except Exception as e:
            logger.error(f"Error in symptom forecasting service: {e}")
            error_occurred = True
            # Do not add symptom_forecasting to result

        # Try to get biometric correlation insights
        try:
            correlation_result = await self.biometric_correlation_service.analyze_correlations(
                patient_id=str(patient_id),
                biometric_data=sanitized_data.get("biometric_data", {}),
                symptom_history=sanitized_data.get("symptom_history", {}),
            )
            # Only add to result if successful
            result["biometric_correlation"] = correlation_result
        except Exception as e:
            logger.error(f"Error in biometric correlation service: {e}")
            error_occurred = True

        # Try to get pharmacogenomics insights
        try:
            pharma_result = await self.pharmacogenomics_service.analyze_medication_response(
                patient_id=str(patient_id),
                genetic_markers=sanitized_data.get("genetic_markers", {}),
                medications=sanitized_data.get("medications", []),
            )
            # Only add to result if successful
            result["pharmacogenomics"] = pharma_result
        except Exception as e:
            logger.error(f"Error in pharmacogenomics service: {e}")
            error_occurred = True

        # Generate integrated recommendations if we have enough data
        if len(result) > 0:
            try:
                recommendations = await self.recommendation_engine.generate_recommendations(
                    patient_id=str(patient_id), insights=result
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

    def _sanitize_patient_data(self, patient_data: dict[str, Any]) -> dict[str, Any]:
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
        for _key, value in list(sanitized.items()):
            if isinstance(value, dict):
                for field in phi_fields:
                    if field in value:
                        del value[field]

        return sanitized

    async def get_digital_twin_status(self, patient_id: UUID) -> dict[str, Any]:
        """
        Get the status of the Digital Twin for a specific patient.

        Args:
            patient_id: UUID of the patient

        Returns:
            Dictionary containing Digital Twin status

        Raises:
            ValidationError: If the patient ID is invalid
            ModelInferenceError: If the status cannot be retrieved
        """
        logger.info(f"Getting digital twin status for patient {patient_id}")
        
        digital_twin = await self.get_digital_twin_by_patient(patient_id)
        if not digital_twin:
            logger.warning(f"No digital twin found for patient {patient_id}")
            return {
                "exists": False,
                "patient_id": str(patient_id),
                "message": "No digital twin exists for this patient"
            }
            
        return {
            "exists": True,
            "patient_id": str(patient_id),
            "digital_twin_id": str(digital_twin.id),
            "created_at": digital_twin.created_at.isoformat(),
            "updated_at": digital_twin.last_updated.isoformat(),
            "version": digital_twin.version,
            "state": {
                "last_sync_time": digital_twin.state.last_sync_time.isoformat() if digital_twin.state.last_sync_time else None,
                "overall_risk_level": digital_twin.state.overall_risk_level,
                "dominant_symptoms": digital_twin.state.dominant_symptoms,
                "current_treatment_effectiveness": digital_twin.state.current_treatment_effectiveness
            }
        }
    async def get_historical_insights(
        self, patient_id: UUID, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """
        Get historical insights for a specific time period.

        Args:
            patient_id: UUID of the patient
            start_date: Start date for historical insights
            end_date: End date for historical insights

        Returns:
            Dictionary containing historical insights

        Raises:
            ValidationError: If the input data is invalid
            ModelInferenceError: If the retrieval fails
        """
        logger.info(f"Getting historical insights for patient {patient_id} from {start_date} to {end_date}")
        
        # Validate date range
        if end_date < start_date:
            logger.error(f"Invalid date range: {start_date} to {end_date}")
            return {
                "error": "Invalid date range: end date must be after start date",
                "patient_id": str(patient_id)
            }
            
        # Get the digital twin
        digital_twin = await self.get_digital_twin_by_patient(patient_id)
        if not digital_twin:
            logger.warning(f"No digital twin found for patient {patient_id}")
            return {
                "error": "No digital twin exists for this patient",
                "patient_id": str(patient_id)
            }
            
        # In a real implementation, we would query historical data from a database
        # For this implementation, we'll return a placeholder
        return {
            "patient_id": str(patient_id),
            "time_range": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "generated_at": datetime.now().isoformat(),
            "insights": [],  # Placeholder for historical insights
            "message": "Historical insights functionality is not fully implemented"
        }
        
    async def generate_comprehensive_insights(
        self, patient_id: UUID, options: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Generate comprehensive patient insights by integrating multiple ML services.
        
        Args:
            patient_id: The ID of the patient
            options: Options for controlling which insights to generate
                include_symptom_forecast: Whether to include symptom forecasting
                include_biometric_correlations: Whether to include biometric correlations
                include_medication_predictions: Whether to include medication predictions
                forecast_days: Number of days to forecast symptoms
                biometric_lookback_days: Number of days to look back for biometric data
        
        Returns:
            A dictionary containing comprehensive patient insights
        """
        options = options or {}
            
        # Get patient data
        patient_data = await self._get_patient_data(patient_id)
        
        # Initialize insights dictionary
        insights: dict[str, Any] = {
            "patient_id": str(patient_id),
            "generated_at": datetime.now().isoformat(),
        }
        
        # Track any errors that occur
        errors: dict[str, str] = {}
        
        # Generate symptom forecast if requested
        if options.get("include_symptom_forecast", True):
            try:
                forecast = await self.symptom_forecasting_service.generate_forecast(
                    patient_id=str(patient_id),
                    days=options.get("forecast_days", 14),
                    conditions=patient_data.get("conditions", []),
                )
                insights["symptom_forecast"] = forecast
            except Exception as e:
                logger.error(f"Error generating symptom forecast: {e!s}")
                errors["symptom_forecast"] = str(e)
        
        # Generate biometric correlations if requested
        if options.get("include_biometric_correlations", True):
            try:
                correlations = await self.biometric_correlation_service.analyze_correlations(
                    patient_id=str(patient_id),
                    lookback_days=options.get("biometric_lookback_days", 30),
                )
                insights["biometric_correlations"] = correlations
            except Exception as e:
                logger.error(f"Error analyzing biometric correlations: {e!s}")
                errors["biometric_correlations"] = str(e)
        
        # Generate medication predictions if requested
        if options.get("include_medication_predictions", True):
            try:
                medications = patient_data.get("medications", [])
                predictions = await self.pharmacogenomics_service.analyze_medication_response(
                    patient_id=str(patient_id),
                    medications=medications,
                )
                insights["medication_predictions"] = predictions
            except Exception as e:
                logger.error(f"Error analyzing medication response: {e!s}")
                errors["medication_predictions"] = str(e)
        
        # Generate integrated recommendations
        try:
            recommendations = await self._generate_integrated_recommendations(insights)
            insights["integrated_recommendations"] = recommendations
        except Exception as e:
            logger.error(f"Error generating integrated recommendations: {e!s}")
            errors["integrated_recommendations"] = str(e)
        
        # Add errors to insights if any occurred
        if errors:
            insights["errors"] = errors
        
        return insights

    async def _generate_integrated_recommendations(self, insights: dict[str, Any]) -> list[dict[str, Any]]:
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
        if medication_predictions and "medication_predictions" in medication_predictions:
            for med_name, med_data in medication_predictions["medication_predictions"].items():
                if "efficacy" in med_data and med_data["efficacy"].get("score", 0) > 0.7:
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
        recommendations.sort(key=lambda x: priority_order.get(x.get("priority", "low"), 99))

        return recommendations

    async def _get_patient_data(self, patient_id: UUID) -> dict[str, Any]:
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
            return patient if isinstance(patient, dict) else {"id": str(patient_id), "data": patient}
        except Exception as e:
            logger.error(f"Error retrieving patient data: {e}")
            raise ValueError(f"Error retrieving patient data: {e!s}")

    async def get_patient_data(self, patient_id: UUID) -> dict[str, Any]:
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
                return {"id": str(patient_id)}
            return patient if isinstance(patient, dict) else {"id": str(patient_id), "data": patient}
        except Exception as e:
            logger.error(f"Error retrieving patient data: {e}")
            return {"id": patient_id, "error": str(e)}
