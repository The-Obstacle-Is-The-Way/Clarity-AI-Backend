"""
Stub mock implementation of DigitalTwinCoreService for non-enhanced integration tests.
"""
import uuid
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.domain.entities.digital_twin import DigitalTwinState
from app.domain.entities.digital_twin_entity import ClinicalInsight
from app.domain.services.digital_twin_core_service import DigitalTwinCoreService


class MockDigitalTwinCoreService(DigitalTwinCoreService):
    """Stub Digital Twin Core Service for integration tests."""

    def __init__(self, digital_twin_repository, patient_repository, *args, **kwargs):
        """Initialize stub service with repository and patient repository."""
        self._digital_twin_repository = digital_twin_repository
        self._patient_repository = patient_repository

    class State:
        def __init__(self, patient_id: UUID, data: dict[str, Any], version: int = 1):
            self.id = uuid.uuid4()
            self.patient_id = patient_id
            self.version = version
            self.data = data

    async def initialize_digital_twin(
        self, patient_id: UUID, include_genetic_data: bool, include_biomarkers: bool
    ) -> Any:
        """Stub initialization returns minimal state with brain_state and neurotransmitter_levels."""
        patient = await self._patient_repository.get_by_id(patient_id)
        if not patient:
            raise ValueError(f"Patient with ID {patient_id} not found")
        data = {"brain_state": {"neurotransmitter_levels": {}}, "treatment_history": []}
        state = self.State(patient_id, data, version=1)
        await self._digital_twin_repository.save(state)
        return state

    async def update_from_actigraphy(
        self, patient_id: UUID, actigraphy_data: dict, data_source: str
    ) -> DigitalTwinState:
        """
        Update Digital Twin with new actigraphy data via PAT.

        Args:
            patient_id: UUID of the patient
            actigraphy_data: Raw actigraphy data to process
            data_source: Source of the actigraphy data

        Returns:
            Updated Digital Twin state
        """
        # Get latest digital twin state
        current_state = await self._digital_twin_repository.get_latest_for_patient(patient_id)
        if not current_state:
            # Initialize new state if none exists
            current_state = await self.initialize_digital_twin(patient_id)

        # Extract time range from actigraphy data
        start_time = datetime.fromisoformat(
            actigraphy_data.get("start_time", datetime.now().isoformat())
        )
        end_time = datetime.fromisoformat(
            actigraphy_data.get("end_time", datetime.now().isoformat())
        )

        # Process actigraphy data with PAT
        pat_results = await self._pat_service.process_actigraphy_data(
            patient_id=patient_id,
            actigraphy_data=actigraphy_data,
            data_source=data_source,
            start_time=start_time,
            end_time=end_time,
        )

        # Import needed entities at the top of the method to ensure availability
        from app.domain.entities.digital_twin_enums import (
            ClinicalInsight,
            ClinicalSignificance,
        )

        # Extract insights from PAT results
        insights = []

        # Convert behavioral insights to clinical insights
        if "behavioral_insights" in pat_results:
            for insight in pat_results.get("behavioral_insights", []):
                clinical_insight = ClinicalInsight(
                    id=uuid4(),
                    title=insight.get("title", "Behavioral Insight"),
                    description=insight.get("description", ""),
                    source="PAT",
                    confidence=insight.get("confidence_score", 0.8),
                    timestamp=datetime.now(),
                    clinical_significance=self._map_clinical_relevance(
                        insight.get("clinical_relevance", "moderate")
                    ),
                    brain_regions=[],  # PAT insights might not have specific brain regions
                    neurotransmitters=[],  # PAT insights might not have specific neurotransmitters
                    supporting_evidence=[f"Analysis of {data_source} actigraphy data"],
                    recommended_actions=[insight.get("recommendation", "Review activity patterns")],
                )
                insights.append(clinical_insight)

        # Sleep insights
        if "sleep_analysis" in pat_results:
            sleep_data = pat_results["sleep_analysis"]

            if sleep_data.get("average_sleep_duration", 8) < 6.5:
                insights.append(
                    ClinicalInsight(
                        id=uuid4(),
                        title="Sleep Duration Concern",
                        description=f"Average sleep duration of {sleep_data.get('average_sleep_duration')} hours is below recommended levels",
                        source="PAT",
                        confidence=0.85,
                        timestamp=datetime.now(),
                        clinical_significance=self._map_clinical_relevance("moderate"),
                        brain_regions=[],
                        neurotransmitters=[],  # Adding the missing required parameter
                        supporting_evidence=["Actigraphy sleep analysis"],
                        recommended_actions=[
                            "Evaluate sleep hygiene",
                            "Consider sleep interventions",
                        ],
                    )
                )

            if sleep_data.get("sleep_efficiency", 0.9) < 0.75:
                insights.append(
                    ClinicalInsight(
                        id=uuid4(),
                        title="Poor Sleep Efficiency",
                        description=f"Sleep efficiency of {sleep_data.get('sleep_efficiency')} indicates fragmented sleep",
                        source="PAT",
                        confidence=0.8,
                        timestamp=datetime.now(),
                        clinical_significance=self._map_clinical_relevance("moderate"),
                        brain_regions=[],
                        neurotransmitters=[],  # Adding the missing required parameter
                        supporting_evidence=["Actigraphy sleep analysis"],
                        recommended_actions=[
                            "Evaluate for sleep disorders",
                            "Consider sleep continuity interventions",
                        ],
                    )
                )

        # Create new digital twin state
        # Use the with_updates method for safe state updates
        new_state = current_state.with_updates(
            clinical_insights=insights,  # Add new insights
            metadata_updates={
                "updated_by": "PAT",
                "update_source": f"{data_source}_actigraphy",
                "update_timestamp": datetime.now().isoformat(),
            },
        )

        # Create clinical insights from PAT results for sleep analysis
        additional_insights = []

        if "sleep_analysis" in pat_results:
            # Import needed for ClinicalInsight and ClinicalSignificance
            from app.domain.entities.digital_twin_enums import (
                ClinicalInsight,
                ClinicalSignificance,
            )

            sleep_insight = ClinicalInsight(
                id=uuid4(),
                title="Sleep Analysis",
                description=f"Sleep analysis results: {pat_results['sleep_analysis']}",
                source="PAT",
                confidence=0.85,
                timestamp=datetime.now(),
                clinical_significance=ClinicalSignificance.MODERATE,
                brain_regions=[],
                neurotransmitters=[],
                supporting_evidence=[f"Analysis of {data_source} actigraphy data"],
                recommended_actions=["Review sleep patterns"],
            )
            additional_insights.append(sleep_insight)

        if "activity_patterns" in pat_results:
            activity_insight = ClinicalInsight(
                id=uuid4(),
                title="Activity Pattern Analysis",
                description=f"Activity patterns: {pat_results['activity_patterns']}",
                source="PAT",
                confidence=0.85,
                timestamp=datetime.now(),
                clinical_significance=ClinicalSignificance.MODERATE,
                brain_regions=[],
                neurotransmitters=[],
                supporting_evidence=[f"Analysis of {data_source} actigraphy data"],
                recommended_actions=["Review activity patterns"],
            )
            additional_insights.append(activity_insight)

        # Combine all insights and update state
        all_insights = insights + additional_insights

        # Create final updated state with combined insights
        new_state = current_state.with_updates(
            clinical_insights=all_insights,
            metadata_updates={
                "updated_by": "PAT",
                "update_source": f"{data_source}_actigraphy",
                "update_timestamp": datetime.now().isoformat(),
            },
        )

        # Save and return the new state
        return await self._digital_twin_repository.save(new_state)

    async def update_from_clinical_notes(
        self,
        patient_id: UUID,
        note_text: str,
        note_type: str,
        clinician_id: UUID | None = None,
    ) -> DigitalTwinState:
        """
        Update Digital Twin with insights from clinical notes via MentalLLaMA.

        Args:
            patient_id: UUID of the patient
            note_text: Text of the clinical note
            note_type: Type of clinical note
            clinician_id: Optional ID of the clinician who wrote the note

        Returns:
            Updated Digital Twin state
        """
        # Get latest digital twin state
        current_state = await self._digital_twin_repository.get_latest_for_patient(patient_id)
        if not current_state:
            # Initialize new state if none exists
            current_state = await self.initialize_digital_twin(patient_id)

        # Process clinical notes with MentalLLaMA
        context = {
            "note_type": note_type,
            "clinician_id": str(clinician_id) if clinician_id else None,
        }

        llama_insights = await self._mentalllama_service.analyze_clinical_notes(
            patient_id=patient_id, note_text=note_text, context=context
        )

        # Create new digital twin state
        new_state = DigitalTwinState(
            id=uuid4(),
            patient_id=patient_id,
            timestamp=datetime.now(),
            version=current_state.version + 1,
            clinical_insights=current_state.clinical_insights + llama_insights,
            brain_state=current_state.brain_state.copy(),
            clinical_metrics=current_state.clinical_metrics.copy(),
            metadata={
                **current_state.metadata,
                "updated_by": "MentalLLaMA",
                "update_source": f"clinical_note_{note_type}",
                "update_timestamp": datetime.now().isoformat(),
            },
        )

        # Update clinical metrics based on the insights
        # This would be more comprehensive in a real implementation
        for insight in llama_insights:
            for region in insight.brain_regions:
                region_str = region.name.lower()
                if region_str not in new_state.brain_state:
                    new_state.brain_state[region_str] = 0.5

                # Adjust activation based on confidence and significance
                significance_factor = self._get_significance_factor(insight.clinical_significance)
                adjustment = 0.1 * significance_factor * insight.confidence
                new_state.brain_state[region_str] = max(
                    0.1, min(0.9, new_state.brain_state[region_str] + adjustment)
                )

        # Save and return the new state
        return await self._digital_twin_repository.save(new_state)

    async def generate_treatment_recommendations(
        self,
        patient_id: UUID,
        digital_twin_state_id: UUID | None = None,
        include_rationale: bool = True,
    ) -> list[dict]:
        """
        Generate treatment recommendations using XGBoost and MentalLLaMA.

        Args:
            patient_id: UUID of the patient
            digital_twin_state_id: Optional specific state ID to use
            include_rationale: Whether to include rationale for recommendations

        Returns:
            List of treatment recommendations with metadata
        """
        # Get patient data
        patient = await self._patient_repository.get_by_id(patient_id)
        if not patient:
            raise ValueError(f"Patient with ID {patient_id} not found")

        # Get digital twin state
        if digital_twin_state_id:
            twin_state = await self._digital_twin_repository.get_by_id(digital_twin_state_id)
            if not twin_state or twin_state.patient_id != patient_id:
                raise ValueError(
                    f"Digital Twin state with ID {digital_twin_state_id} not found for patient {patient_id}"
                )
        else:
            twin_state = await self._digital_twin_repository.get_latest_for_patient(patient_id)
            if not twin_state:
                raise ValueError(f"No Digital Twin state found for patient {patient_id}")

        # Extract relevant patient data for the ML services
        diagnosis_codes = [diagnosis.code for diagnosis in patient.diagnoses if diagnosis.is_active]
        current_medications = [med.name for med in patient.medications if med.is_active]

        # Create clinical history summary
        clinical_history = f"Patient {patient.full_name}, {patient.age} years old, with diagnoses: {', '.join(diagnosis_codes)}"

        # Generate recommendations from MentalLLaMA
        llama_recommendations = await self._mentalllama_service.generate_treatment_recommendations(
            patient_id=patient_id,
            diagnosis_codes=diagnosis_codes,
            current_medications=current_medications,
            clinical_history=clinical_history,
            digital_twin_state_id=twin_state.id,
        )

        # Create treatment options to evaluate with XGBoost
        treatment_options = []
        for rec in llama_recommendations:
            if rec["recommendation_type"] == "medication":
                for option in rec.get("options", [rec["recommendation"]]):
                    treatment_options.append(
                        {
                            "type": "medication",
                            "name": option,
                            "dosage": "standard",
                            "frequency": "daily",
                        }
                    )
            elif rec["recommendation_type"] == "therapy":
                treatment_options.append(
                    {
                        "type": "therapy",
                        "name": rec["recommendation"],
                        "frequency": rec.get("frequency", "weekly"),
                        "duration": rec.get("duration", "12 weeks"),
                    }
                )

        # Add a conservative option (always ensure at least one option)
        if not treatment_options:
            treatment_options.append(
                {
                    "type": "monitoring",
                    "name": "Continued monitoring",
                    "frequency": "monthly",
                }
            )

        # Get predictions from XGBoost
        xgboost_predictions = await self._xgboost_service.predict_treatment_response(
            patient_id=patient_id,
            digital_twin_state_id=twin_state.id,
            treatment_options=treatment_options,
            time_horizon="medium_term",
        )

        # Combine the recommendations with their predictions
        combined_recommendations = []

        for llama_rec in llama_recommendations:
            # Find matching XGBoost predictions
            matching_predictions = []

            if llama_rec["recommendation_type"] == "medication":
                for option in llama_rec.get("options", [llama_rec["recommendation"]]):
                    for pred in xgboost_predictions.get("treatment_responses", []):
                        if option.lower() in pred.get("treatment_name", "").lower():
                            matching_predictions.append(pred)
            else:
                for pred in xgboost_predictions.get("treatment_responses", []):
                    if (
                        llama_rec["recommendation"].lower()
                        in pred.get("treatment_name", "").lower()
                    ):
                        matching_predictions.append(pred)

            # Create combined recommendation
            recommendation = {
                "type": llama_rec["recommendation_type"],
                "name": llama_rec["recommendation"],
                "confidence": llama_rec.get("confidence", 0.8),
                "evidence_level": llama_rec.get("evidence_level", "C"),
                "predicted_efficacy": None,
                "predicted_side_effects": None,
                "predicted_adherence": None,
                "time_to_response": None,
            }

            # Add options if medication
            if llama_rec["recommendation_type"] == "medication" and "options" in llama_rec:
                recommendation["options"] = llama_rec["options"]

            # Add frequency and duration if therapy
            if llama_rec["recommendation_type"] == "therapy":
                recommendation["frequency"] = llama_rec.get("frequency", "weekly")
                recommendation["duration"] = llama_rec.get("duration", "12 weeks")

            # Add prediction data if available
            if matching_predictions:
                # Use the highest efficacy prediction
                best_pred = max(
                    matching_predictions,
                    key=lambda p: p.get("efficacy_prediction", {}).get("value", 0),
                )

                recommendation["predicted_efficacy"] = best_pred.get("efficacy_prediction", {}).get(
                    "value"
                )
                recommendation["predicted_side_effects"] = best_pred.get(
                    "side_effect_prediction", {}
                ).get("value")
                recommendation["predicted_adherence"] = best_pred.get(
                    "adherence_prediction", {}
                ).get("value")
                recommendation["time_to_response"] = best_pred.get("time_to_response", {}).get(
                    "value"
                )

            # Add rationale if requested
            if include_rationale:
                recommendation["rationale"] = llama_rec.get("rationale", "Clinical best practice")

            combined_recommendations.append(recommendation)

        return combined_recommendations

    async def get_visualization_data(
        self,
        patient_id: UUID,
        digital_twin_state_id: UUID | None = None,
        visualization_type: str = "brain_model",
    ) -> dict:
        """
        Get data for 3D visualization of the Digital Twin.

        Args:
            patient_id: UUID of the patient
            digital_twin_state_id: Optional specific state ID to use
            visualization_type: Type of visualization to generate

        Returns:
            Visualization data for the specified type
        """
        # Get digital twin state
        if digital_twin_state_id:
            twin_state = await self._digital_twin_repository.get_by_id(digital_twin_state_id)
            if not twin_state or twin_state.patient_id != patient_id:
                raise ValueError(
                    f"Digital Twin state with ID {digital_twin_state_id} not found for patient {patient_id}"
                )
        else:
            twin_state = await self._digital_twin_repository.get_latest_for_patient(patient_id)
            if not twin_state:
                raise ValueError(f"No Digital Twin state found for patient {patient_id}")

        # Generate visualization data based on type
        if visualization_type == "brain_model":
            # Get brain region activations from XGBoost
            activations = await self._xgboost_service.generate_brain_region_activations(
                patient_id=patient_id, digital_twin_state_id=twin_state.id
            )

            # Collect regions of interest from clinical insights
            regions_of_interest = set()
            for insight in twin_state.clinical_insights:
                for region in insight.brain_regions:
                    regions_of_interest.add(region)

            # Create visualization data
            visualization_data = {
                "patient_id": str(patient_id),
                "digital_twin_state_id": str(twin_state.id),
                "timestamp": datetime.now().isoformat(),
                "visualization_type": "brain_model_3d",
                "brain_regions": [],
                "highlighted_regions": [region.name for region in regions_of_interest],
                "connectivity": [],  # Would contain connectivity data in a real implementation
            }

            # Format brain region data
            for region, activation in activations.items():
                region_data = {
                    "id": region.name,
                    "name": region.name.replace("_", " ").title(),
                    "activation": activation,
                    "highlighted": region in regions_of_interest,
                    "coordinates": self._get_region_coordinates(region),  # Mock coordinates
                }
                visualization_data["brain_regions"].append(region_data)

            # Add some mock connectivity data between regions
            # This would be much more sophisticated in a real implementation
            for i, region1 in enumerate(activations.keys()):
                for j, region2 in enumerate(activations.keys()):
                    if i < j and (region1 in regions_of_interest or region2 in regions_of_interest):
                        # Only add connections for highlighted regions
                        if random.random() < 0.3:  # Only add some connections to avoid clutter
                            connectivity = {
                                "source": region1.name,
                                "target": region2.name,
                                "strength": round(random.uniform(0.3, 0.9), 2),
                            }
                            visualization_data["connectivity"].append(connectivity)

            return visualization_data

        elif visualization_type == "time_series":
            # Get patient history
            history = await self._digital_twin_repository.get_history_for_patient(
                patient_id=patient_id, limit=10  # Last 10 states
            )

            # Create time series data
            time_series_data = {
                "patient_id": str(patient_id),
                "current_state_id": str(twin_state.id),
                "timestamp": datetime.now().isoformat(),
                "visualization_type": "time_series",
                "metrics": [],
                "insights_timeline": [],
            }

            # Extract metrics over time
            if history:
                # Sort by timestamp (oldest first)
                history.sort(key=lambda state: state.timestamp)

                # Extract clinical metrics
                metrics = {}
                for state in history:
                    for metric_key, metric_value in state.clinical_metrics.items():
                        if metric_key not in metrics:
                            metrics[metric_key] = {"name": metric_key, "values": []}

                        metrics[metric_key]["values"].append(
                            {
                                "timestamp": state.timestamp.isoformat(),
                                "value": metric_value
                                if not isinstance(metric_value, dict)
                                else None,
                                "data": metric_value if isinstance(metric_value, dict) else None,
                            }
                        )

                time_series_data["metrics"] = list(metrics.values())

                # Extract insights timeline
                for state in history:
                    for insight in state.clinical_insights:
                        time_series_data["insights_timeline"].append(
                            {
                                "id": str(insight.id),
                                "title": insight.title,
                                "timestamp": insight.timestamp.isoformat(),
                                "significance": insight.clinical_significance.name,
                                "source": insight.source,
                            }
                        )

            return time_series_data

        else:
            raise ValueError(f"Unsupported visualization type: {visualization_type}")

    async def merge_insights(
        self, patient_id: UUID, insights: list[ClinicalInsight], source: str
    ) -> DigitalTwinState:
        """
        Merge new insights into the Digital Twin state.

        Args:
            patient_id: UUID of the patient
            insights: List of new clinical insights
            source: Source of the insights

        Returns:
            Updated Digital Twin state
        """
        # Get latest digital twin state
        current_state = await self._digital_twin_repository.get_latest_for_patient(patient_id)
        if not current_state:
            # Initialize new state if none exists
            current_state = await self.initialize_digital_twin(patient_id)

        # Create new digital twin state with merged insights
        new_state = DigitalTwinState(
            id=uuid4(),
            patient_id=patient_id,
            timestamp=datetime.now(),
            version=current_state.version + 1,
            clinical_insights=current_state.clinical_insights + insights,
            brain_state=current_state.brain_state.copy(),
            clinical_metrics=current_state.clinical_metrics.copy(),
            metadata={
                **current_state.metadata,
                "updated_by": "DigitalTwinCoreService",
                "update_source": f"merge_insights_{source}",
                "update_timestamp": datetime.now().isoformat(),
            },
        )

        # Update brain state based on new insights
        for insight in insights:
            for region in insight.brain_regions:
                region_str = region.name.lower()
                if region_str not in new_state.brain_state:
                    new_state.brain_state[region_str] = 0.5

                # Adjust activation based on confidence and significance
                significance_factor = self._get_significance_factor(insight.clinical_significance)
                adjustment = 0.1 * significance_factor * insight.confidence
                new_state.brain_state[region_str] = max(
                    0.1, min(0.9, new_state.brain_state[region_str] + adjustment)
                )

        # Save and return the new state
        return await self._digital_twin_repository.save(new_state)

    async def compare_states(self, patient_id: UUID, state_id_1: UUID, state_id_2: UUID) -> dict:
        """
        Compare two Digital Twin states to identify changes.

        Args:
            patient_id: UUID of the patient
            state_id_1: UUID of the first state to compare
            state_id_2: UUID of the second state to compare

        Returns:
            Dictionary with comparison results
        """
        # Get the two states
        state_1 = await self._digital_twin_repository.get_by_id(state_id_1)
        state_2 = await self._digital_twin_repository.get_by_id(state_id_2)

        if not state_1 or not state_2:
            raise ValueError("One or both states not found")

        if state_1.patient_id != patient_id or state_2.patient_id != patient_id:
            raise ValueError("States do not belong to the specified patient")

        # Ensure state_1 is the earlier state
        if state_1.timestamp > state_2.timestamp:
            state_1, state_2 = state_2, state_1

        # Compare the states
        comparison = {
            "patient_id": str(patient_id),
            "comparison_timestamp": datetime.now().isoformat(),
            "state_1": {
                "id": str(state_1.id),
                "timestamp": state_1.timestamp.isoformat(),
                "version": state_1.version,
            },
            "state_2": {
                "id": str(state_2.id),
                "timestamp": state_2.timestamp.isoformat(),
                "version": state_2.version,
            },
            "time_between_states": (state_2.timestamp - state_1.timestamp).total_seconds(),
            "brain_state_changes": [],
            "new_insights": [],
            "clinical_metrics_changes": [],
        }

        # Compare brain states
        for region, activation_2 in state_2.brain_state.items():
            activation_1 = state_1.brain_state.get(region, 0.0)
            if abs(activation_1 - activation_2) >= 0.1:  # Only show significant changes
                comparison["brain_state_changes"].append(
                    {
                        "region": region,
                        "before": activation_1,
                        "after": activation_2,
                        "change": activation_2 - activation_1,
                    }
                )

        # Find new insights
        state_1_insight_ids = {str(insight.id) for insight in state_1.clinical_insights}
        for insight in state_2.clinical_insights:
            if str(insight.id) not in state_1_insight_ids:
                comparison["new_insights"].append(
                    {
                        "id": str(insight.id),
                        "title": insight.title,
                        "source": insight.source,
                        "timestamp": insight.timestamp.isoformat(),
                        "clinical_significance": insight.clinical_significance.name,
                    }
                )

        # Compare clinical metrics
        for metric, value_2 in state_2.clinical_metrics.items():
            if metric in state_1.clinical_metrics:
                value_1 = state_1.clinical_metrics[metric]

                # Skip if both are complex objects (would need specific comparison logic)
                if isinstance(value_1, dict) and isinstance(value_2, dict):
                    # For dictionaries, we'd need specific comparison logic based on the metric
                    # This is a simplified example
                    if (
                        metric == "sleep"
                        and "average_sleep_duration" in value_1
                        and "average_sleep_duration" in value_2
                    ):
                        duration_1 = value_1["average_sleep_duration"]
                        duration_2 = value_2["average_sleep_duration"]

                        comparison["clinical_metrics_changes"].append(
                            {
                                "metric": f"{metric}.average_sleep_duration",
                                "before": duration_1,
                                "after": duration_2,
                                "change": duration_2 - duration_1,
                                "percent_change": round(
                                    ((duration_2 - duration_1) / duration_1) * 100, 1
                                )
                                if duration_1
                                else None,
                            }
                        )
                elif not isinstance(value_1, (dict, list)) and not isinstance(
                    value_2, (dict, list)
                ):
                    # For simple values, direct comparison
                    if value_1 != value_2:
                        comparison["clinical_metrics_changes"].append(
                            {
                                "metric": metric,
                                "before": value_1,
                                "after": value_2,
                                "change": value_2 - value_1
                                if isinstance(value_1, (int, float))
                                and isinstance(value_2, (int, float))
                                else None,
                                "percent_change": round(((value_2 - value_1) / value_1) * 100, 1)
                                if isinstance(value_1, (int, float))
                                and isinstance(value_2, (int, float))
                                and value_1
                                else None,
                            }
                        )
            else:
                # New metric in state_2
                comparison["clinical_metrics_changes"].append(
                    {
                        "metric": metric,
                        "before": None,
                        "after": value_2
                        if not isinstance(value_2, (dict, list))
                        else "[complex value]",
                        "change": "new_metric",
                    }
                )

        return comparison

    async def generate_clinical_summary(
        self,
        patient_id: UUID,
        time_range: tuple[str, str] | None = None,
        include_treatment_history: bool = True,
        include_predictions: bool = True,
    ) -> dict:
        """
        Generate comprehensive clinical summary from Digital Twin.

        Args:
            patient_id: UUID of the patient
            time_range: Optional time range for the summary
            include_treatment_history: Whether to include treatment history
            include_predictions: Whether to include predictions

        Returns:
            Dictionary with clinical summary
        """
        # Get patient data
        patient = await self._patient_repository.get_by_id(patient_id)
        if not patient:
            raise ValueError(f"Patient with ID {patient_id} not found")

        # Get latest digital twin state
        latest_state = await self._digital_twin_repository.get_latest_for_patient(patient_id)
        if not latest_state:
            raise ValueError(f"No Digital Twin state found for patient {patient_id}")

        # Parse time range if provided
        start_date = None
        end_date = None
        if time_range:
            start_str, end_str = time_range
            try:
                start_date = datetime.fromisoformat(start_str)
                end_date = datetime.fromisoformat(end_str)
            except ValueError:
                # Invalid date format, ignore time range
                pass

        # Get history for the specified time range
        history = await self._digital_twin_repository.get_history_for_patient(
            patient_id=patient_id,
            start_date=start_date,
            end_date=end_date,
            limit=100,  # Reasonable limit for history
        )

        # Use MentalLLaMA to generate a patient history summary
        focus_areas = ["medication", "therapy", "symptoms"]
        if time_range and start_date and end_date:
            time_range_str = f"{start_date.date().isoformat()} to {end_date.date().isoformat()}"
        else:
            time_range_str = "all"

        llama_summary = await self._mentalllama_service.summarize_patient_history(
            patient_id=patient_id, time_range=time_range_str, focus_areas=focus_areas
        )

        # Collect significant insights
        significant_insights = []
        if history:
            for state in history:
                for insight in state.clinical_insights:
                    if insight.clinical_significance.name in [
                        "MODERATE",
                        "SIGNIFICANT",
                        "CRITICAL",
                    ]:
                        significant_insights.append(
                            {
                                "id": str(insight.id),
                                "title": insight.title,
                                "description": insight.description,
                                "timestamp": insight.timestamp.isoformat(),
                                "source": insight.source,
                                "significance": insight.clinical_significance.name,
                                "confidence": insight.confidence,
                            }
                        )

        # Generate predictions if requested
        treatment_recommendations = []
        risk_predictions = {}
        if include_predictions:
            # Generate treatment recommendations
            treatment_recommendations = await self.generate_treatment_recommendations(
                patient_id=patient_id,
                digital_twin_state_id=latest_state.id,
                include_rationale=True,
            )

            # Generate risk analysis
            clinical_data = {
                "age": patient.age,
                "diagnoses": [
                    {"code": d.code, "name": d.name} for d in patient.diagnoses if d.is_active
                ],
                "medications": [
                    {"name": m.name, "dosage": m.dosage} for m in patient.medications if m.is_active
                ],
            }

            risk_analysis = await self._mentalllama_service.analyze_risk_factors(
                patient_id=patient_id,
                clinical_data=clinical_data,
                digital_twin_state_id=latest_state.id,
            )

            risk_predictions = risk_analysis.get("risk_factors", {})

        # Compile the clinical summary
        summary = {
            "patient": {
                "id": str(patient_id),
                "name": patient.full_name,
                "age": patient.age,
                "gender": patient.gender.name,
                "diagnoses": [
                    {
                        "code": d.code,
                        "name": d.name,
                        "status": "active" if d.is_active else "inactive",
                    }
                    for d in patient.diagnoses
                ],
                "medications": [
                    {
                        "name": m.name,
                        "dosage": m.dosage,
                        "status": "active" if m.is_active else "inactive",
                    }
                    for m in patient.medications
                ],
            },
            "summary_text": llama_summary,
            "digital_twin_state": {
                "id": str(latest_state.id),
                "version": latest_state.version,
                "timestamp": latest_state.timestamp.isoformat(),
            },
            "significant_insights": significant_insights,
            "treatment_recommendations": treatment_recommendations if include_predictions else [],
            "risk_assessment": risk_predictions if include_predictions else {},
            "generated_timestamp": datetime.now().isoformat(),
        }

        # Add treatment history if requested
        if include_treatment_history:
            treatment_history = []

            for med in patient.medications:
                treatment_history.append(
                    {
                        "type": "medication",
                        "name": med.name,
                        "dosage": med.dosage,
                        "start_date": med.start_date.isoformat() if med.start_date else None,
                        "end_date": med.end_date.isoformat() if med.end_date else None,
                        "status": "active" if med.is_active else "inactive",
                    }
                )

            # In a real implementation, we would extract therapy history from the patient record
            # This is a placeholder
            treatment_history.append(
                {
                    "type": "therapy",
                    "name": "Cognitive Behavioral Therapy",
                    "start_date": (datetime.now() - timedelta(days=60)).date().isoformat(),
                    "frequency": "weekly",
                    "status": "active",
                }
            )

            summary["treatment_history"] = treatment_history

        return summary

    async def process_treatment_event(self, patient_id: UUID, event_data: dict[str, Any]) -> Any:
        """Stub treatment event processing: appends to treatment_history."""
        prev = await self._digital_twin_repository.get_latest_state(patient_id)
        version = (getattr(prev, "version", 1) or 1) + 1
        data = dict(prev.data)
        history = list(data.get("treatment_history", []))
        history.append(event_data)
        data["treatment_history"] = history
        state = self.State(patient_id, data, version)
        await self._digital_twin_repository.save(state)
        return state

    async def generate_treatment_recommendations(
        self,
        patient_id: UUID,
        consider_current_medications: bool,
        include_therapy_options: bool,
    ) -> list[dict[str, Any]]:
        """Stub recommendations with at least one medication and one therapy."""
        recs = []
        recs.append({"type": "medication", "name": "Sertraline", "rationale": "Standard SSRI"})
        if include_therapy_options:
            recs.append(
                {
                    "type": "therapy",
                    "name": "Cognitive Behavioral Therapy",
                    "rationale": "Recommended therapy",
                }
            )
        return recs

    async def get_visualization_data(
        self, patient_id: UUID, visualization_type: str
    ) -> dict[str, Any]:
        """Stub visualization: returns brain_model_3d and sample brain_regions."""
        return {
            "visualization_type": "brain_model_3d",
            "brain_regions": [{"id": "AMYGDALA", "activation": 0.5}],
        }

    async def compare_states(
        self, patient_id: UUID, state_id_1: UUID, state_id_2: UUID
    ) -> dict[str, Any]:
        """Stub state comparison with minimal brain_state_changes and new_insights."""
        return {
            "state_1": {"id": str(state_id_1)},
            "state_2": {"id": str(state_id_2)},
            "brain_state_changes": [
                {"region": "amygdala", "before": 0.1, "after": 0.3, "change": 0.2}
            ],
            "new_insights": [{"id": "ins1", "title": "New insight"}],
        }

    async def generate_clinical_summary(
        self,
        patient_id: UUID,
        include_treatment_history: bool,
        include_predictions: bool,
    ) -> dict[str, Any]:
        """Stub clinical summary with patient info, insights, and history."""
        patient = await self._patient_repository.get_by_id(patient_id)
        name = (
            getattr(patient, "full_name", None)
            or f"{getattr(patient, 'first_name', '')} {getattr(patient, 'last_name', '')}".strip()
        )
        return {
            "patient": {"id": str(patient_id), "name": name},
            "digital_twin_state": {"id": str(uuid.uuid4())},
            "significant_insights": [{"id": "ins1", "title": "Insight"}],
            "treatment_recommendations": [],
            "treatment_history": [{"type": "medication", "name": "Sertraline"}],
        }

        # This would be replaced with actual neuroanatomical coordinates
        # in a real implementation
        return {
            "x": random.uniform(-0.8, 0.8),
            "y": random.uniform(-0.8, 0.8),
            "z": random.uniform(-0.8, 0.8),
        }
