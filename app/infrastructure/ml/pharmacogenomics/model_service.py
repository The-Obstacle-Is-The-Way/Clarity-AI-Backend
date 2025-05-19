"""
Pharmacogenomics Model Service for the NOVAMIND Digital Twin.

This module implements the service layer for the Pharmacogenomics microservice,
providing medication response prediction and personalized treatment recommendations
based on genetic markers, following Clean Architecture principles and ensuring
HIPAA compliance.
"""

import logging
import os
from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.exceptions.base_exceptions import ModelExecutionError
from app.domain.exceptions import ValidationError
from app.domain.utils.datetime_utils import UTC
from app.infrastructure.ml.pharmacogenomics.treatment_model import PharmacogenomicsModel


class PharmacogenomicsService:
    """
    Service for pharmacogenomics-based medication response prediction.

    This service implements the core functionality of the Pharmacogenomics
    microservice, providing a clean interface for the domain layer to interact
    with the ML models while maintaining separation of concerns and ensuring
    HIPAA compliance.
    """

    def __init__(
        self,
        model_dir: str,
        model_path: str | None = None,
        gene_markers: list[str] | None = None,
        medications: list[str] | None = None,
    ):
        """
        Initialize the pharmacogenomics service.

        Args:
            model_dir: Directory for model storage
            model_path: Path to pretrained model
            gene_markers: List of genetic markers used by the model
            medications: List of medications supported by the model
        """
        self.model_dir = model_dir

        # Create model directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)

        # Initialize model
        self.model = PharmacogenomicsModel(
            model_path=model_path, gene_markers=gene_markers, medications=medications
        )

        # Medication categories for organization
        self.medication_categories = {
            "ssri": [
                "fluoxetine",
                "sertraline",
                "escitalopram",
                "paroxetine",
                "citalopram",
            ],
            "snri": ["venlafaxine", "duloxetine", "desvenlafaxine"],
            "ndri": ["bupropion"],
            "atypical_antidepressant": ["mirtazapine", "trazodone"],
            "atypical_antipsychotic": [
                "quetiapine",
                "aripiprazole",
                "risperidone",
                "olanzapine",
                "lurasidone",
            ],
            "mood_stabilizer": ["lamotrigine", "valproate", "lithium", "carbamazepine"],
            "anxiolytic": ["clonazepam", "lorazepam", "alprazolam", "buspirone"],
            "stimulant": ["methylphenidate", "amphetamine", "lisdexamfetamine"],
        }

        logging.info("Pharmacogenomics Service initialized")

    async def predict_medication_responses(
        self,
        patient_id: UUID,
        patient_data: dict[str, Any],
        medications: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Predict patient responses to psychiatric medications.

        Args:
            patient_id: UUID of the patient
            patient_data: Patient data including genetic markers
            medications: Optional list of medications to predict (defaults to all)

        Returns:
            Dictionary containing prediction results
        """
        try:
            # Validate patient data
            if not patient_data.get("genetic_markers"):
                raise ValidationError("Patient data must include genetic markers")

            # Get medication predictions
            predictions = await self.model.predict_medication_response(
                patient_id=patient_id,
                patient_data=patient_data,
                medications=medications,
            )

            # Organize predictions by medication category
            categorized_predictions = {}

            for category, meds in self.medication_categories.items():
                category_predictions = {}

                for med in meds:
                    if med in predictions.get("medication_predictions", {}):
                        category_predictions[med] = predictions["medication_predictions"][med]

                if category_predictions:
                    categorized_predictions[category] = category_predictions

            # Add categorized predictions to results
            predictions["categorized_predictions"] = categorized_predictions

            # Generate summary insights
            predictions["insights"] = await self._generate_medication_insights(
                predictions["medication_predictions"]
            )

            return predictions

        except Exception as e:
            logging.error(f"Error predicting medication responses: {e!s}")
            raise ModelExecutionError(f"Failed to predict medication responses: {e!s}")

    async def _generate_medication_insights(
        self, medication_predictions: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Generate insights from medication predictions.

        Args:
            medication_predictions: Dictionary of medication predictions

        Returns:
            List of insights
        """
        insights = []

        # Find top medications by category
        top_by_category = {}

        for category, meds in self.medication_categories.items():
            category_meds = [med for med in meds if med in medication_predictions]

            if category_meds:
                # Sort by effectiveness score
                sorted_meds = sorted(
                    category_meds,
                    key=lambda med: medication_predictions[med]["effectiveness_score"],
                    reverse=True,
                )

                top_by_category[category] = {
                    "top_medication": sorted_meds[0],
                    "score": medication_predictions[sorted_meds[0]]["effectiveness_score"],
                    "category": category,
                }

        # Generate insights for top medications in each category
        for category, data in top_by_category.items():
            medication = data["top_medication"]
            score = data["score"]

            if score >= 0.7:
                strength = "strong"
            elif score >= 0.5:
                strength = "moderate"
            else:
                strength = "potential"

            category_name = category.replace("_", " ").title()

            insight = {
                "medication": medication,
                "category": category,
                "effectiveness_score": score,
                "insight_text": f"{medication.title()} shows {strength} predicted effectiveness as a {category_name}",
                "importance": score,
            }

            insights.append(insight)

        # Sort insights by importance
        insights.sort(key=lambda x: x["importance"], reverse=True)

        return insights

    async def analyze_gene_medication_interactions(
        self, patient_id: UUID, patient_data: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Analyze interactions between patient's genetic markers and medications.

        Args:
            patient_id: UUID of the patient
            patient_data: Patient data including genetic markers

        Returns:
            Dictionary containing interaction analysis
        """
        try:
            # Validate patient data
            if not patient_data.get("genetic_markers"):
                raise ValidationError("Patient data must include genetic markers")

            # Get genetic markers
            genetic_markers = patient_data.get("genetic_markers", {})

            # Analyze gene-medication interactions
            interactions = await self.model.analyze_gene_medication_interactions(genetic_markers)

            # Group interactions by medication
            interactions_by_medication = {}

            for interaction in interactions.get("gene_medication_interactions", []):
                medication = interaction.get("medication")

                if medication:
                    if medication not in interactions_by_medication:
                        interactions_by_medication[medication] = []

                    interactions_by_medication[medication].append(interaction)

            # Add to results
            interactions["patient_id"] = str(patient_id)
            interactions["interactions_by_medication"] = interactions_by_medication

            # Generate summary recommendations
            interactions["recommendations"] = await self._generate_interaction_recommendations(
                interactions["gene_medication_interactions"]
            )

            return interactions

        except Exception as e:
            logging.error(f"Error analyzing gene-medication interactions: {e!s}")
            raise ModelExecutionError(f"Failed to analyze gene-medication interactions: {e!s}")

    async def _generate_interaction_recommendations(
        self, interactions: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Generate recommendations based on gene-medication interactions.

        Args:
            interactions: List of gene-medication interactions

        Returns:
            List of recommendations
        """
        recommendations = []

        # Group interactions by gene
        interactions_by_gene = {}

        for interaction in interactions:
            gene = interaction.get("gene")

            if gene:
                if gene not in interactions_by_gene:
                    interactions_by_gene[gene] = []

                interactions_by_gene[gene].append(interaction)

        # Generate recommendations for each gene
        for gene, gene_interactions in interactions_by_gene.items():
            # Group by variant
            interactions_by_variant = {}

            for interaction in gene_interactions:
                variant = interaction.get("variant")

                if variant:
                    if variant not in interactions_by_variant:
                        interactions_by_variant[variant] = []

                    interactions_by_variant[variant].append(interaction)

            # Generate recommendation for each variant
            for variant, variant_interactions in interactions_by_variant.items():
                medications = [
                    interaction.get("medication") for interaction in variant_interactions
                ]
                medications = [med for med in medications if med]

                if medications:
                    recommendation_text = f"Due to {gene} {variant} status, consider dose adjustments for: {', '.join(medications)}"

                    recommendations.append(
                        {
                            "gene": gene,
                            "variant": variant,
                            "medications": medications,
                            "recommendation_text": recommendation_text,
                            "importance": len(medications),
                        }
                    )

        # Sort recommendations by importance
        recommendations.sort(key=lambda x: x["importance"], reverse=True)

        return recommendations

    async def predict_side_effects(
        self, patient_id: UUID, patient_data: dict[str, Any], medications: list[str]
    ) -> dict[str, Any]:
        """
        Predict potential side effects for specified medications.

        Args:
            patient_id: UUID of the patient
            patient_data: Patient data including genetic markers
            medications: List of medications to predict side effects for

        Returns:
            Dictionary containing side effect predictions
        """
        try:
            # Validate patient data
            if not patient_data.get("genetic_markers"):
                raise ValidationError("Patient data must include genetic markers")

            if not medications:
                raise ValidationError("No medications specified for side effect prediction")

            # Get side effect predictions for each medication
            side_effect_predictions = {}

            for medication in medications:
                prediction = await self.model.predict_side_effects(
                    patient_id=patient_id,
                    patient_data=patient_data,
                    medication=medication,
                )

                side_effect_predictions[medication] = prediction

            # Identify common side effects across medications
            common_effects = await self._identify_common_side_effects(side_effect_predictions)

            # Generate summary insights
            insights = await self._generate_side_effect_insights(
                side_effect_predictions, common_effects
            )

            return {
                "patient_id": str(patient_id),
                "side_effect_predictions": side_effect_predictions,
                "common_effects": common_effects,
                "insights": insights,
                "prediction_generated_at": datetime.now(UTC).isoformat(),
            }

        except Exception as e:
            logging.error(f"Error predicting side effects: {e!s}")
            raise ModelExecutionError(f"Failed to predict side effects: {e!s}")

    async def _identify_common_side_effects(
        self, side_effect_predictions: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Identify common side effects across multiple medications.

        Args:
            side_effect_predictions: Dictionary of side effect predictions by medication

        Returns:
            Dictionary containing common side effects
        """
        # Extract all side effects
        all_effects = {}

        for medication, prediction in side_effect_predictions.items():
            for effect in prediction.get("side_effects", []):
                effect_name = effect.get("effect")

                if effect_name:
                    if effect_name not in all_effects:
                        all_effects[effect_name] = {
                            "medications": [],
                            "probabilities": [],
                            "genetic_factors": set(),
                        }

                    all_effects[effect_name]["medications"].append(medication)
                    all_effects[effect_name]["probabilities"].append(effect.get("probability", 0))

                    for gene in effect.get("genetic_factors", []):
                        all_effects[effect_name]["genetic_factors"].add(gene)

        # Identify common effects (present in multiple medications)
        common_effects = {}

        for effect, data in all_effects.items():
            if len(data["medications"]) > 1:
                common_effects[effect] = {
                    "medications": data["medications"],
                    "average_probability": sum(data["probabilities"]) / len(data["probabilities"]),
                    "max_probability": max(data["probabilities"]),
                    "genetic_factors": list(data["genetic_factors"]),
                    "count": len(data["medications"]),
                }

        return common_effects

    async def _generate_side_effect_insights(
        self,
        side_effect_predictions: dict[str, dict[str, Any]],
        common_effects: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Generate insights from side effect predictions.

        Args:
            side_effect_predictions: Dictionary of side effect predictions by medication
            common_effects: Dictionary of common side effects

        Returns:
            List of insights
        """
        insights = []

        # Generate insights for common side effects
        for effect, data in common_effects.items():
            if data["average_probability"] >= 0.3:
                severity = "high"
            elif data["average_probability"] >= 0.2:
                severity = "moderate"
            else:
                severity = "low"

            medications = data["medications"]

            if len(medications) > 2:
                med_text = f"{', '.join(medications[:-1])} and {medications[-1]}"
            elif len(medications) == 2:
                med_text = f"{medications[0]} and {medications[1]}"
            else:
                med_text = medications[0]

            insight_text = f"{effect.replace('_', ' ').title()} is a {severity} risk side effect common to {med_text}"

            if data["genetic_factors"]:
                genes = data["genetic_factors"]
                gene_text = (
                    f"{', '.join(genes[:-1])} and {genes[-1]}" if len(genes) > 1 else genes[0]
                )
                insight_text += f", influenced by {gene_text} genetic factors"

            insights.append(
                {
                    "effect": effect,
                    "medications": medications,
                    "probability": data["average_probability"],
                    "genetic_factors": data["genetic_factors"],
                    "insight_text": insight_text,
                    "importance": data["average_probability"] * data["count"],
                }
            )

        # Generate insights for high-risk individual side effects
        for medication, prediction in side_effect_predictions.items():
            for effect in prediction.get("high_risk_effects", []):
                effect_name = effect.get("effect")

                # Skip if already covered in common effects
                if effect_name in common_effects:
                    continue

                probability = effect.get("probability", 0)
                genetic_factors = effect.get("genetic_factors", [])

                insight_text = f"{effect_name.replace('_', ' ').title()} is a high risk side effect specific to {medication}"

                if genetic_factors:
                    gene_text = (
                        f"{', '.join(genetic_factors[:-1])} and {genetic_factors[-1]}"
                        if len(genetic_factors) > 1
                        else genetic_factors[0]
                    )
                    insight_text += f", influenced by {gene_text} genetic factors"

                insights.append(
                    {
                        "effect": effect_name,
                        "medications": [medication],
                        "probability": probability,
                        "genetic_factors": genetic_factors,
                        "insight_text": insight_text,
                        "importance": probability,
                    }
                )

        # Sort insights by importance
        insights.sort(key=lambda x: x["importance"], reverse=True)

        return insights

    async def recommend_treatment_plan(
        self,
        patient_id: UUID,
        patient_data: dict[str, Any],
        diagnosis: str,
        current_medications: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Recommend a personalized treatment plan based on genetic markers and diagnosis.

        Args:
            patient_id: UUID of the patient
            patient_data: Patient data including genetic markers
            diagnosis: Patient diagnosis
            current_medications: Optional list of current medications

        Returns:
            Dictionary containing treatment recommendations
        """
        try:
            # Validate patient data
            if not patient_data.get("genetic_markers"):
                raise ValidationError("Patient data must include genetic markers")

            # Define diagnosis-medication mappings
            # This is a simplified version - in practice, this would be a more comprehensive database
            diagnosis_medications = {
                "major_depressive_disorder": {
                    "first_line": [
                        "sertraline",
                        "escitalopram",
                        "venlafaxine",
                        "bupropion",
                    ],
                    "second_line": ["fluoxetine", "duloxetine", "mirtazapine"],
                    "adjunct": ["aripiprazole", "quetiapine", "lithium"],
                },
                "generalized_anxiety_disorder": {
                    "first_line": [
                        "escitalopram",
                        "sertraline",
                        "venlafaxine",
                        "duloxetine",
                    ],
                    "second_line": ["buspirone", "paroxetine"],
                    "adjunct": ["pregabalin", "hydroxyzine"],
                },
                "bipolar_disorder": {
                    "first_line": ["lithium", "lamotrigine", "valproate"],
                    "second_line": ["quetiapine", "aripiprazole", "olanzapine"],
                    "adjunct": ["lurasidone", "carbamazepine"],
                },
                "schizophrenia": {
                    "first_line": ["aripiprazole", "risperidone", "olanzapine"],
                    "second_line": ["quetiapine", "ziprasidone", "paliperidone"],
                    "adjunct": ["clozapine", "lurasidone"],
                },
                "adhd": {
                    "first_line": [
                        "methylphenidate",
                        "amphetamine",
                        "lisdexamfetamine",
                    ],
                    "second_line": ["atomoxetine", "guanfacine"],
                    "adjunct": ["bupropion", "clonidine"],
                },
            }

            # Get medications for diagnosis
            if diagnosis not in diagnosis_medications:
                raise ValidationError(
                    f"Diagnosis {diagnosis} not supported for treatment recommendations"
                )

            diagnosis_meds = diagnosis_medications[diagnosis]

            # Combine all potential medications
            all_medications = []
            for category in ["first_line", "second_line", "adjunct"]:
                all_medications.extend(diagnosis_meds.get(category, []))

            # Predict medication responses
            predictions = await self.model.predict_medication_response(
                patient_id=patient_id,
                patient_data=patient_data,
                medications=all_medications,
            )

            # Analyze gene-medication interactions
            interactions = await self.model.analyze_gene_medication_interactions(
                patient_data.get("genetic_markers", {})
            )

            # Generate treatment recommendations
            recommendations = await self._generate_treatment_recommendations(
                diagnosis=diagnosis,
                diagnosis_meds=diagnosis_meds,
                predictions=predictions,
                interactions=interactions,
                current_medications=current_medications,
            )

            return {
                "patient_id": str(patient_id),
                "diagnosis": diagnosis,
                "current_medications": current_medications,
                "medication_predictions": predictions.get("medication_predictions", {}),
                "gene_interactions": interactions.get("gene_medication_interactions", []),
                "recommendations": recommendations,
                "generated_at": datetime.now(UTC).isoformat(),
            }

        except Exception as e:
            logging.error(f"Error recommending treatment plan: {e!s}")
            raise ModelExecutionError(f"Failed to recommend treatment plan: {e!s}")

    async def _generate_treatment_recommendations(
        self,
        diagnosis: str,
        diagnosis_meds: dict[str, list[str]],
        predictions: dict[str, Any],
        interactions: dict[str, Any],
        current_medications: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Generate treatment recommendations based on predictions and interactions.

        Args:
            diagnosis: Patient diagnosis
            diagnosis_meds: Dictionary of medications by line of treatment
            predictions: Medication response predictions
            interactions: Gene-medication interactions
            current_medications: Optional list of current medications

        Returns:
            Dictionary containing treatment recommendations
        """
        # Extract medication predictions
        med_predictions = predictions.get("medication_predictions", {})

        # Extract gene interactions
        gene_interactions = interactions.get("gene_medication_interactions", [])

        # Create interaction lookup
        interaction_lookup = {}

        for interaction in gene_interactions:
            medication = interaction.get("medication")

            if medication:
                if medication not in interaction_lookup:
                    interaction_lookup[medication] = []

                interaction_lookup[medication].append(interaction)

        # Process each line of treatment
        recommendations = {}

        for line, medications in diagnosis_meds.items():
            # Filter to medications with predictions
            line_meds = [med for med in medications if med in med_predictions]

            # Sort by predicted effectiveness
            sorted_meds = sorted(
                line_meds,
                key=lambda med: med_predictions[med]["effectiveness_score"],
                reverse=True,
            )

            # Generate recommendations for this line
            line_recommendations = []

            for medication in sorted_meds:
                prediction = med_predictions[medication]
                interactions = interaction_lookup.get(medication, [])

                # Check if currently taking
                is_current = current_medications and medication in current_medications

                # Generate recommendation
                recommendation = {
                    "medication": medication,
                    "effectiveness_score": prediction["effectiveness_score"],
                    "confidence": prediction["confidence"],
                    "predicted_category": prediction["predicted_category"],
                    "genetic_interactions": interactions,
                    "has_interactions": len(interactions) > 0,
                    "is_current_medication": is_current,
                }

                # Add dosing guidance based on genetic interactions
                if interactions:
                    interaction_texts = []

                    for interaction in interactions:
                        gene = interaction.get("gene")
                        variant = interaction.get("variant")
                        recommendation_text = interaction.get("recommendation")

                        if gene and variant and recommendation_text:
                            interaction_texts.append(f"{gene} {variant}: {recommendation_text}")

                    recommendation["dosing_guidance"] = interaction_texts

                line_recommendations.append(recommendation)

            recommendations[line] = line_recommendations

        # Generate summary recommendations
        summary = []

        # First line recommendations
        first_line = recommendations.get("first_line", [])

        if first_line:
            # Check for high effectiveness first line options
            high_effectiveness = [med for med in first_line if med["effectiveness_score"] >= 0.7]

            if high_effectiveness:
                for med in high_effectiveness[:2]:  # Top 2
                    summary.append(
                        {
                            "medication": med["medication"],
                            "line": "first_line",
                            "recommendation_text": f"{med['medication'].title()} is recommended as first-line treatment with high predicted effectiveness ({med['effectiveness_score']:.2f})",
                            "has_interactions": med["has_interactions"],
                            "importance": 3 * med["effectiveness_score"],
                        }
                    )
            else:
                # Recommend top first line option
                med = first_line[0]
                summary.append(
                    {
                        "medication": med["medication"],
                        "line": "first_line",
                        "recommendation_text": f"{med['medication'].title()} is recommended as first-line treatment with moderate predicted effectiveness ({med['effectiveness_score']:.2f})",
                        "has_interactions": med["has_interactions"],
                        "importance": 2 * med["effectiveness_score"],
                    }
                )

        # Second line recommendations
        second_line = recommendations.get("second_line", [])

        if second_line:
            # Check for high effectiveness second line options
            high_effectiveness = [med for med in second_line if med["effectiveness_score"] >= 0.7]

            if high_effectiveness:
                med = high_effectiveness[0]
                summary.append(
                    {
                        "medication": med["medication"],
                        "line": "second_line",
                        "recommendation_text": f"{med['medication'].title()} is recommended as an alternative with high predicted effectiveness ({med['effectiveness_score']:.2f})",
                        "has_interactions": med["has_interactions"],
                        "importance": 2 * med["effectiveness_score"],
                    }
                )

        # Adjunct recommendations
        adjunct = recommendations.get("adjunct", [])

        if adjunct:
            # Recommend top adjunct option
            med = adjunct[0]
            summary.append(
                {
                    "medication": med["medication"],
                    "line": "adjunct",
                    "recommendation_text": f"{med['medication'].title()} is recommended as an adjunct treatment with predicted effectiveness of {med['effectiveness_score']:.2f}",
                    "has_interactions": med["has_interactions"],
                    "importance": med["effectiveness_score"],
                }
            )

        # Add genetic interaction warnings
        for medication, interactions in interaction_lookup.items():
            if interactions and any(
                rec["medication"] == medication
                for line_recs in recommendations.values()
                for rec in line_recs
            ):
                # Get the most important interaction
                interaction = interactions[0]
                gene = interaction.get("gene")
                variant = interaction.get("variant")

                if gene and variant:
                    summary.append(
                        {
                            "medication": medication,
                            "line": "genetic_warning",
                            "recommendation_text": f"Caution with {medication.title()} due to {gene} {variant} status - dose adjustment may be required",
                            "has_interactions": True,
                            "importance": 1.5,
                        }
                    )

        # Sort summary by importance
        summary.sort(key=lambda x: x["importance"], reverse=True)

        return {"by_line": recommendations, "summary": summary}

    def get_service_info(self) -> dict[str, Any]:
        """
        Get information about the service.

        Returns:
            Dictionary containing service information
        """
        return {
            "service_name": "Pharmacogenomics Service",
            "model": self.model.get_model_info(),
            "medication_categories": self.medication_categories,
            "timestamp": datetime.now(UTC).isoformat(),
        }
