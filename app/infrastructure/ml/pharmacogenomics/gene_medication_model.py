"""
Gene-Medication Interaction Model for the NOVAMIND Digital Twin.

This module implements a model for analyzing gene-medication interactions
and predicting medication responses based on genetic markers, following
Clean Architecture principles and ensuring HIPAA compliance.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any
from uuid import UUID

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingRegressor, RandomForestClassifier

from app.domain.utils.datetime_utils import UTC
from app.infrastructure.ml.base.base_model import BaseModel


class GeneMedicationModel(BaseModel):
    """
    Model for gene-medication interaction analysis and medication response prediction.

    This class implements a model that analyzes gene-medication interactions and
    predicts medication responses based on genetic markers, providing personalized
    treatment recommendations for psychiatric patients.
    """

    def __init__(
        self,
        model_name: str = "gene_medication_model",
        version: str = "1.0.0",
        model_path: str | None = None,
        logger: logging.Logger | None = None,
        gene_markers: list[str] | None = None,
        medications: list[str] | None = None,
    ):
        """
        Initialize the gene-medication model.

        Args:
            model_name: Name of the model
            version: Version of the model
            model_path: Path to the saved model
            logger: Logger for tracking model operations
            gene_markers: List of genetic markers to analyze
            medications: List of medications to analyze
        """
        super().__init__(model_name, version, model_path, logger)

        # Default gene markers if not provided
        self.gene_markers = gene_markers or [
            "CYP2D6",
            "CYP2C19",
            "CYP2C9",
            "CYP1A2",
            "CYP3A4",
            "CYP3A5",
            "COMT",
            "BDNF",
            "SLC6A4",
            "HTR2A",
            "FKBP5",
            "ABCB1",
            "MTHFR",
        ]

        # Default medications if not provided
        self.medications = medications or [
            "fluoxetine",
            "sertraline",
            "escitalopram",
            "venlafaxine",
            "duloxetine",
            "bupropion",
            "mirtazapine",
            "aripiprazole",
            "quetiapine",
            "risperidone",
            "olanzapine",
            "lamotrigine",
            "valproate",
            "lithium",
            "clozapine",
        ]

        # Initialize models
        self.response_model = None  # Predicts medication response
        self.side_effect_model = None  # Predicts side effect risk
        self.interaction_model = None  # Analyzes gene-medication interactions

        # Gene-medication interaction database
        self.interaction_db = {}

        # Load models if path provided
        if model_path:
            self.load()

    def load(self) -> None:
        """
        Load the model from storage.

        Raises:
            FileNotFoundError: If the model files cannot be found
            ValueError: If the model files are invalid or corrupted
        """
        if not self.model_path:
            raise ValueError("Model path must be specified to load the model")

        try:
            # Load model metadata
            meta_path = os.path.join(self.model_path, "metadata.json")
            with open(meta_path) as f:
                metadata = json.load(f)

            # Update model attributes from metadata
            self.version = metadata.get("version", self.version)
            self.gene_markers = metadata.get("gene_markers", self.gene_markers)
            self.medications = metadata.get("medications", self.medications)
            self.last_training_date = metadata.get("last_training_date")
            self.metrics = metadata.get("metrics", {})

            # Load response model
            response_path = os.path.join(self.model_path, "response_model.joblib")
            self.response_model = joblib.load(response_path)

            # Load side effect model
            side_effect_path = os.path.join(self.model_path, "side_effect_model.joblib")
            self.side_effect_model = joblib.load(side_effect_path)

            # Load interaction model
            interaction_path = os.path.join(self.model_path, "interaction_model.joblib")
            self.interaction_model = joblib.load(interaction_path)

            # Load interaction database
            db_path = os.path.join(self.model_path, "interaction_db.json")
            with open(db_path) as f:
                self.interaction_db = json.load(f)

            self.logger.info(f"Successfully loaded gene-medication model from {self.model_path}")

        except Exception as e:
            self.logger.error(f"Failed to load gene-medication model: {e!s}")
            raise

    def save(self, path: str | None = None) -> str:
        """
        Save the model to storage.

        Args:
            path: Path to save the model to

        Returns:
            The path where the model was saved

        Raises:
            PermissionError: If the model cannot be saved to the specified path
            ValueError: If the model is not initialized
        """
        save_path = path or self.model_path
        if not save_path:
            raise ValueError("Save path must be specified")

        try:
            # Create directory if it doesn't exist
            os.makedirs(save_path, exist_ok=True)

            # Save model metadata
            metadata = {
                "version": self.version,
                "gene_markers": self.gene_markers,
                "medications": self.medications,
                "last_training_date": self.last_training_date,
                "metrics": self.metrics,
                "saved_at": datetime.now(UTC).isoformat(),
            }

            meta_path = os.path.join(save_path, "metadata.json")
            with open(meta_path, "w") as f:
                json.dump(metadata, f, indent=2)

            # Save response model
            if self.response_model:
                response_path = os.path.join(save_path, "response_model.joblib")
                joblib.dump(self.response_model, response_path)

            # Save side effect model
            if self.side_effect_model:
                side_effect_path = os.path.join(save_path, "side_effect_model.joblib")
                joblib.dump(self.side_effect_model, side_effect_path)

            # Save interaction model
            if self.interaction_model:
                interaction_path = os.path.join(save_path, "interaction_model.joblib")
                joblib.dump(self.interaction_model, interaction_path)

            # Save interaction database
            db_path = os.path.join(save_path, "interaction_db.json")
            with open(db_path, "w") as f:
                json.dump(self.interaction_db, f, indent=2)

            self.model_path = save_path
            self.logger.info(f"Successfully saved gene-medication model to {save_path}")
            return save_path

        except Exception as e:
            self.logger.error(f"Failed to save gene-medication model: {e!s}")
            raise

    def preprocess(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Preprocess input data for prediction.

        Args:
            data: Raw input data containing genetic markers and patient information

        Returns:
            Preprocessed data for prediction

        Raises:
            ValueError: If the data is invalid or cannot be preprocessed
        """
        try:
            # Sanitize patient data for HIPAA compliance
            sanitized_data = self.sanitize_patient_data(data)

            # Extract genetic markers
            genetic_data = sanitized_data.get("genetic_markers", {})

            # Create feature vector
            features = []
            for marker in self.gene_markers:
                # Get marker value or default to wild type (0)
                value = genetic_data.get(marker, 0)
                features.append(value)

            # Add patient demographics if available
            demographics = sanitized_data.get("demographics", {})
            if demographics:
                # Age
                age = demographics.get("age", 0)
                features.append(age)

                # Sex (0 for male, 1 for female)
                sex = 1 if demographics.get("sex", "").lower() == "female" else 0
                features.append(sex)

                # Weight (kg)
                weight = demographics.get("weight", 0)
                features.append(weight)

            # Extract medications to analyze
            medications = sanitized_data.get("medications", [])
            if not medications:
                medications = self.medications  # Use all medications if none specified

            return {
                "features": np.array(features, dtype=np.float32),
                "medications": medications,
                "genetic_markers": {
                    marker: genetic_data.get(marker, 0) for marker in self.gene_markers
                },
                "patient_id": sanitized_data.get("patient_id"),
            }

        except Exception as e:
            self.logger.error(f"Error during preprocessing: {e!s}")
            raise ValueError(f"Failed to preprocess data: {e!s}")

    def predict(self, preprocessed_data: dict[str, Any]) -> dict[str, Any]:
        """
        Generate predictions using the model.

        Args:
            preprocessed_data: Preprocessed data for prediction

        Returns:
            Raw predictions from the model

        Raises:
            ValueError: If the model is not initialized or the data is invalid
        """
        try:
            # Ensure models are loaded
            if not all([self.response_model, self.side_effect_model, self.interaction_model]):
                raise ValueError("Models are not initialized")

            features = preprocessed_data["features"]
            medications = preprocessed_data["medications"]
            genetic_markers = preprocessed_data["genetic_markers"]

            # Reshape features for prediction
            features_2d = features.reshape(1, -1)

            # Generate predictions for each medication
            medication_predictions = {}

            for medication in medications:
                # Skip if medication is not in our database
                if medication not in self.medications:
                    continue

                # Get medication index
                med_idx = self.medications.index(medication)

                # Create medication-specific feature vector
                med_features = np.append(features_2d, med_idx)
                med_features = med_features.reshape(1, -1)

                # Predict response (efficacy)
                response_pred = self.response_model.predict_proba(med_features)[0]

                # Predict side effect risk
                side_effect_pred = self.side_effect_model.predict_proba(med_features)[0]

                # Analyze gene-medication interactions
                interactions = self._analyze_interactions(medication, genetic_markers)

                # Store predictions
                medication_predictions[medication] = {
                    "response_probability": {
                        "poor": float(response_pred[0]),
                        "moderate": float(response_pred[1]),
                        "good": float(response_pred[2]),
                    },
                    "side_effect_risk": {
                        "low": float(side_effect_pred[0]),
                        "moderate": float(side_effect_pred[1]),
                        "high": float(side_effect_pred[2]),
                    },
                    "interactions": interactions,
                }

            return {
                "medication_predictions": medication_predictions,
                "genetic_markers": genetic_markers,
            }

        except Exception as e:
            self.logger.error(f"Error during prediction: {e!s}")
            raise ValueError(f"Failed to generate predictions: {e!s}")

    def postprocess(self, predictions: dict[str, Any]) -> dict[str, Any]:
        """
        Postprocess model predictions.

        Args:
            predictions: Raw predictions from the model

        Returns:
            Postprocessed predictions with additional information

        Raises:
            ValueError: If the predictions are invalid or cannot be postprocessed
        """
        try:
            medication_predictions = predictions["medication_predictions"]
            genetic_markers = predictions["genetic_markers"]

            # Generate medication recommendations
            recommendations = self._generate_recommendations(medication_predictions)

            # Generate genetic insights
            genetic_insights = self._generate_genetic_insights(genetic_markers)

            # Combine results
            results = {
                "medication_predictions": medication_predictions,
                "recommendations": recommendations,
                "genetic_insights": genetic_insights,
                "analysis_timestamp": datetime.now(UTC).isoformat(),
            }

            return results

        except Exception as e:
            self.logger.error(f"Error during postprocessing: {e!s}")
            raise ValueError(f"Failed to postprocess predictions: {e!s}")

    def _analyze_interactions(
        self, medication: str, genetic_markers: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Analyze interactions between a medication and genetic markers.

        Args:
            medication: Name of the medication
            genetic_markers: Dictionary of genetic markers

        Returns:
            List of interaction details
        """
        interactions = []

        # Get known interactions from database
        med_interactions = self.interaction_db.get(medication, {})

        for gene, variants in med_interactions.items():
            # Skip if gene not in patient's genetic markers
            if gene not in genetic_markers:
                continue

            # Get patient's variant
            patient_variant = genetic_markers[gene]

            # Check for interactions
            for variant, interaction in variants.items():
                if str(patient_variant) == variant:
                    interactions.append(
                        {
                            "gene": gene,
                            "variant": variant,
                            "effect": interaction["effect"],
                            "impact": interaction["impact"],
                            "evidence_level": interaction["evidence_level"],
                            "recommendation": interaction["recommendation"],
                        }
                    )

        return interactions

    def _generate_recommendations(self, medication_predictions: dict[str, Any]) -> dict[str, Any]:
        """
        Generate medication recommendations based on predictions.

        Args:
            medication_predictions: Predictions for each medication

        Returns:
            Dictionary containing medication recommendations
        """
        # Calculate overall scores for each medication
        medication_scores = {}

        for medication, prediction in medication_predictions.items():
            # Response score (weighted towards 'good' response)
            response_score = (
                prediction["response_probability"]["good"] * 1.0
                + prediction["response_probability"]["moderate"] * 0.5
                + prediction["response_probability"]["poor"] * 0.0
            )

            # Side effect score (inverse of risk, weighted towards 'low' risk)
            side_effect_score = (
                prediction["side_effect_risk"]["low"] * 1.0
                + prediction["side_effect_risk"]["moderate"] * 0.5
                + prediction["side_effect_risk"]["high"] * 0.0
            )

            # Interaction penalty
            interaction_penalty = 0.0
            for interaction in prediction["interactions"]:
                if interaction["impact"] == "high":
                    interaction_penalty += 0.3
                elif interaction["impact"] == "moderate":
                    interaction_penalty += 0.15
                elif interaction["impact"] == "low":
                    interaction_penalty += 0.05

            # Overall score (response is more important than side effects)
            overall_score = (response_score * 0.6) + (side_effect_score * 0.4) - interaction_penalty

            medication_scores[medication] = {
                "overall_score": overall_score,
                "response_score": response_score,
                "side_effect_score": side_effect_score,
                "interaction_penalty": interaction_penalty,
            }

        # Sort medications by overall score
        sorted_medications = sorted(
            medication_scores.items(), key=lambda x: x[1]["overall_score"], reverse=True
        )

        # Generate recommendations
        recommendations = {
            "primary_recommendations": [],
            "alternative_recommendations": [],
            "medications_to_avoid": [],
        }

        # Top 3 medications as primary recommendations
        for medication, scores in sorted_medications[:3]:
            if scores["overall_score"] >= 0.6:  # Threshold for primary recommendation
                recommendations["primary_recommendations"].append(
                    {
                        "medication": medication,
                        "overall_score": scores["overall_score"],
                        "rationale": self._generate_recommendation_rationale(
                            medication, medication_predictions[medication]
                        ),
                    }
                )

        # Next 3 medications as alternatives
        for medication, scores in sorted_medications[3:6]:
            if scores["overall_score"] >= 0.4:  # Threshold for alternative
                recommendations["alternative_recommendations"].append(
                    {
                        "medication": medication,
                        "overall_score": scores["overall_score"],
                        "rationale": self._generate_recommendation_rationale(
                            medication, medication_predictions[medication]
                        ),
                    }
                )

        # Medications to avoid
        for medication, scores in sorted_medications:
            if scores["overall_score"] < 0.4 or scores["interaction_penalty"] > 0.2:
                recommendations["medications_to_avoid"].append(
                    {
                        "medication": medication,
                        "overall_score": scores["overall_score"],
                        "rationale": self._generate_recommendation_rationale(
                            medication, medication_predictions[medication], avoid=True
                        ),
                    }
                )

        return recommendations

    def _generate_recommendation_rationale(
        self, medication: str, prediction: dict[str, Any], avoid: bool = False
    ) -> str:
        """
        Generate rationale for medication recommendation.

        Args:
            medication: Name of the medication
            prediction: Prediction details for the medication
            avoid: Whether this is a medication to avoid

        Returns:
            Rationale string
        """
        if avoid:
            # Rationale for avoiding medication
            if prediction["response_probability"]["poor"] > 0.5:
                rationale = f"Predicted poor response to {medication}"
            elif prediction["side_effect_risk"]["high"] > 0.5:
                rationale = f"High risk of side effects with {medication}"
            elif len(prediction["interactions"]) > 0:
                rationale = f"Genetic interactions may reduce efficacy or increase side effects of {medication}"
            else:
                rationale = f"Other medications show better predicted outcomes than {medication}"
        else:
            # Rationale for recommending medication
            if prediction["response_probability"]["good"] > 0.7:
                rationale = f"High probability of good response to {medication}"
            elif prediction["response_probability"]["good"] > 0.5:
                rationale = f"Moderate to good predicted response to {medication}"
            elif prediction["side_effect_risk"]["low"] > 0.7:
                rationale = f"Low predicted risk of side effects with {medication}"
            else:
                rationale = f"Balanced profile of efficacy and tolerability for {medication}"

            # Add interaction information if present
            if len(prediction["interactions"]) > 0:
                rationale += ", with consideration for genetic interactions"

        return rationale

    def _generate_genetic_insights(self, genetic_markers: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Generate insights based on genetic markers.

        Args:
            genetic_markers: Dictionary of genetic markers

        Returns:
            List of genetic insights
        """
        insights = []

        # CYP2D6 - metabolizes many psychiatric medications
        if "CYP2D6" in genetic_markers:
            variant = genetic_markers["CYP2D6"]
            if variant == 0:
                insights.append(
                    {
                        "gene": "CYP2D6",
                        "variant": "Normal metabolizer",
                        "insight": "Standard dosing for most medications metabolized by CYP2D6 is appropriate.",
                    }
                )
            elif variant == 1:
                insights.append(
                    {
                        "gene": "CYP2D6",
                        "variant": "Intermediate metabolizer",
                        "insight": "May require lower doses of medications metabolized by CYP2D6.",
                    }
                )
            elif variant == 2:
                insights.append(
                    {
                        "gene": "CYP2D6",
                        "variant": "Poor metabolizer",
                        "insight": "Higher risk of side effects with standard doses of medications metabolized by CYP2D6. Consider dose reduction or alternative medications.",
                    }
                )
            elif variant == 3:
                insights.append(
                    {
                        "gene": "CYP2D6",
                        "variant": "Ultrarapid metabolizer",
                        "insight": "May require higher doses of medications metabolized by CYP2D6 for therapeutic effect.",
                    }
                )

        # CYP2C19 - metabolizes many antidepressants
        if "CYP2C19" in genetic_markers:
            variant = genetic_markers["CYP2C19"]
            if variant == 0:
                insights.append(
                    {
                        "gene": "CYP2C19",
                        "variant": "Normal metabolizer",
                        "insight": "Standard dosing for most medications metabolized by CYP2C19 is appropriate.",
                    }
                )
            elif variant == 1:
                insights.append(
                    {
                        "gene": "CYP2C19",
                        "variant": "Intermediate metabolizer",
                        "insight": "May require lower doses of medications metabolized by CYP2C19.",
                    }
                )
            elif variant == 2:
                insights.append(
                    {
                        "gene": "CYP2C19",
                        "variant": "Poor metabolizer",
                        "insight": "Higher risk of side effects with standard doses of medications metabolized by CYP2C19. Consider dose reduction or alternative medications.",
                    }
                )
            elif variant == 3:
                insights.append(
                    {
                        "gene": "CYP2C19",
                        "variant": "Ultrarapid metabolizer",
                        "insight": "May require higher doses of medications metabolized by CYP2C19 for therapeutic effect.",
                    }
                )

        # SLC6A4 - serotonin transporter, relevant for SSRIs
        if "SLC6A4" in genetic_markers:
            variant = genetic_markers["SLC6A4"]
            if variant == 0:
                insights.append(
                    {
                        "gene": "SLC6A4",
                        "variant": "Long/Long",
                        "insight": "May have better response to SSRIs compared to other antidepressant classes.",
                    }
                )
            elif variant == 1:
                insights.append(
                    {
                        "gene": "SLC6A4",
                        "variant": "Long/Short",
                        "insight": "Intermediate response to SSRIs. May benefit from higher doses or augmentation strategies.",
                    }
                )
            elif variant == 2:
                insights.append(
                    {
                        "gene": "SLC6A4",
                        "variant": "Short/Short",
                        "insight": "May have reduced response to SSRIs. Consider alternative antidepressant classes or augmentation strategies.",
                    }
                )

        # HTR2A - serotonin receptor, relevant for antipsychotics
        if "HTR2A" in genetic_markers:
            variant = genetic_markers["HTR2A"]
            if variant == 1:
                insights.append(
                    {
                        "gene": "HTR2A",
                        "variant": "T/T or T/C",
                        "insight": "May have increased risk of side effects with antipsychotics that have strong 5-HT2A binding.",
                    }
                )

        return insights

    def train(
        self,
        training_data: dict[str, Any],
        validation_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Train the model on the provided data.

        Args:
            training_data: Data for training the model
            validation_data: Optional data for validating the model

        Returns:
            Dictionary of training metrics

        Raises:
            ValueError: If the training data is invalid
        """
        try:
            # Extract features and targets
            X_train = training_data["features"]
            y_response = training_data["response_labels"]
            y_side_effects = training_data["side_effect_labels"]

            # Train response model
            self.response_model = RandomForestClassifier(
                n_estimators=100, max_depth=10, random_state=42, n_jobs=-1
            )
            self.response_model.fit(X_train, y_response)

            # Train side effect model
            self.side_effect_model = RandomForestClassifier(
                n_estimators=100, max_depth=10, random_state=42, n_jobs=-1
            )
            self.side_effect_model.fit(X_train, y_side_effects)

            # Train interaction model (simplified for now)
            self.interaction_model = GradientBoostingRegressor(
                n_estimators=100, max_depth=5, random_state=42
            )

            if "interaction_scores" in training_data:
                y_interaction = training_data["interaction_scores"]
                self.interaction_model.fit(X_train, y_interaction)

            # Update interaction database
            if "interaction_db" in training_data:
                self.interaction_db = training_data["interaction_db"]

            # Calculate metrics
            metrics = {}

            # Response model metrics
            response_accuracy = self.response_model.score(X_train, y_response)
            metrics["response_model"] = {"accuracy": response_accuracy}

            # Side effect model metrics
            side_effect_accuracy = self.side_effect_model.score(X_train, y_side_effects)
            metrics["side_effect_model"] = {"accuracy": side_effect_accuracy}

            # Validation metrics if validation data provided
            if validation_data:
                X_val = validation_data["features"]
                y_val_response = validation_data["response_labels"]
                y_val_side_effects = validation_data["side_effect_labels"]

                val_response_accuracy = self.response_model.score(X_val, y_val_response)
                val_side_effect_accuracy = self.side_effect_model.score(X_val, y_val_side_effects)

                metrics["validation"] = {
                    "response_model": {"accuracy": val_response_accuracy},
                    "side_effect_model": {"accuracy": val_side_effect_accuracy},
                }

            # Update model metrics
            self.metrics = metrics

            # Update last training date
            self.last_training_date = datetime.now(UTC).isoformat()

            return metrics

        except Exception as e:
            self.logger.error(f"Error during training: {e!s}")
            raise ValueError(f"Failed to train model: {e!s}")

    def predict_medication_responses(
        self,
        patient_id: UUID,
        patient_data: dict[str, Any],
        medications: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Predict medication responses for a patient.

        Args:
            patient_id: ID of the patient
            patient_data: Patient data including genetic markers
            medications: Optional list of medications to analyze

        Returns:
            Dictionary containing medication response predictions

        Raises:
            ValueError: If the input data is invalid
        """
        try:
            # Prepare input data
            input_data = {
                "patient_id": str(patient_id),
                "genetic_markers": patient_data.get("genetic_markers", {}),
                "demographics": patient_data.get("demographics", {}),
                "medications": medications,
            }

            # Generate predictions
            preprocessed_data = self.preprocess(input_data)
            raw_predictions = self.predict(preprocessed_data)
            processed_results = self.postprocess(raw_predictions)

            # Add metadata
            processed_results["metadata"] = {
                "patient_id": str(patient_id),
                "analysis_generated_at": datetime.now(UTC).isoformat(),
                "model_name": self.model_name,
                "model_version": self.version,
            }

            return processed_results

        except Exception as e:
            self.logger.error(f"Error during medication response prediction: {e!s}")
            raise ValueError(f"Failed to predict medication responses: {e!s}")
