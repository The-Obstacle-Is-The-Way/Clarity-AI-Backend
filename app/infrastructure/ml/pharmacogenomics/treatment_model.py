"""
Pharmacogenomics and Treatment Response Model for the NOVAMIND Digital Twin.

This module implements a machine learning model for predicting medication
response based on pharmacogenomic data, following the architecture described in
the AI Models Core Implementation documentation and adhering to HIPAA compliance.
"""

import logging
import os
from datetime import datetime
from typing import Any
from uuid import UUID

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.model_selection import cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# Import relevant exceptions from core layer as a temporary workaround
from app.core.exceptions.base_exceptions import ModelExecutionError
from app.domain.exceptions import ValidationError
from app.domain.utils.datetime_utils import UTC


class PharmacogenomicsModel:
    """
    Machine learning model for pharmacogenomics and treatment response prediction.

    This model predicts medication response based on genetic markers, patient
    characteristics, and historical treatment data, with a focus on psychiatric
    medications.
    """

    def __init__(
        self,
        model_path: str | None = None,
        gene_markers: list[str] | None = None,
        medications: list[str] | None = None,
    ):
        """
        Initialize the pharmacogenomics model.

        Args:
            model_path: Optional path to a pretrained model
            gene_markers: List of genetic markers used by the model
            medications: List of medications supported by the model
        """
        # Default gene markers if not provided
        self.gene_markers = gene_markers or [
            "CYP2D6",
            "CYP2C19",
            "CYP3A4",
            "CYP1A2",
            "CYP2B6",
            "CYP2C9",
            "COMT",
            "HTR2A",
            "HTR2C",
            "ABCB1",
            "MTHFR",
            "BDNF",
            "SLC6A4",
            "DRD2",
            "OPRM1",
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
            "quetiapine",
            "aripiprazole",
            "risperidone",
            "olanzapine",
            "lamotrigine",
            "valproate",
            "lithium",
            "clonazepam",
            "lorazepam",
        ]

        # Patient features used by the model
        self.patient_features = [
            "age",
            "sex",
            "weight",
            "height",
            "smoking_status",
            "alcohol_consumption",
            "comorbidities",
        ]

        # Initialize models dictionary
        self.models = {}

        # Initialize preprocessors
        self._init_preprocessors()

        # Load pretrained model if provided
        if model_path and os.path.exists(model_path):
            self._load_model(model_path)

    def _init_preprocessors(self) -> None:
        """Initialize data preprocessors for different feature types."""
        # Preprocessor for numerical features
        self.numeric_preprocessor = Pipeline([("scaler", StandardScaler())])

        # Preprocessor for categorical features
        self.categorical_preprocessor = Pipeline(
            [("onehot", OneHotEncoder(handle_unknown="ignore", sparse=False))]
        )

        # Preprocessor for genetic markers
        self.genetic_preprocessor = Pipeline([("scaler", StandardScaler())])

    def _load_model(self, model_path: str) -> None:
        """
        Load a pretrained model from disk.

        Args:
            model_path: Path to the model file
        """
        try:
            model_data = joblib.load(model_path)
            self.models = model_data.get("models", {})
            self.gene_markers = model_data.get("gene_markers", self.gene_markers)
            self.medications = model_data.get("medications", self.medications)
            self.preprocessors = model_data.get("preprocessors", {})

            logging.info(f"Loaded pharmacogenomics model from {model_path}")
        except Exception as e:
            logging.error(f"Error loading pharmacogenomics model: {e!s}")
            raise ModelExecutionError(f"Failed to load pharmacogenomics model: {e!s}")

    def save_model(self, model_path: str) -> None:
        """
        Save the trained model to disk.

        Args:
            model_path: Path to save the model
        """
        model_data = {
            "models": self.models,
            "gene_markers": self.gene_markers,
            "medications": self.medications,
            "preprocessors": {
                "numeric": self.numeric_preprocessor,
                "categorical": self.categorical_preprocessor,
                "genetic": self.genetic_preprocessor,
            },
            "timestamp": datetime.now(UTC).isoformat(),
        }

        try:
            joblib.dump(model_data, model_path)
            logging.info(f"Saved pharmacogenomics model to {model_path}")
        except Exception as e:
            logging.error(f"Error saving pharmacogenomics model: {e!s}")
            raise Exception(f"Failed to save pharmacogenomics model: {e!s}")

    def preprocess_data(
        self, data: dict[str, Any], is_training: bool = False
    ) -> dict[str, np.ndarray]:
        """
        Preprocess input data for model training or inference.

        Args:
            data: Input data dictionary
            is_training: Whether preprocessing is for training

        Returns:
            Dictionary of preprocessed data arrays
        """
        try:
            # Extract genetic markers
            genetic_data = []
            for marker in self.gene_markers:
                genetic_data.append(data.get("genetic_markers", {}).get(marker, 0))

            genetic_array = np.array(genetic_data, dtype=np.float32).reshape(1, -1)

            # Extract patient features
            patient_data = {}

            # Numerical features
            numerical_features = ["age", "weight", "height"]
            numerical_data = []

            for feature in numerical_features:
                numerical_data.append(data.get("patient_features", {}).get(feature, 0))

            numerical_array = np.array(numerical_data, dtype=np.float32).reshape(1, -1)

            # Categorical features
            categorical_features = ["sex", "smoking_status", "alcohol_consumption"]
            categorical_data = []

            for feature in categorical_features:
                categorical_data.append(str(data.get("patient_features", {}).get(feature, "")))

            categorical_array = np.array(categorical_data).reshape(1, -1)

            # Comorbidities (multi-hot encoding)
            comorbidities = data.get("patient_features", {}).get("comorbidities", [])
            comorbidity_list = [
                "diabetes",
                "hypertension",
                "obesity",
                "liver_disease",
                "kidney_disease",
                "thyroid_disorder",
                "seizure_disorder",
            ]

            comorbidity_data = []

            for condition in comorbidity_list:
                comorbidity_data.append(1 if condition in comorbidities else 0)

            comorbidity_array = np.array(comorbidity_data, dtype=np.float32).reshape(1, -1)

            # Apply preprocessing
            if is_training:
                # Fit and transform
                genetic_processed = self.genetic_preprocessor.fit_transform(genetic_array)
                numerical_processed = self.numeric_preprocessor.fit_transform(numerical_array)
                categorical_processed = self.categorical_preprocessor.fit_transform(
                    categorical_array
                )
            else:
                # Transform only
                genetic_processed = self.genetic_preprocessor.transform(genetic_array)
                numerical_processed = self.numeric_preprocessor.transform(numerical_array)
                categorical_processed = self.categorical_preprocessor.transform(categorical_array)

            # Combine all features
            combined_features = np.hstack(
                [
                    genetic_processed,
                    numerical_processed,
                    categorical_processed,
                    comorbidity_array,
                ]
            )

            return {
                "combined_features": combined_features,
                "genetic_features": genetic_processed,
                "numerical_features": numerical_processed,
                "categorical_features": categorical_processed,
                "comorbidity_features": comorbidity_array,
            }

        except Exception as e:
            logging.error(f"Error preprocessing data: {e!s}")
            raise ValidationError(f"Failed to preprocess data: {e!s}")

    def train(
        self,
        training_data: list[dict[str, Any]],
        validation_data: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Train the pharmacogenomics model.

        Args:
            training_data: List of training data samples
            validation_data: Optional validation data

        Returns:
            Dictionary containing training results
        """
        try:
            if not training_data:
                raise ValidationError("No training data provided")

            # Prepare data for each medication
            medication_data = {med: {"X": [], "y": []} for med in self.medications}

            # Process each training sample
            for sample in training_data:
                # Preprocess sample
                preprocessed = self.preprocess_data(sample, is_training=True)

                # Extract medication responses
                medication_responses = sample.get("medication_responses", {})

                for medication in self.medications:
                    if medication in medication_responses:
                        response = medication_responses[medication]

                        # Add to medication-specific dataset
                        medication_data[medication]["X"].append(
                            preprocessed["combined_features"][0]
                        )
                        medication_data[medication]["y"].append(response.get("effectiveness", 0))

            # Train a model for each medication with sufficient data
            training_results = {}

            for medication, data in medication_data.items():
                if len(data["X"]) >= 20:  # Minimum samples for training
                    X = np.array(data["X"])
                    y = np.array(data["y"])

                    # Train regression model for effectiveness
                    model = GradientBoostingRegressor(
                        n_estimators=100,
                        learning_rate=0.1,
                        max_depth=5,
                        random_state=42,
                    )

                    # Cross-validation
                    cv_scores = cross_val_score(model, X, y, cv=5, scoring="neg_mean_squared_error")

                    # Train on full dataset
                    model.fit(X, y)

                    # Store model
                    self.models[medication] = {
                        "effectiveness_model": model,
                        "training_samples": len(y),
                        "cv_scores": -cv_scores.mean(),  # Convert back to MSE
                    }

                    # Calculate feature importance
                    feature_importance = model.feature_importances_

                    # Store training results
                    training_results[medication] = {
                        "training_samples": len(y),
                        "cv_mse": -cv_scores.mean(),
                        "cv_rmse": np.sqrt(-cv_scores.mean()),
                        "feature_importance": feature_importance.tolist(),
                    }

            return {
                "training_results": training_results,
                "medications_trained": list(training_results.keys()),
                "total_medications": len(self.medications),
                "trained_medications": len(training_results),
                "timestamp": datetime.now(UTC).isoformat(),
            }

        except Exception as e:
            logging.error(f"Error training pharmacogenomics model: {e!s}")
            raise ModelExecutionError(f"Failed to train pharmacogenomics model: {e!s}")

    async def predict_medication_response(
        self,
        patient_id: UUID,
        patient_data: dict[str, Any],
        medications: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Predict patient response to psychiatric medications.

        Args:
            patient_id: UUID of the patient
            patient_data: Patient data including genetic markers
            medications: Optional list of medications to predict (defaults to all)

        Returns:
            Dictionary containing prediction results
        """
        try:
            if not self.models:
                raise ModelExecutionError("Model has not been trained or loaded")

            # Use all medications if not specified
            if medications is None:
                medications = self.medications
            else:
                # Filter to only include medications we have models for
                medications = [med for med in medications if med in self.models]

            if not medications:
                raise ValidationError("No valid medications specified for prediction")

            # Preprocess patient data
            preprocessed = self.preprocess_data(patient_data)
            features = preprocessed["combined_features"]

            # Generate predictions for each medication
            predictions = {}

            for medication in medications:
                if medication in self.models:
                    model_data = self.models[medication]

                    # Predict effectiveness
                    effectiveness_model = model_data["effectiveness_model"]
                    effectiveness_score = float(effectiveness_model.predict(features)[0])

                    # Calculate confidence based on training samples
                    training_samples = model_data["training_samples"]
                    confidence = min(0.95, 0.5 + (training_samples / 200))

                    # Generate prediction
                    predictions[medication] = {
                        "effectiveness_score": effectiveness_score,
                        "confidence": confidence,
                        "training_samples": training_samples,
                        "predicted_category": self._categorize_effectiveness(effectiveness_score),
                    }

            # Sort medications by predicted effectiveness
            sorted_medications = sorted(
                predictions.keys(),
                key=lambda med: predictions[med]["effectiveness_score"],
                reverse=True,
            )

            return {
                "patient_id": str(patient_id),
                "medication_predictions": predictions,
                "recommended_medications": sorted_medications[:3],  # Top 3 recommendations
                "prediction_generated_at": datetime.now(UTC).isoformat(),
            }

        except Exception as e:
            logging.error(f"Error predicting medication response: {e!s}")
            raise ModelExecutionError(f"Failed to predict medication response: {e!s}")

    def _categorize_effectiveness(self, score: float) -> str:
        """
        Categorize effectiveness score into descriptive category.

        Args:
            score: Effectiveness score (0-1)

        Returns:
            Category description
        """
        if score >= 0.8:
            return "Excellent response expected"
        elif score >= 0.6:
            return "Good response expected"
        elif score >= 0.4:
            return "Moderate response expected"
        elif score >= 0.2:
            return "Limited response expected"
        else:
            return "Poor response expected"

    async def analyze_gene_medication_interactions(
        self, genetic_markers: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Analyze interactions between genetic markers and medications.

        Args:
            genetic_markers: Dictionary of genetic marker values

        Returns:
            Dictionary containing interaction analysis
        """
        try:
            # Define known gene-medication interactions
            # This is a simplified version - in practice, this would be a more comprehensive database
            known_interactions = {
                "CYP2D6": {
                    "poor_metabolizer": [
                        "fluoxetine",
                        "paroxetine",
                        "venlafaxine",
                        "risperidone",
                    ],
                    "rapid_metabolizer": [
                        "amitriptyline",
                        "nortriptyline",
                        "haloperidol",
                    ],
                },
                "CYP2C19": {
                    "poor_metabolizer": ["citalopram", "escitalopram", "sertraline"],
                    "rapid_metabolizer": ["diazepam", "clopidogrel"],
                },
                "CYP3A4": {
                    "poor_metabolizer": ["quetiapine", "ziprasidone", "aripiprazole"],
                    "rapid_metabolizer": ["buspirone", "alprazolam"],
                },
                "COMT": {
                    "val/val": ["methylphenidate", "amphetamine"],
                    "met/met": ["olanzapine", "clozapine"],
                },
                "HTR2A": {
                    "T/T": ["risperidone", "olanzapine", "clozapine"],
                    "C/C": ["paroxetine", "fluoxetine"],
                },
                "SLC6A4": {
                    "S/S": ["citalopram", "escitalopram", "sertraline"],
                    "L/L": ["fluoxetine", "paroxetine"],
                },
            }

            # Analyze patient's genetic markers
            interactions = []

            for gene, variants in known_interactions.items():
                if gene in genetic_markers:
                    patient_variant = genetic_markers.get(gene)

                    for variant, medications in variants.items():
                        if patient_variant == variant:
                            for medication in medications:
                                if medication in self.medications:
                                    interactions.append(
                                        {
                                            "gene": gene,
                                            "variant": variant,
                                            "medication": medication,
                                            "interaction_type": "metabolism",
                                            "clinical_significance": "significant",
                                            "recommendation": f"Consider dose adjustment for {medication} due to {gene} {variant} status",
                                        }
                                    )

            return {
                "gene_medication_interactions": interactions,
                "total_interactions": len(interactions),
                "genes_analyzed": list(known_interactions.keys()),
                "analysis_generated_at": datetime.now(UTC).isoformat(),
            }

        except Exception as e:
            logging.error(f"Error analyzing gene-medication interactions: {e!s}")
            raise ModelExecutionError(f"Failed to analyze gene-medication interactions: {e!s}")

    async def predict_side_effects(
        self, patient_id: UUID, patient_data: dict[str, Any], medication: str
    ) -> dict[str, Any]:
        """
        Predict potential side effects for a specific medication.

        Args:
            patient_id: UUID of the patient
            patient_data: Patient data including genetic markers
            medication: Medication to predict side effects for

        Returns:
            Dictionary containing side effect predictions
        """
        try:
            if medication not in self.medications:
                raise ValidationError(f"Medication {medication} not supported by the model")

            # Define known medication side effects and associated genetic markers
            # This is a simplified version - in practice, this would be a more comprehensive database
            side_effect_profiles = {
                "fluoxetine": {
                    "nausea": {
                        "genes": ["CYP2D6"],
                        "variants": ["poor_metabolizer"],
                        "probability": 0.3,
                    },
                    "insomnia": {
                        "genes": ["CYP2C19"],
                        "variants": ["rapid_metabolizer"],
                        "probability": 0.2,
                    },
                    "headache": {"genes": [], "variants": [], "probability": 0.15},
                },
                "sertraline": {
                    "nausea": {
                        "genes": ["CYP2C19"],
                        "variants": ["poor_metabolizer"],
                        "probability": 0.25,
                    },
                    "diarrhea": {"genes": [], "variants": [], "probability": 0.2},
                    "insomnia": {
                        "genes": ["SLC6A4"],
                        "variants": ["S/S"],
                        "probability": 0.15,
                    },
                },
                "escitalopram": {
                    "nausea": {
                        "genes": ["CYP2C19"],
                        "variants": ["poor_metabolizer"],
                        "probability": 0.2,
                    },
                    "drowsiness": {"genes": [], "variants": [], "probability": 0.15},
                    "sexual_dysfunction": {
                        "genes": ["SLC6A4"],
                        "variants": ["L/L"],
                        "probability": 0.1,
                    },
                },
                "venlafaxine": {
                    "nausea": {
                        "genes": ["CYP2D6"],
                        "variants": ["poor_metabolizer"],
                        "probability": 0.3,
                    },
                    "hypertension": {
                        "genes": ["CYP2D6"],
                        "variants": ["poor_metabolizer"],
                        "probability": 0.15,
                    },
                    "headache": {"genes": [], "variants": [], "probability": 0.2},
                },
                "bupropion": {
                    "insomnia": {"genes": [], "variants": [], "probability": 0.2},
                    "headache": {"genes": [], "variants": [], "probability": 0.15},
                    "dry_mouth": {
                        "genes": ["CYP2B6"],
                        "variants": ["poor_metabolizer"],
                        "probability": 0.1,
                    },
                },
                "quetiapine": {
                    "sedation": {
                        "genes": ["CYP3A4"],
                        "variants": ["poor_metabolizer"],
                        "probability": 0.4,
                    },
                    "weight_gain": {
                        "genes": ["HTR2C"],
                        "variants": ["C/C"],
                        "probability": 0.3,
                    },
                    "dry_mouth": {"genes": [], "variants": [], "probability": 0.15},
                },
                "aripiprazole": {
                    "akathisia": {
                        "genes": ["DRD2"],
                        "variants": ["A/A"],
                        "probability": 0.2,
                    },
                    "nausea": {
                        "genes": ["CYP2D6"],
                        "variants": ["poor_metabolizer"],
                        "probability": 0.15,
                    },
                    "insomnia": {"genes": [], "variants": [], "probability": 0.1},
                },
                "risperidone": {
                    "weight_gain": {
                        "genes": ["HTR2C"],
                        "variants": ["C/C"],
                        "probability": 0.3,
                    },
                    "sedation": {"genes": [], "variants": [], "probability": 0.25},
                    "prolactin_elevation": {
                        "genes": ["DRD2"],
                        "variants": ["A/A"],
                        "probability": 0.4,
                    },
                },
                "olanzapine": {
                    "weight_gain": {
                        "genes": ["HTR2C"],
                        "variants": ["C/C"],
                        "probability": 0.4,
                    },
                    "sedation": {"genes": [], "variants": [], "probability": 0.3},
                    "metabolic_changes": {
                        "genes": ["MC4R"],
                        "variants": ["risk_allele"],
                        "probability": 0.25,
                    },
                },
                "lamotrigine": {
                    "headache": {"genes": [], "variants": [], "probability": 0.1},
                    "dizziness": {"genes": [], "variants": [], "probability": 0.1},
                    "rash": {
                        "genes": ["HLA-B"],
                        "variants": ["*1502"],
                        "probability": 0.05,
                    },
                },
                "valproate": {
                    "nausea": {"genes": [], "variants": [], "probability": 0.15},
                    "weight_gain": {"genes": [], "variants": [], "probability": 0.2},
                    "tremor": {
                        "genes": ["UGT1A4"],
                        "variants": ["poor_metabolizer"],
                        "probability": 0.1,
                    },
                },
                "lithium": {
                    "tremor": {"genes": [], "variants": [], "probability": 0.25},
                    "polyuria": {"genes": [], "variants": [], "probability": 0.2},
                    "weight_gain": {"genes": [], "variants": [], "probability": 0.15},
                },
            }

            # Get side effect profile for the medication
            if medication not in side_effect_profiles:
                return {
                    "patient_id": str(patient_id),
                    "medication": medication,
                    "side_effects": [],
                    "message": "No side effect data available for this medication",
                    "prediction_generated_at": datetime.now(UTC).isoformat(),
                }

            profile = side_effect_profiles[medication]

            # Get patient's genetic markers
            genetic_markers = patient_data.get("genetic_markers", {})

            # Predict side effects
            side_effects = []

            for effect, data in profile.items():
                # Start with base probability
                probability = data["probability"]

                # Adjust based on genetic markers
                for i, gene in enumerate(data["genes"]):
                    if gene in genetic_markers:
                        patient_variant = genetic_markers.get(gene)
                        target_variant = data["variants"][i] if i < len(data["variants"]) else None

                        if patient_variant == target_variant:
                            # Increase probability if genetic marker matches
                            probability += 0.2

                # Adjust based on patient characteristics
                patient_features = patient_data.get("patient_features", {})

                # Age adjustment
                age = patient_features.get("age", 0)
                if age > 65:
                    probability += 0.1

                # Weight adjustment for metabolic side effects
                if effect in ["weight_gain", "metabolic_changes"]:
                    weight = patient_features.get("weight", 0)
                    height = patient_features.get("height", 0)

                    if weight > 0 and height > 0:
                        # Calculate BMI
                        bmi = weight / ((height / 100) ** 2)

                        if bmi > 30:
                            probability += 0.1

                # Cap probability at 0.95
                probability = min(0.95, probability)

                # Add to side effects list
                side_effects.append(
                    {
                        "effect": effect,
                        "probability": probability,
                        "severity": "moderate" if probability > 0.3 else "mild",
                        "genetic_factors": [
                            gene for gene in data["genes"] if gene in genetic_markers
                        ],
                    }
                )

            # Sort by probability
            side_effects.sort(key=lambda x: x["probability"], reverse=True)

            return {
                "patient_id": str(patient_id),
                "medication": medication,
                "side_effects": side_effects,
                "high_risk_effects": [e for e in side_effects if e["probability"] > 0.3],
                "prediction_generated_at": datetime.now(UTC).isoformat(),
            }

        except Exception as e:
            logging.error(f"Error predicting side effects: {e!s}")
            raise ModelExecutionError(f"Failed to predict side effects: {e!s}")

    def get_model_info(self) -> dict[str, Any]:
        """
        Get information about the model.

        Returns:
            Dictionary containing model information
        """
        return {
            "model_type": "Pharmacogenomics and Treatment Response Model",
            "gene_markers": self.gene_markers,
            "medications": self.medications,
            "trained_medications": list(self.models.keys()) if self.models else [],
            "patient_features": self.patient_features,
            "timestamp": datetime.now(UTC).isoformat(),
        }
