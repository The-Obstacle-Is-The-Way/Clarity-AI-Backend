"""
Serialization utilities for ML models in the NOVAMIND system.

This module provides standardized methods for saving and loading machine learning
models used in the Digital Twin system, ensuring consistent serialization across
all ML services and proper handling of model artifacts.
"""

import json
import os
import pickle
from datetime import datetime
from typing import Any

import joblib
import torch
import xgboost as xgb

from app.domain.utils.datetime_utils import UTC
from app.infrastructure.logging.logger import get_logger

logger = get_logger(__name__)


class ModelSerializer:
    """
    Utility class for serializing and deserializing ML models.

    This class provides standardized methods for saving and loading different
    types of machine learning models, including scikit-learn, XGBoost, PyTorch,
    and custom models, ensuring consistent serialization across all ML services.
    """

    @staticmethod
    def save_model(
        model: Any,
        model_path: str,
        model_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """
        Save a model to disk with metadata.

        Args:
            model: The model object to save
            model_path: Path where the model should be saved
            model_type: Type of the model (e.g., 'sklearn', 'pytorch', 'xgboost')
            metadata: Optional metadata to save with the model

        Returns:
            The path where the model was saved

        Raises:
            ValueError: If the model type is not supported
            IOError: If the model cannot be saved to the specified path
        """
        os.makedirs(os.path.dirname(model_path), exist_ok=True)

        # Save metadata
        metadata = metadata or {}
        metadata.update(
            {
                "model_type": model_type,
                "saved_at": datetime.now(UTC).isoformat(),
                "version": metadata.get("version", "1.0.0"),
            }
        )

        metadata_path = f"{model_path}.meta.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        # Save model based on type
        try:
            if model_type == "sklearn":
                joblib.dump(model, model_path)
            elif model_type == "xgboost":
                if isinstance(model, xgb.Booster):
                    model.save_model(model_path)
                else:
                    joblib.dump(model, model_path)
            elif model_type == "pytorch":
                torch.save(model.state_dict(), model_path)
            elif model_type == "custom":
                with open(model_path, "wb") as f:
                    pickle.dump(model, f)
            else:
                raise ValueError(f"Unsupported model type: {model_type}")

            logger.info(f"Successfully saved {model_type} model to {model_path}")
            return model_path

        except Exception as e:
            logger.error(f"Failed to save model: {e!s}")
            raise

    @staticmethod
    def load_model(
        model_path: str,
        model_class: Any | None = None,
        custom_load_fn: callable | None = None,
    ) -> tuple:
        """
        Load a model from disk with its metadata.

        Args:
            model_path: Path to the saved model
            model_class: For PyTorch models, the model class to instantiate
            custom_load_fn: Optional custom function to load the model

        Returns:
            A tuple of (model, metadata)

        Raises:
            FileNotFoundError: If the model file cannot be found
            ValueError: If the model type is not supported or the model is corrupted
        """
        # Load metadata
        metadata_path = f"{model_path}.meta.json"
        try:
            with open(metadata_path) as f:
                metadata = json.load(f)
        except FileNotFoundError:
            logger.warning(f"No metadata found for model at {model_path}")
            metadata = {"model_type": "unknown"}

        model_type = metadata.get("model_type", "unknown")

        # Load model based on type
        try:
            if custom_load_fn is not None:
                model = custom_load_fn(model_path)
            elif model_type == "sklearn":
                model = joblib.load(model_path)
            elif model_type == "xgboost":
                # Try to load as a Booster first
                try:
                    model = xgb.Booster()
                    model.load_model(model_path)
                except:
                    # Fall back to joblib if it's a scikit-learn API model
                    model = joblib.load(model_path)
            elif model_type == "pytorch":
                if model_class is None:
                    raise ValueError("model_class must be provided for PyTorch models")
                model = model_class()
                model.load_state_dict(torch.load(model_path))
                model.eval()  # Set to evaluation mode
            elif model_type == "custom" or model_type == "unknown":
                with open(model_path, "rb") as f:
                    model = pickle.load(f)
            else:
                raise ValueError(f"Unsupported model type: {model_type}")

            logger.info(f"Successfully loaded {model_type} model from {model_path}")
            return model, metadata

        except Exception as e:
            logger.error(f"Failed to load model: {e!s}")
            raise

    @staticmethod
    def save_ensemble(
        models: dict[str, Any],
        base_path: str,
        model_types: dict[str, str],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        """
        Save an ensemble of models to disk.

        Args:
            models: Dictionary mapping model names to model objects
            base_path: Base path where models should be saved
            model_types: Dictionary mapping model names to model types
            metadata: Optional metadata to save with the ensemble

        Returns:
            Dictionary mapping model names to saved paths

        Raises:
            ValueError: If any model type is not supported
            IOError: If any model cannot be saved
        """
        os.makedirs(base_path, exist_ok=True)

        # Save ensemble metadata
        ensemble_metadata = metadata or {}
        ensemble_metadata.update(
            {
                "ensemble_size": len(models),
                "model_names": list(models.keys()),
                "saved_at": datetime.now(UTC).isoformat(),
                "version": metadata.get("version", "1.0.0"),
            }
        )

        ensemble_meta_path = os.path.join(base_path, "ensemble.meta.json")
        with open(ensemble_meta_path, "w") as f:
            json.dump(ensemble_metadata, f, indent=2)

        # Save individual models
        model_paths = {}
        for model_name, model in models.items():
            model_type = model_types.get(model_name, "custom")
            model_path = os.path.join(base_path, f"{model_name}.model")

            # Add model-specific metadata
            model_metadata = {
                "ensemble_name": metadata.get("name", "ensemble"),
                "model_name": model_name,
                "version": metadata.get("version", "1.0.0"),
            }

            try:
                saved_path = ModelSerializer.save_model(
                    model, model_path, model_type, model_metadata
                )
                model_paths[model_name] = saved_path
            except Exception as e:
                logger.error(f"Failed to save model {model_name}: {e!s}")
                raise

        logger.info(f"Successfully saved ensemble with {len(models)} models to {base_path}")
        return model_paths

    @staticmethod
    def load_ensemble(
        base_path: str,
        model_classes: dict[str, Any] | None = None,
        custom_load_fns: dict[str, callable] | None = None,
    ) -> tuple:
        """
        Load an ensemble of models from disk.

        Args:
            base_path: Base path where models are saved
            model_classes: Dictionary mapping model names to model classes (for PyTorch)
            custom_load_fns: Dictionary mapping model names to custom load functions

        Returns:
            A tuple of (models_dict, ensemble_metadata)

        Raises:
            FileNotFoundError: If the ensemble metadata or any model file cannot be found
            ValueError: If any model type is not supported or any model is corrupted
        """
        # Load ensemble metadata
        ensemble_meta_path = os.path.join(base_path, "ensemble.meta.json")
        try:
            with open(ensemble_meta_path) as f:
                ensemble_metadata = json.load(f)
        except FileNotFoundError:
            logger.warning(f"No ensemble metadata found at {ensemble_meta_path}")
            # Try to find model files directly
            model_files = [
                f
                for f in os.listdir(base_path)
                if f.endswith(".model") and not f.startswith("ensemble")
            ]
            ensemble_metadata = {
                "model_names": [os.path.splitext(f)[0] for f in model_files],
                "ensemble_size": len(model_files),
            }

        model_names = ensemble_metadata.get("model_names", [])
        if not model_names:
            raise ValueError(f"No models found in ensemble at {base_path}")

        # Load individual models
        models = {}
        model_classes = model_classes or {}
        custom_load_fns = custom_load_fns or {}

        for model_name in model_names:
            model_path = os.path.join(base_path, f"{model_name}.model")

            try:
                model_class = model_classes.get(model_name)
                custom_load_fn = custom_load_fns.get(model_name)

                model, _ = ModelSerializer.load_model(model_path, model_class, custom_load_fn)
                models[model_name] = model
            except Exception as e:
                logger.error(f"Failed to load model {model_name}: {e!s}")
                raise

        logger.info(f"Successfully loaded ensemble with {len(models)} models from {base_path}")
        return models, ensemble_metadata
