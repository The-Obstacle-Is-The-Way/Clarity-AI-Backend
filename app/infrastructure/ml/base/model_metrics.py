"""
Standardized metrics calculation for ML models in the NOVAMIND system.

This module provides utilities for calculating and tracking performance metrics
for machine learning models used in the Digital Twin system, ensuring consistent
evaluation across all ML services.
"""

from typing import Any

import numpy as np
from sklearn import metrics


class ModelMetrics:
    """
    Utility class for calculating and tracking model performance metrics.

    This class provides standardized methods for calculating common performance
    metrics for different types of machine learning models, including classification,
    regression, and time series forecasting.
    """

    @staticmethod
    def calculate_classification_metrics(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_prob: np.ndarray | None = None,
        average: str = "weighted",
    ) -> dict[str, float]:
        """
        Calculate standard metrics for classification models.

        Args:
            y_true: Ground truth labels
            y_pred: Predicted labels
            y_prob: Predicted probabilities (optional, for ROC AUC)
            average: Method for averaging metrics in multiclass settings
                     (e.g., 'micro', 'macro', 'weighted')

        Returns:
            Dictionary of performance metrics
        """
        results = {
            "accuracy": float(metrics.accuracy_score(y_true, y_pred)),
            "precision": float(
                metrics.precision_score(
                    y_true, y_pred, average=average, zero_division=0
                )
            ),
            "recall": float(
                metrics.recall_score(y_true, y_pred, average=average, zero_division=0)
            ),
            "f1_score": float(
                metrics.f1_score(y_true, y_pred, average=average, zero_division=0)
            ),
        }

        # Add confusion matrix
        cm = metrics.confusion_matrix(y_true, y_pred)
        results["confusion_matrix"] = cm.tolist()

        # Add ROC AUC if probabilities are provided
        if y_prob is not None:
            # For binary classification
            if y_prob.shape[1] == 2:
                results["roc_auc"] = float(metrics.roc_auc_score(y_true, y_prob[:, 1]))
            # For multiclass
            else:
                try:
                    results["roc_auc"] = float(
                        metrics.roc_auc_score(
                            y_true, y_prob, multi_class="ovr", average=average
                        )
                    )
                except Exception:
                    # If ROC AUC cannot be calculated (e.g., missing classes)
                    results["roc_auc"] = None

        return results

    @staticmethod
    def calculate_regression_metrics(
        y_true: np.ndarray, y_pred: np.ndarray
    ) -> dict[str, float]:
        """
        Calculate standard metrics for regression models.

        Args:
            y_true: Ground truth values
            y_pred: Predicted values

        Returns:
            Dictionary of performance metrics
        """
        return {
            "mean_absolute_error": float(metrics.mean_absolute_error(y_true, y_pred)),
            "mean_squared_error": float(metrics.mean_squared_error(y_true, y_pred)),
            "root_mean_squared_error": float(
                np.sqrt(metrics.mean_squared_error(y_true, y_pred))
            ),
            "r2_score": float(metrics.r2_score(y_true, y_pred)),
            "explained_variance": float(
                metrics.explained_variance_score(y_true, y_pred)
            ),
        }

    @staticmethod
    def calculate_time_series_metrics(
        y_true: np.ndarray, y_pred: np.ndarray, multivariate: bool = False
    ) -> dict[str, float]:
        """
        Calculate metrics specifically for time series forecasting models.

        Args:
            y_true: Ground truth time series values
            y_pred: Predicted time series values
            multivariate: Whether the time series is multivariate

        Returns:
            Dictionary of performance metrics
        """
        # Start with standard regression metrics
        results = ModelMetrics.calculate_regression_metrics(y_true, y_pred)

        # Add time series specific metrics
        if not multivariate:
            # For univariate time series
            results["mean_absolute_percentage_error"] = float(
                np.mean(np.abs((y_true - y_pred) / np.maximum(np.abs(y_true), 1e-10)))
                * 100
            )

            # Symmetric Mean Absolute Percentage Error (handles zero values better)
            denominator = np.maximum(np.abs(y_true) + np.abs(y_pred), 1e-10)
            results["symmetric_mape"] = float(
                np.mean(2.0 * np.abs(y_true - y_pred) / denominator) * 100
            )
        else:
            # For multivariate time series, calculate metrics for each variable
            # and average them
            n_variables = y_true.shape[1]
            mape_values = []
            smape_values = []

            for i in range(n_variables):
                y_true_var = y_true[:, i]
                y_pred_var = y_pred[:, i]

                # MAPE
                mape = (
                    np.mean(
                        np.abs(
                            (y_true_var - y_pred_var)
                            / np.maximum(np.abs(y_true_var), 1e-10)
                        )
                    )
                    * 100
                )
                mape_values.append(mape)

                # SMAPE
                denominator = np.maximum(np.abs(y_true_var) + np.abs(y_pred_var), 1e-10)
                smape = (
                    np.mean(2.0 * np.abs(y_true_var - y_pred_var) / denominator) * 100
                )
                smape_values.append(smape)

            results["mean_absolute_percentage_error"] = float(np.mean(mape_values))
            results["symmetric_mape"] = float(np.mean(smape_values))

        return results

    @staticmethod
    def calculate_pharmacogenomics_metrics(
        y_true: np.ndarray, y_pred: np.ndarray, medication_classes: list[str]
    ) -> dict[str, Any]:
        """
        Calculate metrics specifically for pharmacogenomics models.

        Args:
            y_true: Ground truth medication response values
            y_pred: Predicted medication response values
            medication_classes: List of medication class names

        Returns:
            Dictionary of performance metrics
        """
        # Overall metrics
        overall_metrics = ModelMetrics.calculate_classification_metrics(
            y_true.flatten(), y_pred.flatten()
        )

        # Per-medication class metrics
        class_metrics = {}
        for i, medication_class in enumerate(medication_classes):
            class_metrics[medication_class] = (
                ModelMetrics.calculate_classification_metrics(
                    y_true[:, i], y_pred[:, i]
                )
            )

        return {"overall": overall_metrics, "per_medication_class": class_metrics}

    @staticmethod
    def calculate_biometric_correlation_metrics(
        true_correlations: np.ndarray,
        predicted_correlations: np.ndarray,
        biometric_features: list[str],
        mental_health_indicators: list[str],
    ) -> dict[str, Any]:
        """
        Calculate metrics for biometric correlation models.

        Args:
            true_correlations: Ground truth correlation values
            predicted_correlations: Predicted correlation values
            biometric_features: List of biometric feature names
            mental_health_indicators: List of mental health indicator names

        Returns:
            Dictionary of performance metrics
        """
        # Overall regression metrics
        overall_metrics = ModelMetrics.calculate_regression_metrics(
            true_correlations.flatten(), predicted_correlations.flatten()
        )

        # Feature-specific metrics
        feature_metrics = {}
        for i, feature in enumerate(biometric_features):
            feature_metrics[feature] = {}
            for j, indicator in enumerate(mental_health_indicators):
                feature_metrics[feature][indicator] = {
                    "mae": float(
                        metrics.mean_absolute_error(
                            true_correlations[i, j], predicted_correlations[i, j]
                        )
                    ),
                    "rmse": float(
                        np.sqrt(
                            metrics.mean_squared_error(
                                true_correlations[i, j], predicted_correlations[i, j]
                            )
                        )
                    ),
                }

        return {"overall": overall_metrics, "per_feature": feature_metrics}
