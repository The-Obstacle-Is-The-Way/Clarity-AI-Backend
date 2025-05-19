"""
NOVAMIND Data Transformation Utility
===================================
Data anonymization and processing utilities for the NOVAMIND platform.
Implements HIPAA-compliant data transformation for research and analytics.
"""

import hashlib
import re
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd

# Removed unused import: from ..config import settings
# Corrected import path for EncryptionService
from app.infrastructure.security.encryption.base_encryption_service import (
    BaseEncryptionService as EncryptionService,
)


class DataAnonymizer:
    """
    HIPAA-compliant data anonymizer for patient data.
    Provides methods for anonymizing PHI for research and analytics.
    """

    def __init__(self, encryption_service: EncryptionService | None = None):
        """
        Initialize the data anonymizer.

        Args:
            encryption_service: Encryption service for hashing identifiers
        """
        if encryption_service:
            self.encryption_service = encryption_service
        else:
            # Create encryption service directly to avoid circular imports
            # Lazy-load the encryption service factory to avoid circular imports
            def get_encryption_service():
                test_key = "test_encryption_key_for_anonymizer_default"
                return EncryptionService(secret_key=test_key)

            self.encryption_service = get_encryption_service()

        # PHI field patterns for detection
        self.phi_patterns = {
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "ssn": r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",
            "phone": r"\b(\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
            "address": r"\b\d+\s+[A-Za-z0-9\s,]+\b(?:street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|parkway|pkwy|circle|cir|boulevard|blvd)\b",
            "dob": r"\b(0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])[-/](19|20)\d{2}\b",
            "name": r"\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b",
        }

    def anonymize_patient_id(self, patient_id: str, salt: bytes | None = None) -> str:
        """
        Create a consistent anonymized identifier for a patient.

        Args:
            patient_id: Original patient ID
            salt: Optional salt for hashing

        Returns:
            Anonymized patient ID
        """
        # Generate hash with salt
        hash_value, _ = self.encryption_service.generate_hash(patient_id, salt)

        # Return first 8 characters of hash as anonymized ID
        return hash_value[:8]

    def anonymize_date(
        self, date_value: str | datetime, shift_days: int | None = None
    ) -> str | datetime:
        """
        Anonymize a date by shifting it randomly but consistently.

        Args:
            date_value: Date to anonymize
            shift_days: Optional fixed number of days to shift

        Returns:
            Anonymized date in the same format as input
        """
        # Convert string to datetime if needed
        original_type = type(date_value)
        if isinstance(date_value, str):
            try:
                date_obj = datetime.strptime(date_value, "%Y-%m-%d")
            except ValueError:
                try:
                    date_obj = datetime.strptime(date_value, "%m/%d/%Y")
                except ValueError:
                    # If we can't parse the date, return as is
                    return date_value
        else:
            date_obj = date_value

        # Determine shift amount (use provided or generate based on date)
        if shift_days is None:
            # Generate a consistent shift based on the date itself using SHA-256
            date_str = date_obj.strftime("%Y%m%d")
            hash_obj = hashlib.sha256(date_str.encode())
            hash_int = int(
                hash_obj.hexdigest()[:8], 16
            )  # Use first 8 chars for reasonable integer
            shift_days = (hash_int % 30) - 15  # -15 to +14 days

        # Shift the date
        shifted_date = date_obj + timedelta(days=shift_days)

        # Return in original format
        if original_type is str:
            if "/" in date_value:
                return shifted_date.strftime("%m/%d/%Y")
            else:
                return shifted_date.strftime("%Y-%m-%d")
        else:
            return shifted_date

    def anonymize_text(self, text: str) -> str:
        """
        Anonymize free text by removing PHI.

        Args:
            text: Text to anonymize

        Returns:
            Anonymized text with PHI replaced
        """
        if not text:
            return ""

        anonymized = text

        # Replace each type of PHI
        for phi_type, pattern in self.phi_patterns.items():
            # Use the format expected by tests: [REDACTED TYPE]
            replacement = f"[REDACTED {phi_type.upper()}]"
            anonymized = re.sub(pattern, replacement, anonymized)

        return anonymized

    def anonymize_dict(
        self,
        data: dict[str, Any],
        phi_fields: list[str],
        id_fields: list[str] | None = None,
        date_fields: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Anonymize a dictionary of patient data.

        Args:
            data: Dictionary to anonymize
            phi_fields: Fields containing PHI to completely redact
            id_fields: Fields containing IDs to hash
            date_fields: Fields containing dates to shift

        Returns:
            Anonymized dictionary
        """
        if not data:
            return {}

        anonymized = {}
        id_fields = id_fields or []
        date_fields = date_fields or []

        for key, value in data.items():
            if key in phi_fields:
                # Completely redact PHI fields
                anonymized[key] = "[REDACTED]"
            elif key in id_fields and isinstance(value, str):
                # Hash ID fields
                anonymized[key] = self.anonymize_patient_id(value)
            elif key in date_fields:
                # Shift date fields
                anonymized[key] = self.anonymize_date(value)
            elif isinstance(value, dict):
                # Recursively anonymize nested dictionaries
                anonymized[key] = self.anonymize_dict(
                    value, phi_fields, id_fields, date_fields
                )
            elif isinstance(value, list):
                # Handle lists - anonymize dictionaries in lists
                anonymized[key] = [
                    (
                        self.anonymize_dict(item, phi_fields, id_fields, date_fields)
                        if isinstance(item, dict)
                        else item
                    )
                    for item in value
                ]
            elif isinstance(value, str):
                # Check if string contains PHI
                anonymized[key] = self.anonymize_text(value)
            else:
                # Keep other values as is
                anonymized[key] = value

        return anonymized


class DataNormalizer:
    """
    Data normalization utilities for ML preprocessing.
    Provides methods for standardizing and normalizing data.
    """

    @staticmethod
    def z_score_normalize(data: list[float] | np.ndarray) -> np.ndarray:
        """
        Normalize data using Z-score (mean=0, std=1).

        Args:
            data: Data to normalize

        Returns:
            Normalized data
        """
        data_array = np.array(data)
        mean = np.mean(data_array)
        std = np.std(data_array)

        # Avoid division by zero
        if std == 0:
            return np.zeros_like(data_array)

        return (data_array - mean) / std

    @staticmethod
    def min_max_normalize(
        data: list[float] | np.ndarray,
        feature_range: tuple[float, float] = (0, 1),
    ) -> np.ndarray:
        """
        Normalize data to a specific range.

        Args:
            data: Data to normalize
            feature_range: Target range (min, max)

        Returns:
            Normalized data
        """
        data_array = np.array(data)
        min_val = np.min(data_array)
        max_val = np.max(data_array)

        # Avoid division by zero
        if max_val == min_val:
            return np.full_like(data_array, feature_range[0])

        scaled = (data_array - min_val) / (max_val - min_val)
        return scaled * (feature_range[1] - feature_range[0]) + feature_range[0]

    @staticmethod
    def normalize_dataframe(
        df: pd.DataFrame,
        method: str = "z-score",
        columns: list[str] | None = None,
        feature_range: tuple[float, float] = (0, 1),
    ) -> pd.DataFrame:
        """
        Normalize selected columns in a DataFrame.

        Args:
            df: DataFrame to normalize
            method: Normalization method ('z-score' or 'min-max')
            columns: Columns to normalize (all numeric columns if None)
            feature_range: Target range for min-max normalization

        Returns:
            Normalized DataFrame
        """
        # Make a copy to avoid modifying the original
        normalized_df = df.copy()

        # Select columns to normalize
        if columns is None:
            columns = df.select_dtypes(include=np.number).columns.tolist()

        # Apply normalization to each column
        for col in columns:
            if col in normalized_df.columns and pd.api.types.is_numeric_dtype(
                normalized_df[col]
            ):
                if method == "z-score":
                    normalized_df[col] = DataNormalizer.z_score_normalize(
                        normalized_df[col].values
                    )
                elif method == "min-max":
                    normalized_df[col] = DataNormalizer.min_max_normalize(
                        normalized_df[col].values, feature_range
                    )

        return normalized_df


class MissingValueImputer:
    """
    Missing value imputation for clinical data.
    Provides methods for handling missing values in datasets.
    """

    @staticmethod
    def mean_imputation(data: list[float] | np.ndarray) -> np.ndarray:
        """
        Impute missing values with the mean.

        Args:
            data: Data with missing values (NaN)

        Returns:
            Data with missing values imputed
        """
        data_array = np.array(data)
        mean_value = np.nanmean(data_array)

        # Replace NaN with mean
        return np.where(np.isnan(data_array), mean_value, data_array)

    @staticmethod
    def median_imputation(data: list[float] | np.ndarray) -> np.ndarray:
        """
        Impute missing values with the median.

        Args:
            data: Data with missing values (NaN)

        Returns:
            Data with missing values imputed
        """
        data_array = np.array(data)
        median_value = np.nanmedian(data_array)

        # Replace NaN with median
        return np.where(np.isnan(data_array), median_value, data_array)

    @staticmethod
    def mode_imputation(data: list[Any] | np.ndarray) -> np.ndarray:
        """
        Impute missing values with the mode (most frequent value).

        Args:
            data: Data with missing values (NaN or None)

        Returns:
            Data with missing values imputed
        """
        data_array = np.array(data)

        # Find most frequent non-NaN value
        unique_values, counts = np.unique(
            data_array[~pd.isna(data_array)], return_counts=True
        )

        if len(counts) > 0:
            mode_value = unique_values[np.argmax(counts)]

            # Replace NaN with mode
            return np.where(pd.isna(data_array), mode_value, data_array)
        else:
            # If all values are NaN, return as is
            return data_array

    @staticmethod
    def impute_dataframe(
        df: pd.DataFrame,
        method: str = "mean",
        columns: list[str] | None = None,
        categorical_columns: list[str] | None = None,
    ) -> pd.DataFrame:
        """
        Impute missing values in a DataFrame.

        Args:
            df: DataFrame with missing values
            method: Imputation method ('mean', 'median', or 'mode')
            columns: Numeric columns to impute (all numeric columns if None)
            categorical_columns: Categorical columns to impute with mode

        Returns:
            DataFrame with missing values imputed
        """
        # Make a copy to avoid modifying the original
        imputed_df = df.copy()

        # Select numeric columns to impute
        if columns is None:
            columns = df.select_dtypes(include=np.number).columns.tolist()

        # Select categorical columns to impute
        if categorical_columns is None:
            categorical_columns = df.select_dtypes(exclude=np.number).columns.tolist()

        # Apply imputation to numeric columns
        for col in columns:
            if col in imputed_df.columns and pd.api.types.is_numeric_dtype(
                imputed_df[col]
            ):
                if method == "mean":
                    imputed_df[col] = MissingValueImputer.mean_imputation(
                        imputed_df[col].values
                    )
                elif method == "median":
                    imputed_df[col] = MissingValueImputer.median_imputation(
                        imputed_df[col].values
                    )
                elif method == "mode":
                    imputed_df[col] = MissingValueImputer.mode_imputation(
                        imputed_df[col].values
                    )

        # Apply mode imputation to categorical columns
        for col in categorical_columns:
            if col in imputed_df.columns and not pd.api.types.is_numeric_dtype(
                imputed_df[col]
            ):
                imputed_df[col] = MissingValueImputer.mode_imputation(
                    imputed_df[col].values
                )

        return imputed_df


class TimeSeriesProcessor:
    """
    Time series data processing for clinical data.
    Provides methods for preparing time series data for ML models.
    """

    @staticmethod
    def create_sequences(
        data: np.ndarray, sequence_length: int, target_column: int | None = None
    ) -> tuple[np.ndarray, np.ndarray | None]:
        """
        Create sequences for time series prediction.

        Args:
            data: Time series data (samples x features)
            sequence_length: Length of each sequence
            target_column: Index of target column to predict

        Returns:
            Tuple of (X_sequences, y_targets) if target_column provided,
            otherwise just X_sequences
        """
        X = []
        y = [] if target_column is not None else None

        for i in range(len(data) - sequence_length):
            # Extract sequence
            sequence = data[i : i + sequence_length]
            X.append(sequence)

            # Extract target if specified
            if target_column is not None:
                target = data[i + sequence_length, target_column]
                y.append(target)

        return np.array(X), np.array(y) if y else None

    @staticmethod
    def resample_time_series(
        df: pd.DataFrame,
        date_column: str,
        freq: str = "D",
        aggregation_dict: dict[str, str] | None = None,
    ) -> pd.DataFrame:
        """
        Resample time series data to a different frequency.

        Args:
            df: DataFrame with time series data
            date_column: Column containing dates
            freq: Target frequency ('D' for daily, 'W' for weekly, etc.)
            aggregation_dict: Dictionary mapping columns to aggregation methods

        Returns:
            Resampled DataFrame
        """
        # Ensure date column is datetime type
        df = df.copy()
        df[date_column] = pd.to_datetime(df[date_column])

        # Set date as index
        df = df.set_index(date_column)

        # Default aggregation is mean for numeric, first for others
        if aggregation_dict is None:
            aggregation_dict = {}
            for col in df.columns:
                if pd.api.types.is_numeric_dtype(df[col]):
                    aggregation_dict[col] = "mean"
                else:
                    aggregation_dict[col] = "first"

        # Resample and aggregate
        resampled = df.resample(freq).agg(aggregation_dict)

        # Reset index to make date a column again
        resampled = resampled.reset_index()

        return resampled

    @staticmethod
    def detect_anomalies(
        data: np.ndarray, window_size: int = 10, threshold: float = 3.0
    ) -> np.ndarray:
        """
        Detect anomalies in time series data using Z-score.

        Args:
            data: Time series data (1D array)
            window_size: Size of rolling window
            threshold: Z-score threshold for anomaly

        Returns:
            Boolean array indicating anomalies
        """
        anomalies = np.zeros(len(data), dtype=bool)

        # Calculate rolling mean and std
        for i in range(len(data) - window_size):
            window = data[i : i + window_size]
            window_mean = np.mean(window)
            window_std = np.std(window)

            # Avoid division by zero
            if window_std == 0:
                continue

            # Calculate Z-score for next point
            z_score = abs((data[i + window_size] - window_mean) / window_std)

            # Mark as anomaly if Z-score exceeds threshold
            if z_score > threshold:
                anomalies[i + window_size] = True

        return anomalies


class FeatureEngineer:
    """
    Feature engineering for ML models.
    Provides methods for creating and transforming features.
    """

    @staticmethod
    def create_polynomial_features(data: np.ndarray, degree: int = 2) -> np.ndarray:
        """
        Create polynomial features.

        Args:
            data: Input data (samples x features)
            degree: Polynomial degree

        Returns:
            Data with polynomial features
        """
        n_samples, n_features = data.shape
        poly_features = []

        # Add original features
        poly_features.append(data)

        # Add polynomial features
        for d in range(2, degree + 1):
            for i in range(n_features):
                poly_features.append(data[:, i : i + 1] ** d)

        # Add interaction terms
        for i in range(n_features):
            for j in range(i + 1, n_features):
                poly_features.append(data[:, i : i + 1] * data[:, j : j + 1])

        return np.hstack(poly_features)

    @staticmethod
    def create_lag_features(data: np.ndarray, lag_periods: list[int]) -> np.ndarray:
        """
        Create lag features for time series data.

        Args:
            data: Time series data (samples x features)
            lag_periods: List of lag periods to create

        Returns:
            Data with lag features
        """
        n_samples, n_features = data.shape
        all_features = [data]

        for lag in lag_periods:
            lag_data = np.zeros_like(data)
            lag_data[lag:] = data[:-lag]
            all_features.append(lag_data)

        return np.hstack(all_features)

    @staticmethod
    def create_rolling_features(
        data: np.ndarray,
        window_sizes: list[int],
        functions: list[Callable] = [np.mean, np.std, np.min, np.max],
    ) -> np.ndarray:
        """
        Create rolling window features for time series data.

        Args:
            data: Time series data (samples x features)
            window_sizes: List of window sizes
            functions: List of aggregation functions

        Returns:
            Data with rolling features
        """
        n_samples, n_features = data.shape
        all_features = [data]

        for window in window_sizes:
            for func in functions:
                rolling_features = np.zeros_like(data)

                for i in range(window, n_samples):
                    for j in range(n_features):
                        rolling_features[i, j] = func(data[i - window : i, j])

                all_features.append(rolling_features)

        return np.hstack(all_features)

    @staticmethod
    def one_hot_encode(
        data: np.ndarray, categories: list[list[Any]] | None = None
    ) -> np.ndarray:
        """
        One-hot encode categorical features.

        Args:
            data: Categorical data (samples x features)
            categories: List of categories for each feature

        Returns:
            One-hot encoded data
        """
        n_samples, n_features = data.shape
        encoded_features = []

        for j in range(n_features):
            feature = data[:, j]

            # Determine categories
            if categories is not None and j < len(categories):
                cats = categories[j]
            else:
                cats = np.unique(feature)

            # Create one-hot encoding
            n_cats = len(cats)
            cat_dict = {cat: i for i, cat in enumerate(cats)}

            one_hot = np.zeros((n_samples, n_cats))
            for i, val in enumerate(feature):
                if val in cat_dict:
                    one_hot[i, cat_dict[val]] = 1

            encoded_features.append(one_hot)

        return np.hstack(encoded_features)


# Create default instances
default_anonymizer = DataAnonymizer()
default_normalizer = DataNormalizer()
default_imputer = MissingValueImputer()
default_ts_processor = TimeSeriesProcessor()
default_feature_engineer = FeatureEngineer()
