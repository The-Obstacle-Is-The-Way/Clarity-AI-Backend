"""
Neurotransmitter effect models for the Temporal Neurotransmitter System.

This module defines the data structures for representing neurotransmitter effects
and their clinical significance.
"""
from datetime import datetime
from typing import Any

from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    ClinicalSignificance,
    Neurotransmitter,
)


class NeurotransmitterEffect:
    """
    Model for representing the effects of a neurotransmitter on a brain region.

    This class captures statistical and clinical measures of neurotransmitter effects,
    including effect size, confidence intervals, statistical significance, and
    potential clinical implications.
    """

    def __init__(
        self,
        neurotransmitter: Neurotransmitter,
        effect_size: float,
        confidence_interval: tuple[float, float],
        p_value: float,
        sample_size: int,
        clinical_significance: ClinicalSignificance,
        brain_region: BrainRegion | None = None,
        time_series_data: list[tuple[datetime, float]] | None = None,
        baseline_period: tuple[datetime, datetime] | None = None,
        comparison_period: tuple[datetime, datetime] | None = None,
    ):
        """
        Initialize a new neurotransmitter effect.

        Args:
            neurotransmitter: The neurotransmitter being analyzed
            effect_size: Magnitude of effect (Cohen's d)
            confidence_interval: Lower and upper bounds of the effect size
            p_value: Statistical p-value of the effect
            sample_size: Number of data points included in analysis
            clinical_significance: Clinical significance classification
            brain_region: Brain region where the effect occurs
            time_series_data: Time series data for the neurotransmitter levels
            baseline_period: Period defining the baseline for comparison
            comparison_period: Period to compare against the baseline
        """
        # Validate inputs
        if not (0 <= p_value <= 1):
            raise ValueError(f"p_value must be between 0 and 1, got {p_value}")

        if confidence_interval[0] > confidence_interval[1]:
            raise ValueError(
                f"Confidence interval lower bound must be less than upper bound, "
                f"got {confidence_interval}"
            )

        self.neurotransmitter = neurotransmitter
        self.effect_size = effect_size
        self.p_value = p_value
        self.confidence_interval = confidence_interval
        self.sample_size = sample_size
        self.clinical_significance = clinical_significance
        self.brain_region = brain_region
        self.time_series_data = time_series_data or []
        self.baseline_period = baseline_period
        self.comparison_period = comparison_period

    @property
    def is_statistically_significant(self) -> bool:
        """Whether the effect is statistically significant (p < 0.05)."""
        return bool(self.p_value < 0.05)

    @property
    def precision(self) -> float:
        """
        The precision of the effect measurement.

        Calculated as 1 / (confidence interval width).
        """
        ci_width = self.confidence_interval[1] - self.confidence_interval[0]
        return 1.0 / ci_width if ci_width > 0 else float("inf")

    @property
    def effect_magnitude(self) -> str:
        """
        The magnitude category of the effect.

        Returns 'large', 'medium', 'small', or 'negligible' based on Cohen's d thresholds.
        """
        abs_effect = abs(self.effect_size)

        if abs_effect >= 0.8:
            return "large"
        elif abs_effect >= 0.5:
            return "medium"
        elif abs_effect >= 0.2:
            return "small"
        else:
            return "negligible"

    @property
    def direction(self) -> str:
        """The direction of the effect ('increase', 'decrease', or 'no change')."""
        if self.effect_size > 0.1:
            return "increase"
        elif self.effect_size < -0.1:
            return "decrease"
        else:
            return "no change"

    def get_relative_change(self) -> float:
        """
        Calculate relative change in neurotransmitter levels.

        Returns:
            Relative change as a percentage
        """
        if not self.time_series_data or len(self.time_series_data) < 2:
            return 0.0

        # Get first and last values
        first_value = self.time_series_data[0][1]
        last_value = self.time_series_data[-1][1]

        # Avoid division by zero
        if first_value == 0:
            return 0.0 if last_value == 0 else 1.0

        return (last_value - first_value) / first_value

    def get_trend_direction(self) -> str:
        """
        Get trend direction (increasing, decreasing, stable).

        Returns:
            String describing the trend direction
        """
        relative_change = self.get_relative_change()

        if relative_change > 0.1:
            return "increasing"
        elif relative_change < -0.1:
            return "decreasing"
        else:
            return "stable"

    @classmethod
    def create(
        cls,
        neurotransmitter: Neurotransmitter,
        raw_data: list[float],
        baseline_data: list[float],
        clinical_significance: ClinicalSignificance,
    ) -> "NeurotransmitterEffect":
        """
        Factory method to create an effect from raw measurement data.

        Automatically calculates effect size, p-value, and confidence interval.

        Args:
            neurotransmitter: The neurotransmitter being measured
            raw_data: The intervention measurements
            baseline_data: The baseline measurements
            clinical_significance: Clinician-assessed significance

        Returns:
            A new NeurotransmitterEffect instance
        """
        # Import here to avoid circular imports
        import numpy as np
        from scipy import stats

        # Calculate effect size (Cohen's d)
        mean1 = np.mean(raw_data)
        mean2 = np.mean(baseline_data)
        std1 = np.std(raw_data, ddof=1)
        std2 = np.std(baseline_data, ddof=1)

        # Pooled standard deviation
        pooled_std = np.sqrt(
            ((len(raw_data) - 1) * std1**2 + (len(baseline_data) - 1) * std2**2)
            / (len(raw_data) + len(baseline_data) - 2)
        )

        # Effect size
        effect_size = (mean1 - mean2) / pooled_std if pooled_std > 0 else 0

        # Calculate p-value using t-test
        t_stat, p_value = stats.ttest_ind(raw_data, baseline_data, equal_var=False)

        # Calculate confidence interval for effect size
        # Using approximation from Hedges & Olkin
        se = np.sqrt(
            (len(raw_data) + len(baseline_data)) / (len(raw_data) * len(baseline_data))
            + effect_size**2 / (2 * (len(raw_data) + len(baseline_data)))
        )

        ci_lower = effect_size - 1.96 * se
        ci_upper = effect_size + 1.96 * se

        return cls(
            neurotransmitter=neurotransmitter,
            effect_size=effect_size,
            confidence_interval=(ci_lower, ci_upper),
            p_value=p_value,
            sample_size=len(raw_data) + len(baseline_data),
            clinical_significance=clinical_significance,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert effect to dictionary for serialization.

        Returns:
            Dictionary representation of the effect
        """
        result = {
            "neurotransmitter": self.neurotransmitter.value,
            "effect_size": self.effect_size,
            "p_value": self.p_value,
            "confidence_interval": self.confidence_interval,
            "sample_size": self.sample_size,
            "is_statistically_significant": self.is_statistically_significant,
            "clinical_significance": self.clinical_significance.value,
            "effect_magnitude": self.effect_magnitude,
            "direction": self.direction,
            "trend_direction": self.get_trend_direction(),
        }

        if self.brain_region:
            result["brain_region"] = self.brain_region.value

        # Add time series data if available
        if self.time_series_data:
            result["time_series_data"] = [
                {"timestamp": ts.isoformat(), "value": value}
                for ts, value in self.time_series_data
            ]

        # Add comparison periods if available
        if self.baseline_period and self.comparison_period:
            result["comparison_periods"] = {
                "baseline": {
                    "start": self.baseline_period[0].isoformat(),
                    "end": self.baseline_period[1].isoformat(),
                },
                "comparison": {
                    "start": self.comparison_period[0].isoformat(),
                    "end": self.comparison_period[1].isoformat(),
                },
            }

        return result

    def to_visualization_data(self) -> dict[str, Any]:
        """
        Convert to a format suitable for visualization.

        Returns:
            Dictionary with visualization-friendly data
        """
        return {
            "neurotransmitter": self.neurotransmitter.value.lower(),
            "effect_size": self.effect_size,
            "confidence_interval": self.confidence_interval,
            "p_value": self.p_value,
            "is_significant": self.is_statistically_significant,
            "effect_magnitude": self.effect_magnitude,
            "direction": self.direction,
            "clinical_significance": self.clinical_significance.value.lower(),
            "sample_size": self.sample_size,
        }
