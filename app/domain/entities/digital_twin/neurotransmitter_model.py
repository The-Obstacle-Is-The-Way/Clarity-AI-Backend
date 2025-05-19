"""
Models for the Digital Twin neurotransmitter simulation.

This module implements models for simulating neurotransmitter levels
and their effects on mental health conditions.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import random

from app.domain.entities.digital_twin.digital_twin import DigitalTwin
from app.domain.entities.medication import Medication


@dataclass
class NeurotransmitterTwinModel:
    """
    Model for simulating neurotransmitter levels in the digital twin.

    This model tracks current neurotransmitter levels and simulates
    how they are affected by medications, stress, and other factors.
    """

    digital_twin: DigitalTwin
    current_serotonin: float = field(init=False)
    current_dopamine: float = field(init=False)
    current_gaba: float = field(init=False)
    current_norepinephrine: float = field(init=False)

    def __post_init__(self):
        """Initialize the current neurotransmitter levels from baseline values."""
        self.reset_to_baseline()

    def reset_to_baseline(self):
        """Reset all neurotransmitters to the baseline values from the digital twin."""
        self.current_serotonin = self.digital_twin.baseline_serotonin
        self.current_dopamine = self.digital_twin.baseline_dopamine
        self.current_gaba = self.digital_twin.baseline_gaba
        self.current_norepinephrine = self.digital_twin.baseline_norepinephrine

    def simulate_medication_effect(self, medication: Medication, days: int = 28):
        """
        Simulate the effect of a medication on neurotransmitter levels.

        Args:
            medication: The medication to simulate
            days: Number of days to simulate (default 28)
        """
        # Medication class effects on neurotransmitters
        med_class = medication.medication_class.upper()

        # Apply medication effects based on class
        if med_class == "SSRI":
            # Selective Serotonin Reuptake Inhibitors - increase serotonin
            self.current_serotonin *= (
                1 + 0.05 * days * self.digital_twin.medication_sensitivity
            )

        elif med_class == "SNRI":
            # Serotonin-Norepinephrine Reuptake Inhibitors - increase both
            self.current_serotonin *= (
                1 + 0.03 * days * self.digital_twin.medication_sensitivity
            )
            self.current_norepinephrine *= (
                1 + 0.04 * days * self.digital_twin.medication_sensitivity
            )

        elif med_class == "NDRI":
            # Norepinephrine-Dopamine Reuptake Inhibitors - increase both
            self.current_norepinephrine *= (
                1 + 0.04 * days * self.digital_twin.medication_sensitivity
            )
            self.current_dopamine *= (
                1 + 0.04 * days * self.digital_twin.medication_sensitivity
            )

        elif med_class == "MAOI":
            # Monoamine Oxidase Inhibitors - increase all
            self.current_serotonin *= (
                1 + 0.02 * days * self.digital_twin.medication_sensitivity
            )
            self.current_dopamine *= (
                1 + 0.02 * days * self.digital_twin.medication_sensitivity
            )
            self.current_norepinephrine *= (
                1 + 0.02 * days * self.digital_twin.medication_sensitivity
            )

        elif med_class == "TCA":
            # Tricyclic Antidepressants - complex effects
            self.current_serotonin *= (
                1 + 0.02 * days * self.digital_twin.medication_sensitivity
            )
            self.current_norepinephrine *= (
                1 + 0.03 * days * self.digital_twin.medication_sensitivity
            )

        elif med_class == "BENZODIAZEPINE":
            # Increase GABA
            self.current_gaba *= (
                1 + 0.05 * days * self.digital_twin.medication_sensitivity
            )

    def simulate_stress(self, stress_level: float, days: int = 1):
        """
        Simulate the effect of stress on neurotransmitter levels.

        Args:
            stress_level: Stress level from 0 (none) to 1 (extreme)
            days: Number of days to simulate (default 1)
        """
        # Stress typically decreases serotonin and dopamine
        stress_factor = (
            stress_level * self.digital_twin.cortisol_sensitivity * days * 0.05
        )

        self.current_serotonin *= 1 - stress_factor
        self.current_dopamine *= 1 - stress_factor

        # Stress can initially increase norepinephrine, then deplete it
        if days <= 3:
            self.current_norepinephrine *= 1 + stress_factor
        else:
            self.current_norepinephrine *= 1 - stress_factor * 0.5


@dataclass
class MentalStateModel:
    """
    Model for simulating mental state based on neurotransmitter levels.

    This model calculates depression and anxiety scores based on the
    current neurotransmitter levels from the NeurotransmitterTwinModel.
    """

    neurotransmitter_model: NeurotransmitterTwinModel
    depression_score: float = field(init=False)
    anxiety_score: float = field(init=False)

    def __post_init__(self):
        """Initialize the mental state scores."""
        self.update_scores()

    def update_scores(self):
        """Update depression and anxiety scores based on current neurotransmitter levels."""
        self.depression_score = self._calculate_depression_score()
        self.anxiety_score = self._calculate_anxiety_score()

    def _calculate_depression_score(self) -> float:
        """
        Calculate depression score based on neurotransmitter levels.

        Returns:
            float: Depression score from 0-100, where higher means more depressed
        """
        # Formula based on simplified neurotransmitter theory
        nm = self.neurotransmitter_model

        # Depression is associated with low serotonin and dopamine
        serotonin_factor = 50 * (
            2 - nm.current_serotonin
        )  # Higher when serotonin is lower
        dopamine_factor = 30 * (
            2 - nm.current_dopamine
        )  # Higher when dopamine is lower
        norepinephrine_factor = 20 * (2 - nm.current_norepinephrine)

        score = (serotonin_factor + dopamine_factor + norepinephrine_factor) / 3

        # Add some randomness to represent natural variation
        score += random.uniform(-5, 5)

        # Clamp between 0-100
        return max(0, min(100, score))

    def _calculate_anxiety_score(self) -> float:
        """
        Calculate anxiety score based on neurotransmitter levels.

        Returns:
            float: Anxiety score from 0-100, where higher means more anxious
        """
        # Formula based on simplified neurotransmitter theory
        nm = self.neurotransmitter_model

        # Anxiety is associated with low GABA and serotonin, high norepinephrine
        gaba_factor = 40 * (2 - nm.current_gaba)  # Higher when GABA is lower
        serotonin_factor = 30 * (
            2 - nm.current_serotonin
        )  # Higher when serotonin is lower
        norepinephrine_factor = 30 * (
            nm.current_norepinephrine
        )  # Higher when norepinephrine is higher

        score = (gaba_factor + serotonin_factor + norepinephrine_factor) / 3

        # Add some randomness to represent natural variation
        score += random.uniform(-5, 5)

        # Clamp between 0-100
        return max(0, min(100, score))


@dataclass
class MedicationResponseModel:
    """
    Model for predicting a patient's response to medication.

    This model uses the digital twin to predict how a patient
    would respond to a specific medication.
    """

    neurotransmitter_model: NeurotransmitterTwinModel

    def predict_response(
        self, medication: Medication, days: int = 28
    ) -> Dict[str, float]:
        """
        Predict how the patient would respond to a medication.

        Args:
            medication: The medication to simulate
            days: Number of days to simulate (default 28)

        Returns:
            Dict with predicted response metrics
        """
        # Create a copy of the current state
        original_serotonin = self.neurotransmitter_model.current_serotonin
        original_dopamine = self.neurotransmitter_model.current_dopamine
        original_gaba = self.neurotransmitter_model.current_gaba
        original_norepinephrine = self.neurotransmitter_model.current_norepinephrine

        # Simulate medication effect
        self.neurotransmitter_model.simulate_medication_effect(medication, days)

        # Create mental state model to calculate scores
        mental_state = MentalStateModel(
            neurotransmitter_model=self.neurotransmitter_model
        )

        # Get predicted scores
        pred_depression = mental_state.depression_score
        pred_anxiety = mental_state.anxiety_score

        # Calculate change metric (improvement from 0-100)
        depression_improvement = max(0, 50 - pred_depression / 2)  # Lower is better
        anxiety_improvement = max(0, 50 - pred_anxiety / 2)  # Lower is better

        # Add expected side effects based on medication class
        side_effect_risk = self._calculate_side_effect_risk(medication)

        # Restore original state
        self.neurotransmitter_model.current_serotonin = original_serotonin
        self.neurotransmitter_model.current_dopamine = original_dopamine
        self.neurotransmitter_model.current_gaba = original_gaba
        self.neurotransmitter_model.current_norepinephrine = original_norepinephrine

        return {
            "depression_improvement": depression_improvement,
            "anxiety_improvement": anxiety_improvement,
            "side_effect_risk": side_effect_risk,
            "overall_benefit": (depression_improvement + anxiety_improvement) / 2
            - side_effect_risk * 0.5,
        }

    def _calculate_side_effect_risk(self, medication: Medication) -> float:
        """
        Calculate risk of side effects for a medication.

        Args:
            medication: The medication to evaluate

        Returns:
            float: Side effect risk from 0-100
        """
        med_class = medication.medication_class.upper()

        # Base risk by medication class (simplified)
        base_risk = {
            "SSRI": 30,
            "SNRI": 35,
            "NDRI": 40,
            "MAOI": 70,
            "TCA": 60,
            "BENZODIAZEPINE": 50,
        }.get(med_class, 40)

        # Adjust for sensitivity and dosage
        twin = self.neurotransmitter_model.digital_twin
        adjusted_risk = base_risk * twin.medication_sensitivity

        # Adjust for dosage and add randomness
        if hasattr(medication, "dosage") and medication.dosage:
            adjusted_risk *= medication.dosage / 20  # Normalize around 20mg

        return min(100, max(0, adjusted_risk + random.uniform(-10, 10)))
