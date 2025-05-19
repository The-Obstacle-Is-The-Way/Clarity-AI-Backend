"""
Domain entity for biometric alert rules.

This module defines the core domain entities for biometric alert rules,
including value objects and enums for use throughout the application.
Following proper domain-driven design principles.
"""
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, ConfigDict

from app.core.utils.date_utils import utcnow

# Value Objects and Enums

class AlertPriority(str, Enum):
    """Priority levels for biometric alerts."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    INFO = "info"
    
    def __str__(self) -> str:
        return self.value


class BiometricMetricType(str, Enum):
    """Types of biometric metrics that can be monitored."""
    HEART_RATE = "heart_rate"
    BLOOD_PRESSURE = "blood_pressure"
    BLOOD_GLUCOSE = "blood_glucose"
    OXYGEN_SATURATION = "oxygen_saturation"
    RESPIRATORY_RATE = "respiratory_rate"
    TEMPERATURE = "temperature"
    SLEEP_DURATION = "sleep_duration"
    STEPS = "steps"
    WEIGHT = "weight"
    ACTIVITY_LEVEL = "activity_level"
    STRESS_LEVEL = "stress_level"
    MOOD = "mood"
    
    def __str__(self) -> str:
        return self.value
    
    @classmethod
    def get_display_name(cls, value: str) -> str:
        """Get a human-readable display name for a metric type."""
        display_names = {
            cls.HEART_RATE: "Heart Rate",
            cls.BLOOD_PRESSURE: "Blood Pressure",
            cls.BLOOD_GLUCOSE: "Blood Glucose",
            cls.OXYGEN_SATURATION: "Oxygen Saturation",
            cls.RESPIRATORY_RATE: "Respiratory Rate",
            cls.TEMPERATURE: "Temperature",
            cls.SLEEP_DURATION: "Sleep Duration",
            cls.STEPS: "Steps",
            cls.WEIGHT: "Weight",
            cls.ACTIVITY_LEVEL: "Activity Level",
            cls.STRESS_LEVEL: "Stress Level",
            cls.MOOD: "Mood"
        }
        return display_names.get(value, value)


class ComparatorOperator(str, Enum):
    """Comparison operators for rule conditions."""
    GREATER_THAN = ">"
    LESS_THAN = "<"
    EQUAL_TO = "=="
    GREATER_THAN_OR_EQUAL = ">="
    LESS_THAN_OR_EQUAL = "<="
    NOT_EQUAL = "!="
    
    def __str__(self) -> str:
        return self.value
    
    def evaluate(self, left: Any, right: Any) -> bool:
        """Evaluate the comparison between two values."""
        if self == ComparatorOperator.GREATER_THAN:
            return left > right
        elif self == ComparatorOperator.LESS_THAN:
            return left < right
        elif self == ComparatorOperator.EQUAL_TO:
            return left == right
        elif self == ComparatorOperator.GREATER_THAN_OR_EQUAL:
            return left >= right
        elif self == ComparatorOperator.LESS_THAN_OR_EQUAL:
            return left <= right
        elif self == ComparatorOperator.NOT_EQUAL:
            return left != right
        else:
            raise ValueError(f"Unknown operator: {self}")


class RuleLogicalOperator(str, Enum):
    """Logical operators for combining rule conditions."""
    AND = "and"
    OR = "or"
    
    def __str__(self) -> str:
        return self.value
    
    def evaluate(self, left: bool, right: bool) -> bool:
        """Evaluate the logical operation between two boolean values."""
        if self == RuleLogicalOperator.AND:
            return left and right
        elif self == RuleLogicalOperator.OR:
            return left or right
        else:
            raise ValueError(f"Unknown logical operator: {self}")


# Aggregates and Entities

class RuleCondition(BaseModel):
    """A condition for a biometric alert rule."""
    metric_type: BiometricMetricType
    operator: ComparatorOperator
    threshold_value: float
    description: str | None = None
    
    def evaluate(self, metric_value: float) -> bool:
        """Evaluate if the condition is met for a given metric value."""
        return self.operator.evaluate(metric_value, self.threshold_value)
    
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True
    )


class BiometricAlertRule(BaseModel):
    """Domain entity for biometric alert rules."""
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str | None = None
    patient_id: UUID
    provider_id: UUID | None = None
    conditions: list[RuleCondition]
    logical_operator: RuleLogicalOperator = RuleLogicalOperator.AND
    priority: AlertPriority = AlertPriority.MEDIUM
    is_active: bool = True
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime | None = None
    template_id: UUID | None = None
    
    def evaluate(self, metrics: dict[BiometricMetricType, float]) -> bool:
        """
        Evaluate if the rule is triggered based on the provided metrics.
        
        Args:
            metrics: Dictionary mapping metric types to their values
            
        Returns:
            bool: True if the rule conditions are met, False otherwise
        """
        # No conditions means no trigger
        if not self.conditions:
            return False
        
        # Evaluate each condition
        results = []
        for condition in self.conditions:
            metric_value = metrics.get(condition.metric_type)
            if metric_value is None:
                # Skip this condition if the metric is not provided
                continue
            
            results.append(condition.evaluate(metric_value))
        
        # No results means no metrics matched our conditions
        if not results:
            return False
        
        # Evaluate all results according to the logical operator
        if self.logical_operator == RuleLogicalOperator.AND:
            return all(results)
        else:  # OR
            return any(results)
    
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True
    )
