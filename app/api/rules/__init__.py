"""
API rules and templates module.

This module defines rule templates for various API-enforced business rules,
following the Strategy and Template Method patterns from GOF.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class RuleEvaluationResult(BaseModel):
    """Result of a rule evaluation with metadata."""
    
    triggered: bool = Field(
        ..., 
        description="Whether the rule was triggered"
    )
    confidence: float = Field(
        ..., 
        description="Confidence level of the rule evaluation (0-1)"
    )
    details: dict[str, Any] = Field(
        default_factory=dict, 
        description="Additional details about the evaluation"
    )
    timestamp: str | None = Field(
        None, 
        description="ISO timestamp when the rule was evaluated"
    )


class RuleTemplate(ABC):
    """
    Abstract template for rule definitions.
    
    This abstract class follows the Template Method pattern,
    defining the structure for rule evaluation while allowing
    specific implementations to override key methods.
    """
    
    def __init__(self, name: str, description: str, severity: str):
        """
        Initialize a rule template.
        
        Args:
            name: Rule name
            description: Rule description
            severity: Rule severity level
        """
        self.name = name
        self.description = description
        self.severity = severity
    
    @abstractmethod
    async def evaluate(self, context: dict[str, Any]) -> RuleEvaluationResult:
        """
        Evaluate the rule against the provided context.
        
        Args:
            context: Context data for rule evaluation
            
        Returns:
            Result of the rule evaluation
        """
        pass


class AlertRuleTemplate(RuleTemplate):
    """
    Template for alert generation rules.
    
    This concrete template builds on the base template,
    adding alert-specific functionality.
    """
    
    def __init__(
        self, 
        name: str, 
        description: str, 
        severity: str,
        alert_type: str,
        recipients: list[str] = None
    ):
        """
        Initialize an alert rule template.
        
        Args:
            name: Rule name
            description: Rule description
            severity: Rule severity level
            alert_type: Type of alert to generate
            recipients: List of alert recipients
        """
        super().__init__(name, description, severity)
        self.alert_type = alert_type
        self.recipients = recipients or []


class PatientRiskRuleTemplate(RuleTemplate):
    """
    Template for patient risk assessment rules.
    
    This concrete template focuses on evaluating patient risk
    based on various clinical factors.
    """
    
    def __init__(
        self, 
        name: str, 
        description: str, 
        severity: str,
        risk_domain: str,
        threshold: float
    ):
        """
        Initialize a patient risk rule template.
        
        Args:
            name: Rule name
            description: Rule description
            severity: Rule severity level
            risk_domain: Domain of risk (suicide, relapse, etc.)
            threshold: Threshold for risk triggering
        """
        super().__init__(name, description, severity)
        self.risk_domain = risk_domain
        self.threshold = threshold
