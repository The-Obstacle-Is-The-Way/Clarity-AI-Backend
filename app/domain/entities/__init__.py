"""
Domain entities package for the Novamind Digital Twin Backend.

This package contains business domain entities representing core objects
in the system with their properties and behaviors.
"""

from app.domain.entities.assessment import AssessmentResult, AssessmentType

__all__ = ["AssessmentResult", "AssessmentType"]
