"""
Diagnosis code value object for the NOVAMIND backend.

This module contains the DiagnosisCode value object, which represents
a standardized diagnosis code (ICD-10 or DSM-5) with validation.
"""

from dataclasses import dataclass
from enum import Enum


class CodeSystem(Enum):
    """Enumeration of diagnosis code systems"""

    ICD10 = "ICD-10"
    DSM5 = "DSM-5"
    SNOMED = "SNOMED-CT"


@dataclass(frozen=True)
class DiagnosisCode:
    """
    Value object representing a diagnosis code.

    This is an immutable value object with validation logic for
    psychiatric diagnosis codes from standard coding systems.
    """

    code: str
    system: CodeSystem
    description: str
    category: str | None = None

    def __post_init__(self):
        """Validate the diagnosis code format"""
        if not self.code:
            raise ValueError("Diagnosis code cannot be empty")

        if not self.description:
            raise ValueError("Diagnosis description cannot be empty")

        # Validate ICD-10 format (letter followed by digits)
        if self.system == CodeSystem.ICD10:
            if not (
                len(self.code) >= 3
                and self.code[0].isalpha()
                and self.code[1:].replace(".", "").isdigit()
            ):
                raise ValueError(f"Invalid ICD-10 code format: {self.code}")

        # Validate DSM-5 format
        elif self.system == CodeSystem.DSM5:
            if not self.code.startswith(
                ("DSM-5-", "2", "3", "4", "5", "6", "7", "8", "9")
            ):
                raise ValueError(f"Invalid DSM-5 code format: {self.code}")

    @property
    def is_psychiatric(self) -> bool:
        """
        Check if this is a psychiatric diagnosis

        For ICD-10, psychiatric codes are typically F00-F99
        """
        if self.system == CodeSystem.ICD10:
            return self.code.startswith("F")
        # All DSM-5 codes are psychiatric by definition
        elif self.system == CodeSystem.DSM5:
            return True
        # For SNOMED, we would need more complex logic
        return False

    def validate_code(self) -> None:
        """
        Validate that the diagnosis code matches the required format.

        Raises:
            ValueError: If code format is invalid
        """
        if not self.CODE_PATTERN.match(self.code):
            raise ValueError(
                f"Invalid diagnosis code format. Must match pattern: {self.CODE_PATTERN.pattern}"
            )

    def __str__(self) -> str:
        """String representation of the diagnosis code"""
        return f"{self.code} ({self.system.value}): {self.description}"
