from enum import Enum


class Gender(str, Enum):
    """Gender enum for patient data with string values for easier serialization."""

    MALE = "male"
    FEMALE = "female"
    NON_BINARY = "non-binary"
    OTHER = "other"
    PREFER_NOT_TO_SAY = "prefer_not_to_say"


__all__ = ["Gender"]
