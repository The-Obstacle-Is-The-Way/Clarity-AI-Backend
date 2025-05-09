from enum import Enum

class Gender(Enum):
    MALE = "male"
    FEMALE = "female"
    NON_BINARY = "non-binary"
    OTHER = "other"
    PREFER_NOT_TO_SAY = "prefer_not_to_say"

__all__ = ['Gender'] 