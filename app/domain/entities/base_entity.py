"""
Base class for domain entities.
"""
from dataclasses import dataclass, field
from uuid import UUID, uuid4
from datetime import datetime

@dataclass(kw_only=True)
class BaseEntity:
    """Base entity providing common fields like ID."""
    id: UUID = field(default_factory=uuid4)

    # You might add common methods or properties here later if needed
    # For example, equality based on ID:
    # def __eq__(self, other):
    #     if not isinstance(other, BaseEntity):
    #         return NotImplemented
    #     return self.id == other.id
    #
    # def __hash__(self):
    #     return hash(self.id)
