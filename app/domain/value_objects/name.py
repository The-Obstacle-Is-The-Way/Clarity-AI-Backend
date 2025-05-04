
from pydantic import BaseModel, ConfigDict, Field


class Name(BaseModel):
    """Represents a person's name as a value object."""
    first_name: str = Field(..., description="The person's first name.")
    last_name: str = Field(..., description="The person's last name.")
    middle_name: str | None = Field(None, description="The person's middle name (optional).")

    # V2 Config
    model_config = ConfigDict(frozen=True)  # Value objects should be immutable
    
    def __str__(self) -> str:
        """Return a string representation of the name."""
        if self.middle_name:
            return f"{self.first_name} {self.middle_name} {self.last_name}"
        return f"{self.first_name} {self.last_name}"
    
    def split(self) -> list[str]:
        """Split the name into parts, useful for compatibility with code that expects string splitting."""
        return str(self).split()
    
    def get_full_name(self) -> str:
        """Return the full name as a string."""
        return str(self)
    
    def get_last_name_first(self) -> str:
        """Return the name in 'LastName, FirstName' format."""
        return f"{self.last_name}, {self.first_name}"
    
    def get_initials(self) -> str:
        """Return the initials."""
        if self.middle_name:
            return f"{self.first_name[0]}{self.middle_name[0]}{self.last_name[0]}"
        return f"{self.first_name[0]}{self.last_name[0]}"
