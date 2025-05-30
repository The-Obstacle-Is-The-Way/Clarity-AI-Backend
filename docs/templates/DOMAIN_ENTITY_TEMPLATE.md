# [ENTITY_NAME] Entity

## Purpose

[ENTITY_PURPOSE_DESCRIPTION]

This entity represents [BUSINESS_CONCEPT] in the Clarity-AI domain model.

## Properties

| Property | Type | Description |
|----------|------|-------------|
| [PROPERTY_1] | [TYPE] | [DESCRIPTION] |
| [PROPERTY_2] | [TYPE] | [DESCRIPTION] |
| [PROPERTY_3] | [TYPE] | [DESCRIPTION] |
| [PROPERTY_4] | [TYPE] | [DESCRIPTION] |

## Implementation

### Location

```
[FILE_PATH]
```

### Code Definition

```python
class [ENTITY_NAME]:
    """
    [ENTITY_DOCSTRING]
    """
    
    def __init__(
        self,
        [PROPERTY_1]: [TYPE],
        [PROPERTY_2]: [TYPE],
        [PROPERTY_3]: [TYPE],
        [PROPERTY_4]: [TYPE] = None
    ):
        """
        Initialize a new [ENTITY_NAME].
        
        Args:
            [PROPERTY_1]: [PARAMETER_DESCRIPTION]
            [PROPERTY_2]: [PARAMETER_DESCRIPTION]
            [PROPERTY_3]: [PARAMETER_DESCRIPTION]
            [PROPERTY_4]: [PARAMETER_DESCRIPTION]
        """
        self.[PROPERTY_1] = [PROPERTY_1]
        self.[PROPERTY_2] = [PROPERTY_2]
        self.[PROPERTY_3] = [PROPERTY_3]
        self.[PROPERTY_4] = [PROPERTY_4]
    
    # Include any entity methods here
```

## Related Value Objects

- [VALUE_OBJECT_1]: [RELATIONSHIP_DESCRIPTION]
- [VALUE_OBJECT_2]: [RELATIONSHIP_DESCRIPTION]

## Repository Interface

```python
class I[ENTITY_NAME]Repository(Protocol):
    """
    Repository interface for [ENTITY_NAME] entities.
    """
    
    async def get_by_id(self, id: UUID) -> Optional[[ENTITY_NAME]]:
        """
        Retrieve an [ENTITY_NAME] by its ID.
        
        Args:
            id: The unique identifier of the [ENTITY_NAME]
            
        Returns:
            The [ENTITY_NAME] if found, None otherwise
        """
        ...
    
    async def create(self, [ENTITY_PARAM]: [ENTITY_NAME]) -> [ENTITY_NAME]:
        """
        Create a new [ENTITY_NAME].
        
        Args:
            [ENTITY_PARAM]: The [ENTITY_NAME] to create
            
        Returns:
            The created [ENTITY_NAME] with any system-generated fields
        """
        ...
    
    # Include other repository methods
```

## Business Rules

- [RULE_1]
- [RULE_2]
- [RULE_3]

## Domain Services

The following domain services operate on this entity:

- [SERVICE_1]: [SERVICE_1_DESCRIPTION]
- [SERVICE_2]: [SERVICE_2_DESCRIPTION]

## Persistence

This entity is persisted as:

```python
class [ENTITY_NAME]Model(Base):
    """
    SQLAlchemy model for [ENTITY_NAME].
    """
    
    __tablename__ = "[TABLE_NAME]"
    
    [COLUMN_1] = Column([SQLALCHEMY_TYPE], primary_key=True)
    [COLUMN_2] = Column([SQLALCHEMY_TYPE], nullable=False)
    [COLUMN_3] = Column([SQLALCHEMY_TYPE], nullable=False)
    [COLUMN_4] = Column([SQLALCHEMY_TYPE], nullable=True)
    
    # Include any relationships
```

## API Representation

```python
class [ENTITY_NAME]Schema(BaseModel):
    """
    Pydantic schema for API representation of [ENTITY_NAME].
    """
    
    [FIELD_1]: [PYDANTIC_TYPE]
    [FIELD_2]: [PYDANTIC_TYPE]
    [FIELD_3]: [PYDANTIC_TYPE]
    [FIELD_4]: Optional[[PYDANTIC_TYPE]] = None
    
    class Config:
        """Schema configuration."""
        
        json_schema_extra = {
            "example": {
                "[FIELD_1]": "[EXAMPLE_VALUE]",
                "[FIELD_2]": "[EXAMPLE_VALUE]",
                "[FIELD_3]": "[EXAMPLE_VALUE]",
                "[FIELD_4]": "[EXAMPLE_VALUE]"
            }
        }
    
    @classmethod
    def from_entity(cls, entity: [ENTITY_NAME]) -> "[ENTITY_NAME]Schema":
        """
        Create a schema instance from a domain entity.
        
        Args:
            entity: The domain entity
            
        Returns:
            A schema instance
        """
        return cls(
            [FIELD_1]=entity.[PROPERTY_1],
            [FIELD_2]=entity.[PROPERTY_2],
            [FIELD_3]=entity.[PROPERTY_3],
            [FIELD_4]=entity.[PROPERTY_4]
        )
```

## HIPAA Considerations

This entity [CONTAINS/DOES NOT CONTAIN] Protected Health Information (PHI):

- [PHI_FIELD_1]: [PHI_DESCRIPTION]
- [PHI_FIELD_2]: [PHI_DESCRIPTION]

The following safeguards are implemented:
- [SAFEGUARD_1]
- [SAFEGUARD_2]
- [SAFEGUARD_3]