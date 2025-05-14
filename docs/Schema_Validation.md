# Schema Validation

## Overview

This document details the schema validation implementation in the Clarity AI Backend, which ensures data integrity, security, and HIPAA compliance through comprehensive input and output validation. By adhering to clean architecture principles, we maintain a rigid validation boundary between external inputs and our core domain.

## Core Principles

1. **Strict Validation**: All external inputs must be validated before processing
2. **Separation of Concerns**: DTOs separate API schemas from domain models
3. **Centralized Definition**: Validation rules defined in one place
4. **HIPAA Compliance**: Validates PHI formats and prevents exposure of sensitive data
5. **Clean Architecture**: Maintains the integrity of layer boundaries
6. **Exception Safety**: Consistent error handling for validation failures

## Current Implementation

The current implementation of schema validation in the Clarity AI Backend uses Pydantic for validating all input and output data. Pydantic is integrated with FastAPI to provide automatic validation of request bodies, query parameters, and path parameters.

### Pydantic Models

The project uses modern Pydantic v2 schemas with up-to-date features:

```python
import uuid
from datetime import date, datetime
from pydantic import BaseModel, Field, EmailStr, computed_field, ConfigDict

class PatientBase(BaseModel):
    first_name: str = Field(..., description="Patient's first name")
    last_name: str = Field(..., description="Patient's last name")
    date_of_birth: date = Field(..., description="Patient's date of birth")
    email: EmailStr | None = Field(None, description="Patient's email address")
    phone_number: str | None = Field(None, description="Patient's phone number")

class PatientCreateRequest(PatientBase):
    # Fields specific to creation, if any. For now, inherits all from PatientBase.
    pass

class PatientRead(PatientBase):
    id: uuid.UUID = Field(..., description="Unique identifier for the patient")
    created_at: datetime | None = Field(None, description="When the patient record was created")
    updated_at: datetime | None = Field(None, description="When the patient record was last updated")
    created_by: uuid.UUID | None = Field(None, description="ID of the user who created the patient record")

    @computed_field
    @property
    def name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    model_config = ConfigDict(from_attributes=True)  # Modern replacement for orm_mode
```

### Authentication Schemas

The authentication system uses dedicated schemas to ensure secure validation:

```python
from pydantic import BaseModel, EmailStr, Field, ConfigDict

class TokenResponseSchema(BaseModel):
    """Response schema for successful login or token refresh."""
    access_token: str = Field(..., description="JWT Access Token")
    refresh_token: str = Field(..., description="JWT Refresh Token")
    token_type: str = Field("bearer", description="Type of the token")
    expires_in: int = Field(..., description="Seconds until access token expiration")
    user_id: Optional[uuid.UUID] = Field(None, description="User ID of the authenticated user")
    roles: Optional[List[str]] = Field(None, description="Roles of the authenticated user")

    model_config = ConfigDict(from_attributes=True)

class LoginRequestSchema(BaseModel):
    """Request schema for user login."""
    username: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., description="User's password")
    remember_me: bool = Field(False, description="Whether to issue a long-lived refresh token")
```

### Validation Utilities

The codebase includes dedicated validation utilities for common data types, particularly focusing on PHI validation:

```python
def validate_us_phone(phone_number: str) -> bool:
    """
    Validate if a string is a properly formatted US phone number.
    """
    # Remove any non-digit characters for validation
    digits_only = re.sub(r'\D', '', phone_number)
    
    # US phone numbers should have 10 digits (or 11 with country code 1)
    return (len(digits_only) == 10 or 
            (len(digits_only) == 11 and digits_only.startswith('1')))

def validate_ssn(ssn: str) -> bool:
    """
    Validate if a string could be a Social Security Number format.
    """
    # Basic regex for SSN format (###-##-#### or #########)
    ssn_pattern = re.compile(r'^\d{3}-?\d{2}-?\d{4}$')
    return bool(ssn_pattern.match(ssn))
```

## Implementation Status

### Current Status

- ✅ Modern Pydantic v2 models used for API schemas
- ✅ Clear separation between request and response models
- ✅ Use of EmailStr and other specialized validators
- ✅ Support for computed fields in response models
- ✅ Proper ORM integration with `model_config = ConfigDict(from_attributes=True)`
- ✅ Utility functions for validating PHI data
- ⚠️ Limited custom validators beyond standard Pydantic

### Architectural Gaps

The current implementation has several areas that could be improved:

- 🔄 **Inconsistent Validation**: Validation approaches vary across different parts of the codebase
- 🔄 **Limited Custom Validators**: Few custom validators for domain-specific validation
- 🔄 **Incomplete Exception Handling**: Some endpoints may not handle validation errors consistently
- 🔄 **Missing Comprehensive PHI Validation**: PHI validation could be more thoroughly implemented
- 🔄 **Minimal Unit Tests**: Few tests specifically targeting validation logic

## Best Practices for Implementation

### API Schema Design

1. **Base and Specialized Models**: Create base models with common fields, then extend for specific use cases
   ```python
   class UserBase(BaseModel):
       email: EmailStr
   
   class UserCreate(UserBase):
       password: str
   
   class UserRead(UserBase):
       id: UUID
       created_at: datetime
   ```

2. **Separate Request/Response Models**: Always use separate models for requests and responses
   ```python
   # Request model
   class PatientCreateRequest(BaseModel):
       first_name: str
       last_name: str
   
   # Response model
   class PatientResponse(BaseModel):
       id: UUID
       first_name: str
       last_name: str
       created_at: datetime
   ```

3. **Use Field Constraints**: Apply constraints directly in the schema
   ```python
   class PasswordReset(BaseModel):
       password: str = Field(..., min_length=8, max_length=100)
       email: EmailStr = Field(..., description="Email address to reset")
   ```

### Validation Techniques

1. **Custom Validators**: Use `@field_validator` for complex field validation
   ```python
   from pydantic import field_validator
   
   class UserCreate(BaseModel):
       password: str
       
       @field_validator('password')
       def password_strength(cls, v):
           if len(v) < 8:
               raise ValueError('Password must be at least 8 characters')
           # Add more strength checks here
           return v
   ```

2. **Model Validators**: Use `@model_validator` for validations across multiple fields
   ```python
   from pydantic import model_validator
   
   class AppointmentCreate(BaseModel):
       start_time: datetime
       end_time: datetime
       
       @model_validator(mode='after')
       def check_times(self):
           if self.end_time <= self.start_time:
               raise ValueError('End time must be after start time')
           return self
   ```

3. **Computed Fields**: Use `@computed_field` for derived values
   ```python
   class Patient(BaseModel):
       first_name: str
       last_name: str
       
       @computed_field
       @property
       def full_name(self) -> str:
           return f"{self.first_name} {self.last_name}"
   ```

### Error Handling

1. **Consistent HTTP Status Codes**: Use appropriate status codes for validation errors
   ```python
   # 400 Bad Request for client-side validation issues
   # 422 Unprocessable Entity for semantic validation failures
   ```

2. **Structured Error Responses**: Return detailed, structured error information
   ```python
   {
     "detail": [
       {
         "loc": ["body", "email"],
         "msg": "Invalid email format",
         "type": "value_error.email"
       }
     ]
   }
   ```

3. **Domain Validation Exceptions**: Create specific exception types for domain validation errors
   ```python
   class DomainValidationError(Exception):
       def __init__(self, field: str, message: str, code: str = "validation_error"):
           self.field = field
           self.message = message
           self.code = code
           super().__init__(f"{field}: {message}")
   ```

## HIPAA Compliance Considerations

For HIPAA compliance in schema validation:

1. **Validate PHI Formats**: Use strict validation for PHI fields
   ```python
   @field_validator('medical_record_number')
   def validate_mrn(cls, v):
       if v and not re.match(r'^[A-Z0-9]{6,10}$', v):
           raise ValueError('Invalid medical record number format')
       return v
   ```

2. **Mask Sensitive Data**: Apply masking to sensitive fields in responses
   ```python
   @field_validator('ssn')
   def mask_ssn(cls, v):
       if v:
           # Only show last 4 digits
           return f"XXX-XX-{v[-4:]}"
       return v
   ```

3. **Audit Validation Failures**: Log validation failures for PHI fields (without including the actual data)
   ```python
   try:
       validated_data = PatientModel(**raw_data)
   except ValidationError as e:
       # Log fields that failed validation without the actual values
       fields = [error["loc"][0] for error in e.errors()]
       audit_logger.log_validation_failure(user_id, "patient_create", fields)
       raise
   ```

By implementing these patterns and addressing the identified gaps, the Clarity AI Backend can ensure robust data validation while maintaining clean architecture principles and HIPAA compliance.
