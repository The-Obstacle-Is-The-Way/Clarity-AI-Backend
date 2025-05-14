# External Services Integration

## Overview

This document outlines the implementation patterns for integrating external services with the Clarity AI Backend. Following clean architecture principles, all external service integrations are encapsulated in the infrastructure layer and accessed through well-defined interfaces in the core layer.

## Core Principles

1. **Clean Architecture**: External services are isolated to the infrastructure layer
2. **Dependency Inversion**: Core business logic depends on interfaces, not concrete implementations
3. **Adapter Pattern**: External services are wrapped in adapters that conform to internal interfaces
4. **Resilience**: Integrations handle failures gracefully with proper error handling and retry logic
5. **HIPAA Compliance**: PHI transmitted to external services follows strict security protocols

## Integration Architecture

### Core Interface

```python
# app/core/interfaces/services/external_model_service_interface.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from app.core.domain.entities import ModelResult

class IExternalModelService(ABC):
    """Interface for external ML model services."""
    
    @abstractmethod
    async def predict(self, data: Dict[str, Any]) -> ModelResult:
        """
        Send data to external model for prediction.
        
        Args:
            data: Input data for prediction
            
        Returns:
            Model prediction result
            
        Raises:
            ModelServiceError: If prediction fails
        """
        pass
    
    @abstractmethod
    async def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the external model.
        
        Returns:
            Model metadata
        """
        pass
```

### Infrastructure Implementation

```python
# app/infrastructure/external/aws/bedrock_service.py
import boto3
import json
from typing import Dict, Any, Optional
from app.core.interfaces.services import IExternalModelService
from app.core.domain.entities import ModelResult
from app.core.domain.errors import ModelServiceError
from app.infrastructure.external.aws.config import BedrockConfig
from app.infrastructure.external.aws.mappers import BedrockResponseMapper

class BedrockModelService(IExternalModelService):
    """AWS Bedrock implementation of external model service."""
    
    def __init__(self, config: BedrockConfig):
        """
        Initialize Bedrock service.
        
        Args:
            config: Service configuration
        """
        self._config = config
        self._client = None
        self._response_mapper = BedrockResponseMapper()
    
    def _get_client(self):
        """Get or create Bedrock client."""
        if not self._client:
            self._client = boto3.client(
                service_name="bedrock-runtime",
                region_name=self._config.region_name,
                aws_access_key_id=self._config.aws_access_key_id,
                aws_secret_access_key=self._config.aws_secret_access_key
            )
        return self._client
    
    async def predict(self, data: Dict[str, Any]) -> ModelResult:
        """Send data to Bedrock model for prediction."""
        try:
            # Prepare request payload
            payload = {
                "inputs": data,
                "parameters": self._config.model_parameters
            }
            
            # Invoke model
            response = self._get_client().invoke_model(
                modelId=self._config.model_id,
                body=json.dumps(payload)
            )
            
            # Parse response
            result = json.loads(response["body"].read())
            
            # Map to domain entity
            return self._response_mapper.to_model_result(result)
            
        except Exception as e:
            raise ModelServiceError(f"Bedrock prediction failed: {str(e)}") from e
    
    async def get_model_info(self) -> Dict[str, Any]:
        """Get information about the Bedrock model."""
        return {
            "model_id": self._config.model_id,
            "provider": "AWS Bedrock",
            "region": self._config.region_name,
            "capabilities": self._config.capabilities
        }
```

## Configuration Management

```python
# app/infrastructure/external/aws/config.py
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

class BedrockConfig(BaseModel):
    """Configuration for AWS Bedrock service."""
    
    model_id: str
    region_name: str
    aws_access_key_id: str
    aws_secret_access_key: str
    model_parameters: Dict[str, Any] = Field(default_factory=dict)
    capabilities: List[str] = Field(default_factory=list)
    timeout: int = 30
    max_retries: int = 3
```

## Dependency Injection

```python
# app/presentation/api/dependencies/external.py
from fastapi import Depends
from app.core.config import settings
from app.core.interfaces.services import IExternalModelService
from app.infrastructure.external.aws.bedrock_service import BedrockModelService
from app.infrastructure.external.aws.config import BedrockConfig

def get_bedrock_config() -> BedrockConfig:
    """Dependency provider for Bedrock configuration."""
    return BedrockConfig(
        model_id=settings.BEDROCK_MODEL_ID,
        region_name=settings.AWS_REGION,
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        model_parameters=settings.BEDROCK_MODEL_PARAMETERS,
        capabilities=["text-generation", "embeddings"]
    )

def get_external_model_service(
    config: BedrockConfig = Depends(get_bedrock_config)
) -> IExternalModelService:
    """Dependency provider for external model service."""
    return BedrockModelService(config)
```

## HTTP Client Integration

Generic HTTP client wrapper for external REST APIs:

```python
# app/infrastructure/external/http/client.py
import aiohttp
import json
from typing import Dict, Any, Optional
from app.core.domain.errors import ExternalServiceError

class HttpClient:
    """HTTP client for external service communication."""
    
    def __init__(self, base_url: str, timeout: int = 30):
        """
        Initialize HTTP client.
        
        Args:
            base_url: Base URL for the service
            timeout: Request timeout in seconds
        """
        self._base_url = base_url
        self._timeout = timeout
    
    async def get(
        self, 
        path: str, 
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Send GET request to external service.
        
        Args:
            path: API endpoint path
            params: Query parameters
            headers: Request headers
            
        Returns:
            Response data
            
        Raises:
            ExternalServiceError: If request fails
        """
        async with aiohttp.ClientSession() as session:
            try:
                url = f"{self._base_url}/{path}"
                async with session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=self._timeout
                ) as response:
                    if response.status >= 400:
                        error_text = await response.text()
                        raise ExternalServiceError(
                            f"HTTP error {response.status}: {error_text}"
                        )
                    
                    return await response.json()
                    
            except aiohttp.ClientError as e:
                raise ExternalServiceError(f"HTTP request failed: {str(e)}") from e
```

## HIPAA-Compliant External Transmissions

```python
# app/infrastructure/external/security/phi_handlers.py
from app.core.domain.entities import Patient
from typing import Dict, Any

class PHITransmissionHandler:
    """Handles secure transmission of PHI to external services."""
    
    @staticmethod
    def prepare_phi_for_transmission(
        patient: Patient, 
        required_fields: list[str]
    ) -> Dict[str, Any]:
        """
        Prepare PHI for secure transmission to external services.
        
        Args:
            patient: Patient entity containing PHI
            required_fields: List of fields required by external service
            
        Returns:
            Dictionary with minimal required PHI, properly secured
        """
        # Start with empty payload
        payload = {}
        
        # Only include explicitly requested fields
        if "id" in required_fields:
            payload["patient_id"] = str(patient.id)
            
        if "age" in required_fields:
            # Send age instead of DOB when possible
            payload["age"] = patient.calculate_age()
            
        if "biometrics" in required_fields and patient.biometric_readings:
            # Include de-identified biometric data
            payload["biometrics"] = [
                {
                    "type": reading.type,
                    "value": reading.value,
                    "timestamp": reading.timestamp.isoformat()
                }
                for reading in patient.biometric_readings
            ]
        
        # Add audit trail metadata
        payload["_audit"] = {
            "request_id": get_current_request_id(),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return payload
```

## Resilience Patterns

### Circuit Breaker

```python
# app/infrastructure/external/resilience/circuit_breaker.py
import time
from enum import Enum
from typing import Callable, TypeVar, Any, Optional

T = TypeVar('T')

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered

class CircuitBreaker:
    """
    Circuit breaker pattern implementation for external services.
    Prevents cascading failures by failing fast when a service is unreliable.
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 30,
        name: str = "default"
    ):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before trying again
            name: Name of this circuit breaker
        """
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._name = name
        self._failure_count = 0
        self._state = CircuitState.CLOSED
        self._last_failure_time = 0
    
    async def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Function to execute
            args: Positional arguments
            kwargs: Keyword arguments
            
        Returns:
            Function result
            
        Raises:
            CircuitOpenError: If circuit is open
            Exception: Original exception if function fails
        """
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time > self._recovery_timeout:
                # Try again after timeout
                self._state = CircuitState.HALF_OPEN
            else:
                raise CircuitOpenError(
                    f"Circuit {self._name} is open, request rejected"
                )
        
        try:
            result = await func(*args, **kwargs)
            
            # Success, reset if in half-open state
            if self._state == CircuitState.HALF_OPEN:
                self._reset()
                
            return result
            
        except Exception as e:
            # Record failure
            self._failure_count += 1
            self._last_failure_time = time.time()
            
            # Check if we should open the circuit
            if (self._state == CircuitState.CLOSED and 
                self._failure_count >= self._failure_threshold):
                self._state = CircuitState.OPEN
            
            raise e
    
    def _reset(self):
        """Reset circuit breaker state."""
        self._failure_count = 0
        self._state = CircuitState.CLOSED
```

## Service Mocking for Testing

```python
# app/tests/mocks/external_services.py
from typing import Dict, Any
from app.core.interfaces.services import IExternalModelService
from app.core.domain.entities import ModelResult
import json
import os

class MockExternalModelService(IExternalModelService):
    """Mock implementation of external model service for testing."""
    
    def __init__(self, test_responses_path: str = None):
        """
        Initialize mock service.
        
        Args:
            test_responses_path: Path to JSON file with test responses
        """
        self._responses = {}
        if test_responses_path and os.path.exists(test_responses_path):
            with open(test_responses_path, "r") as f:
                self._responses = json.load(f)
    
    async def predict(self, data: Dict[str, Any]) -> ModelResult:
        """Return mock prediction result."""
        # Use a deterministic key from input data
        input_type = data.get("type", "default")
        
        # Get mock response
        mock_data = self._responses.get(input_type, {
            "prediction": 0.5,
            "confidence": 0.8,
            "features": {}
        })
        
        return ModelResult(
            prediction=mock_data["prediction"],
            confidence=mock_data["confidence"],
            features=mock_data.get("features", {})
        )
    
    async def get_model_info(self) -> Dict[str, Any]:
        """Return mock model info."""
        return {
            "model_id": "mock-model-123",
            "provider": "Mock Provider",
            "capabilities": ["testing"]
        }
```

## Integration Examples

### Integrating with OpenAI API

```python
# app/infrastructure/external/openai/service.py
from app.core.interfaces.services import ITextGenerationService
from app.core.domain.errors import ModelServiceError
from app.infrastructure.external.openai.config import OpenAIConfig
from app.infrastructure.external.resilience import CircuitBreaker
import openai
from typing import List, Dict, Any

class OpenAIService(ITextGenerationService):
    """Integration with OpenAI API."""
    
    def __init__(self, config: OpenAIConfig):
        self._config = config
        self._client = openai.AsyncClient(api_key=config.api_key)
        self._circuit_breaker = CircuitBreaker(
            name="openai",
            failure_threshold=3,
            recovery_timeout=60
        )
    
    async def generate_text(
        self, 
        prompt: str,
        max_tokens: int = 1000
    ) -> str:
        """Generate text using OpenAI model."""
        
        async def _call_api():
            try:
                response = await self._client.chat.completions.create(
                    model=self._config.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                    temperature=self._config.temperature
                )
                return response.choices[0].message.content
            except Exception as e:
                raise ModelServiceError(f"OpenAI API error: {str(e)}") from e
        
        # Execute with circuit breaker protection
        return await self._circuit_breaker.execute(_call_api)
```

## Current Implementation Status

### Strengths

- Clean separation of external service concerns
- Adapter pattern consistently applied
- Strong error handling and resilience patterns
- HIPAA-compliant data transmission

### Architectural Gaps

- Some services still use direct API calls without circuit breakers
- Inconsistent logging of external service interactions
- Retry mechanisms not standardized across all services
- Configuration management needs centralization

By following these patterns, the Clarity AI Backend maintains a clean, maintainable integration layer that properly encapsulates external service concerns while enforcing security, compliance, and architectural boundaries.
