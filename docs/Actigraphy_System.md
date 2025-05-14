# Actigraphy System

## Overview

The Actigraphy System is a revolutionary component of the Clarity AI Backend that transcends conventional activity monitoring by transforming raw physical movement data into quantum-precise psychiatric insights. At its core, this system leverages multi-dimensional activity patterns to construct a mathematical representation of behavioral states that serve as fundamental building blocks for the psychiatric digital twin platform.

## Current Architectural Implementation

The Actigraphy System demonstrates a hybrid architectural approach that combines Clean Architecture aspirations with pragmatic implementation patterns. The current implementation exhibits these characteristics:

1. **Interface Duality**: Two parallel interface definitions exist - `PATInterface` in the core layer and `IPATService` in the presentation layer
2. **Partial Dependency Inversion**: Some components depend on abstractions while others use concrete implementations directly
3. **Mock Implementation in Production Code**: `MockPATService` implementation exists directly in route files rather than in a testing layer
4. **AWS Service Abstraction**: Advanced dependency inversion for AWS services via `AWSServiceFactory`

### Architectural Vision vs. Current Reality

While the architectural vision follows a mathematically pure Clean Architecture implementation, the current codebase exhibits implementation pragmatism with areas requiring architectural refinement.

## System Components

### Interface Definitions

Two parallel interface definitions exist for the Actigraphy subsystem, with differing levels of method detail:

#### Core Layer Interface (`app/core/services/ml/pat/pat_interface.py`)

```python
class PATInterface(abc.ABC):
    """Interface for the PAT service."""
    
    @abc.abstractmethod
    def initialize(self, config: dict[str, Any]) -> None: ...
    
    @abc.abstractmethod
    def analyze_actigraphy(
        self,
        patient_id: str,
        readings: list[dict[str, Any]],
        start_time: str,
        end_time: str,
        sampling_rate_hz: float,
        device_info: dict[str, Any],
        analysis_types: list[str],
        **kwargs
    ) -> dict[str, Any]: ...
    
    @abc.abstractmethod
    def get_actigraphy_embeddings(...) -> dict[str, Any]: ...
    
    @abc.abstractmethod
    def get_analysis_by_id(self, analysis_id: str) -> dict[str, Any]: ...
```

#### Presentation Layer Interface (inline in `app/presentation/api/v1/routes/actigraphy.py`)

```python
class IPATService:
    """Interface for PAT analysis service."""
    
    async def analyze_actigraphy(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze actigraphy data and return results."""
        pass
    
    async def get_embeddings(self, data: dict[str, Any]) -> dict[str, Any]:
        """Generate embeddings from actigraphy data."""
        pass
```

### API Routes

The actual API routes are defined in `app/presentation/api/v1/routes/actigraphy.py`:

```python
"""API Routes for Actigraphy Data.

Handles endpoints related to retrieving and managing actigraphy data.
"""

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Query
from pydantic import BaseModel, UUID4
from sqlalchemy.ext.asyncio import AsyncSession

# Proper imports following Clean Architecture principles
from app.presentation.api.dependencies.auth import require_roles, get_current_user
from app.presentation.api.dependencies.database import get_db
from app.core.domain.entities.user import UserRole, User
from app.infrastructure.logging.audit_logger import audit_log_phi_access

# Import centralized schemas
from app.presentation.api.schemas.actigraphy import (
    ActigraphyAnalysisRequest,
    AnalyzeActigraphyResponse,
    ActigraphyModelInfoResponse,
    ActigraphyUploadResponse,
    ActigraphySummaryResponse,
    ActigraphyDataResponse,
    ActigraphyAnalysisResult,
    AnalysisType
)

router = APIRouter()
```

### PAT Service Integration

The Actigraphy System integrates with the Pretrained Actigraphy Transformer (PAT) service for advanced analysis:

```python
# Define interface for the PAT service following Interface Segregation Principle
class IPATService:
    """Interface for PAT analysis service."""
    
    async def analyze_actigraphy(self, data: dict[str, Any]) -> dict[str, Any]:
        """Analyze actigraphy data and return results."""
        pass
    
    async def get_embeddings(self, data: dict[str, Any]) -> dict[str, Any]:
        """Generate embeddings from actigraphy data."""
        pass

# Dependency injection for the service following Dependency Inversion Principle
async def get_pat_service(db: AsyncSession = Depends(get_db)) -> IPATService:
    """Get the PAT service implementation."""
    # In a production environment, this would get the actual service implementation
    # from a factory following Clean Architecture principles
    return MockPATService()
```

## Available Endpoints

### 1. Analyze Actigraphy

```python
@router.post(
    "/analyze", 
    response_model=AnalyzeActigraphyResponse,
    summary="Analyze actigraphy data"
)
async def analyze_actigraphy(
    data: ActigraphyAnalysisRequest,
    current_user = Depends(require_roles([UserRole.CLINICIAN, UserRole.ADMIN])),
    pat_service: IPATService = Depends(get_pat_service)
) -> AnalyzeActigraphyResponse:
    """
    Analyze actigraphy data for a patient.
    
    This endpoint processes the provided actigraphy data and returns various
    analytical metrics based on the requested analysis types.
    """
```

This endpoint processes raw actigraphy data to extract clinically relevant metrics such as:

- Sleep quality assessment
- Activity level patterns
- Circadian rhythm analysis
- Energy expenditure estimation
- Movement characteristics

**Authentication**: Requires authenticated user  
**Authorization**: Limited to clinicians and administrators  
**Request Body**: `ActigraphyAnalysisRequest` containing patient ID, time range, and analysis types  
**Response**: `AnalyzeActigraphyResponse` containing analysis results

### 2. Generate Embeddings

```python
@router.post(
    "/embeddings",
    summary="Generate embeddings from actigraphy data"
)
async def get_actigraphy_embeddings(
    data: dict[str, Any],
    current_user = Depends(require_roles([UserRole.CLINICIAN, UserRole.ADMIN])),
    pat_service: IPATService = Depends(get_pat_service)
):
    """
    Generate embeddings from actigraphy data.
    
    This endpoint processes the provided actigraphy data and returns vector 
    embeddings that can be used for further analysis or machine learning tasks.
    """
```

This endpoint transforms actigraphy data into vector embeddings for use in machine learning applications, enabling:

- Similarity comparisons between patients
- Pattern recognition across populations
- Integration with other data modalities
- Longitudinal tracking of changes

**Authentication**: Requires authenticated user  
**Authorization**: Limited to clinicians and administrators  
**Request Body**: Actigraphy data to analyze  
**Response**: Vector embeddings and metadata

### 3. Get Model Information

```python
@router.get(
    "/model-info",
    response_model=ActigraphyModelInfoResponse,
    summary="Get actigraphy model information"
)
async def get_model_info(
    current_user: User = Depends(require_roles([UserRole.PATIENT, UserRole.CLINICIAN, UserRole.ADMIN])),
    args: Optional[str] = Query(default=None),
    kwargs: Optional[str] = Query(default=None)
) -> ActigraphyModelInfoResponse:
    """
    Get information about the current actigraphy model.
    """
```

This endpoint provides metadata about the models used for actigraphy analysis, including:

- Model version and capabilities
- Supported analysis types
- Training dataset characteristics
- Performance metrics
- Last update timestamp

**Authentication**: Requires authenticated user  
**Authorization**: Accessible to patients, clinicians, and administrators  
**Response**: `ActigraphyModelInfoResponse` containing model information

### 4. Upload Actigraphy Data

```python
@router.post(
    "/upload",
    response_model=ActigraphyUploadResponse,
    summary="Upload actigraphy data"
)
async def upload_actigraphy_data_stub(
    current_user: CurrentUserDep,
    file: UploadFile = File(...)
) -> ActigraphyUploadResponse:
    """
    Upload actigraphy data from a file.
    
    This endpoint allows uploading actigraphy data from various device formats,
    including raw accelerometer data, processed activity metrics, or proprietary
    wearable device exports.
    """
```

This endpoint enables the upload of actigraphy data from various sources, supporting:

- Raw accelerometer data files
- Processed activity metrics
- Device-specific export formats
- Batch uploads of historical data

**Authentication**: Requires authenticated user  
**Authorization**: Requires appropriate access permissions  
**Request Body**: File upload containing actigraphy data  
**Response**: `ActigraphyUploadResponse` confirming successful processing

### 5. Get Patient Actigraphy Data

```python
@router.get(
    "/patient/{patient_id}",
    response_model=ActigraphyDataResponse,
    summary="Get patient actigraphy data"
)
async def get_patient_actigraphy_data(
    patient_id: uuid.UUID,
    start_date: datetime,
    end_date: datetime,
    current_user: CurrentUserDep,
    args: Optional[str] = Query(default=None),
    kwargs: Optional[str] = Query(default=None)
) -> ActigraphyDataResponse:
    """
    Get actigraphy data for a specific patient within a date range.
    
    This endpoint retrieves actigraphy data for the specified patient between the
    provided start and end dates. Both dates must be valid ISO format.
    """
```

This endpoint retrieves actigraphy data for a specific patient within a date range, providing:

- Raw accelerometer readings
- Processed activity metrics
- Sleep-wake patterns
- Daily summaries
- Previous analysis results

**Authentication**: Requires authenticated user  
**Authorization**: Requires appropriate access to patient data  
**Path Parameters**: `patient_id` - UUID of the patient  
**Query Parameters**:

- `start_date` - Beginning of the date range (ISO format)
- `end_date` - End of the date range (ISO format)  
**Response**: `ActigraphyDataResponse` containing the patient's actigraphy data

## Data Models

The Actigraphy System uses several Pydantic models to validate inputs and structure outputs:

### Analysis Request

```python
class ActigraphyAnalysisRequest(BaseModel):
    """Request model for actigraphy analysis."""
    patient_id: UUID4
    readings: List[Dict[str, Any]]
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    device_info: Optional[Dict[str, Any]] = None
    analysis_types: List[AnalysisType] = [AnalysisType.SLEEP_QUALITY, AnalysisType.ACTIVITY_LEVEL]
    options: Optional[Dict[str, Any]] = None
```

### Analysis Response

```python
class AnalyzeActigraphyResponse(BaseModel):
    """Response model for actigraphy analysis results."""
    analysis_id: UUID4
    patient_id: str
    time_range: Dict[str, datetime]
    results: List[ActigraphyAnalysisResult]
```

### Analysis Result

```python
class ActigraphyAnalysisResult(BaseModel):
    """Model for a single actigraphy analysis result."""
    analysis_type: AnalysisType
    analysis_time: datetime
    sleep_metrics: Optional[Dict[str, Any]] = None
    activity_metrics: Optional[Dict[str, Any]] = None
    circadian_metrics: Optional[Dict[str, Any]] = None
    raw_results: Dict[str, Any]
```

### Daily Summary

```python
class DailySummary(BaseModel):
    """Daily summary of actigraphy data."""
    date: datetime
    total_activity_count: int
    steps: int
    distance_meters: float
    active_minutes: Dict[str, int]  # light, moderate, vigorous
    calories_burned: float
    sleep_duration_minutes: int
    sleep_efficiency: float
    sleep_stages: Dict[SleepStage, int]  # minutes in each sleep stage
```

### Sleep Stage Enum

```python
class SleepStage(str, Enum):
    """Enumeration of sleep stages."""
    AWAKE = "awake"
    LIGHT = "light"
    DEEP = "deep"
    REM = "rem"
    UNKNOWN = "unknown"
```

## Data Processing Pipeline

The Actigraphy System employs a multi-stage processing pipeline:

1. **Data Collection**: Raw accelerometer data is collected from wearable devices
2. **Preprocessing**: Data is cleaned, normalized, and segmented
3. **Feature Extraction**: Temporal and frequency domain features are extracted
4. **Analysis**: Machine learning models extract clinically relevant metrics
5. **Integration**: Results are integrated into the patient's digital twin

## Clinical Applications

The Actigraphy System supports various clinical applications:

### Depression Monitoring

Activity patterns can identify depression symptoms:

- Reduced overall activity levels
- Disrupted sleep patterns
- Increased sedentary behavior
- Reduced diurnal variation

### Bipolar Disorder

Actigraphy can detect bipolar state transitions:

- Hypomanic/manic states show increased activity and reduced sleep
- Depressive states show reduced activity and increased sleep
- Mixed states show erratic activity patterns

### Anxiety Assessment

Activity data can provide objective anxiety markers:

- Restlessness and agitation
- Sleep onset difficulties
- Fragmented activity patterns
- Stress-related movement signatures

### Treatment Response

Longitudinal actigraphy data can objectively measure treatment efficacy:

- Normalization of sleep-wake patterns
- Increases in overall activity levels
- Restoration of circadian rhythms
- Reduction in pathological movement patterns

## HIPAA Compliance

The Actigraphy System implements robust security measures:

1. **PHI Protection**: Patient identifiers are securely handled
2. **Access Control**: Data access is restricted based on role
3. **Audit Logging**: All data access is logged for compliance
4. **Data Minimization**: Only necessary information is collected and processed

## Architectural Gaps and Refinement Opportunities

### Current Architectural Issues

1. **Interface Duplication**: Two parallel interfaces (`PATInterface` and `IPATService`) with different method signatures and locations
2. **Layer Violations**: Interfaces defined in presentation layer instead of core layer
3. **Testing Code in Production**: Mock implementation in route files rather than segregated in test layers
4. **Inconsistent Dependency Injection**: Some components use proper DI, others create dependencies directly

### Implementation Roadmap for Architectural Purity

1. **Interface Consolidation**: Migrate to a single `IPAT` interface in the core layer
2. **Remove Presentation Layer Mocks**: Move all mock implementations to the test layer
3. **Factory Pattern Implementation**: Create proper factory for actigraphy service implementations
4. **Schema Alignment**: Ensure consistent data structures between interface and implementations

## Integration with Digital Twin

The Actigraphy System integrates with the Digital Twin through:

1. **Continuous Data Feed**: Regular updates to the digital twin with new actigraphy data
2. **Multimodal Analysis**: Combining actigraphy with other data sources
3. **Longitudinal Tracking**: Monitoring changes in activity patterns over time
4. **Visualization Components**: Interactive visualization of activity patterns

## Future Enhancements

The Actigraphy System roadmap includes:

1. **Real-time Analysis**: Processing data streams in real-time
2. **Mobile Integration**: Direct integration with smartphone and wearable SDKs
3. **Expanded Device Support**: Support for additional wearable devices
4. **Enhanced ML Models**: More sophisticated behavioral pattern recognition
5. **Personalized Baselines**: Individual-specific pattern analysis

## Related Components

- **PAT Service**: Provides specialized analysis of actigraphy data
- **Digital Twin System**: Incorporates actigraphy insights into the comprehensive patient model
- **Device Integration Services**: Connects with various wearable devices and data sources
- **Alert Rules System**: Generates clinical alerts based on actigraphy pattern changes
