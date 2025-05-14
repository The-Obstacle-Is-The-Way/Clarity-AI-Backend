# Actigraphy System

## Overview

The Actigraphy System is a specialized component of the Clarity AI Backend that transforms raw physical movement data into psychiatric insights. This system leverages multi-dimensional activity patterns to construct a mathematical representation of behavioral states that serve as fundamental building blocks for the psychiatric digital twin platform.

## Current Architectural Implementation

The Actigraphy System exhibits a layered architectural approach following Clean Architecture principles, with some implementation-specific patterns. The current implementation demonstrates these characteristics:

1. **Dual Interface Pattern**: Two interfaces for actigraphy functionality exist:
   - `ActigraphyServiceInterface` in the core layer (app/core/interfaces/services)
   - `IPATService` inline in the routes file (app/presentation/api/v1/routes/actigraphy.py)

2. **Partial Dependency Inversion**: The system utilizes dependency injection for the PAT service in API routes

3. **Mock Implementation for Development**: `MockPATService` is implemented directly in the routes file for testing and development

4. **Protocol-based Interfaces**: The Core layer uses `@runtime_checkable` Protocol patterns for interface definition

## Interface Definitions

### Core Layer Interface (`app/core/interfaces/services/actigraphy_service_interface.py`)

```python
@runtime_checkable
class ActigraphyServiceInterface(Protocol):
    """Interface for actigraphy data processing and analysis services."""
    
    async def initialize(self) -> None:
        """Initialize the actigraphy service."""
        ...
    
    async def analyze_actigraphy(
        self, 
        patient_id: str, 
        readings: List[Dict[str, Any]], 
        device_info: Optional[Dict[str, Any]] = None,
        analysis_types: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Analyze actigraphy data to extract relevant features and patterns."""
        ...
    
    async def get_embeddings(
        self, 
        patient_id: str, 
        readings: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Generate embeddings from actigraphy data for use in machine learning models."""
        ...
    
    async def get_analysis_by_id(
        self, 
        analysis_id: str,
        patient_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Retrieve a previously performed analysis by its ID."""
        ...
    
    async def get_patient_analyses(
        self, 
        patient_id: str,
        limit: int = 10,
        offset: int = 0
    ) -> Dict[str, Any]:
        """Retrieve all analyses performed for a specific patient."""
        ...
    
    async def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current actigraphy analysis model."""
        ...
    
    async def get_analysis_types(self) -> List[str]:
        """Get available analysis types supported by the service."""
        ...
    
    async def integrate_with_digital_twin(
        self, 
        patient_id: str,
        analysis_id: str,
        profile_id: Optional[str] = None,
        integration_options: Optional[Dict[str, bool]] = None
    ) -> Dict[str, Any]:
        """Integrate actigraphy analysis results with a patient's digital twin."""
        ...
```

### Route-Level Interface (`app/presentation/api/v1/routes/actigraphy.py`)

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

## API Routes

The Actigraphy System exposes several endpoints through FastAPI:

```python
router = APIRouter()
```

### Dependency Injection

```python
async def get_pat_service(db: AsyncSession = Depends(get_db)) -> IPATService:
    """Get the PAT service implementation."""
    # In a production environment, this would use a factory pattern
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
```

This endpoint processes raw actigraphy data to extract clinically relevant metrics such as:

- Sleep quality assessment
- Activity level patterns
- Circadian rhythm analysis
- Energy expenditure estimation
- Movement characteristics

**Authentication**: Requires authenticated user  
**Authorization**: Limited to patients, clinicians, and administrators  
**Request Body**: `ActigraphyAnalysisRequest` containing patient ID, time range, and analysis types  
**Response**: `AnalyzeActigraphyResponse` containing analysis results

### 2. Generate Embeddings

```python
@router.post(
    "/embeddings",
    summary="Generate embeddings from actigraphy data"
)
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
```

This endpoint provides metadata about the models used for actigraphy analysis, including:

- Model version and capabilities
- Supported analysis types
- Last update timestamp
- Model identifier

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
    "/{patient_id}",
    response_model=ActigraphyDataResponse,
    summary="Get Actigraphy Data for a Patient with Date Range"
)
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

### Analysis Types and Sleep Stages

```python
class AnalysisType(str, Enum):
    """Types of actigraphy analysis that can be performed."""
    SLEEP_QUALITY = "sleep_quality"
    ACTIVITY_PATTERNS = "activity_patterns"
    CIRCADIAN_RHYTHM = "circadian_rhythm"
    ENERGY_EXPENDITURE = "energy_expenditure"
    MOVEMENT_INTENSITY = "movement_intensity"
    ACTIVITY_LEVEL = "activity_level"
    ACTIVITY = "activity"
    SLEEP = "sleep"
    STRESS = "stress"


class SleepStage(str, Enum):
    """Sleep stages identified in actigraphy analysis."""
    AWAKE = "awake"
    LIGHT = "light"
    DEEP = "deep"
    REM = "rem"
    UNKNOWN = "unknown"
```

### Analysis Request

```python
class ActigraphyAnalysisRequest(BaseSchema):
    """Schema for requesting analysis of existing actigraphy data."""
    patient_id: str
    analysis_types: list[AnalysisType]
    start_time: datetime | None = None
    end_time: datetime | None = None
    parameters: dict[str, Any] | None = None
```

### Analysis Response

```python
class AnalyzeActigraphyResponse(BaseSchema):
    """Schema for actigraphy analysis response."""
    analysis_id: uuid.UUID
    patient_id: str
    time_range: dict[str, datetime]
    results: list[ActigraphyAnalysisResult]
```

### Analysis Result

```python
class ActigraphyAnalysisResult(BaseSchema):
    """Results of a specific type of actigraphy analysis."""
    analysis_type: AnalysisType
    analysis_time: datetime
    sleep_metrics: SleepMetrics | None = None
    activity_metrics: ActivityMetrics | None = None
    circadian_metrics: CircadianMetrics | None = None
    raw_results: dict[str, Any] | None = None
```

### Various Metrics

```python
class SleepMetrics(BaseSchema):
    """Sleep metrics derived from actigraphy data."""
    total_sleep_time: float  # in minutes
    sleep_efficiency: float  # percentage
    sleep_latency: float  # in minutes
    wake_after_sleep_onset: float  # in minutes
    sleep_stage_duration: dict[SleepStage, float]  # in minutes
    number_of_awakenings: int

class ActivityMetrics(BaseSchema):
    """Activity metrics derived from actigraphy data."""
    total_steps: int
    active_minutes: float
    sedentary_minutes: float
    energy_expenditure: float  # in calories
    peak_activity_times: list[datetime]

class CircadianMetrics(BaseSchema):
    """Circadian rhythm metrics derived from actigraphy data."""
    rest_onset_time: datetime
    activity_onset_time: datetime
    rhythm_stability: float  # 0-1 scale
    interdaily_stability: float
    intradaily_variability: float
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
3. **Audit Logging**: All PHI access is logged using the audit_log_phi_access function
4. **Data Minimization**: Only necessary information is collected and processed

## Architectural Refinement Opportunities

### Current Architectural Issues

1. **Interface Duplication**: Two parallel interfaces (`ActigraphyServiceInterface` and `IPATService`) with different method signatures
2. **Layer Violations**: Service interface defined inline in presentation layer rather than imported from core layer
3. **Testing Code in Production**: Mock implementation in route files rather than segregated in test layers
4. **Inconsistent Method Signatures**: The interfaces have different method parameters

### Implementation Roadmap for Architectural Purity

1. **Interface Consolidation**: Migrate to a single interface in the core layer
2. **Factory Pattern Implementation**: Create proper factory for actigraphy service implementations
3. **Separate Test Implementations**: Move mock implementations to dedicated test modules
4. **Consistent Parameter Approach**: Standardize on either discrete parameters or a request object pattern

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
