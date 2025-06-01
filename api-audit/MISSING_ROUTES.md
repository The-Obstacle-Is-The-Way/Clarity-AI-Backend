# Missing Routes Documentation

## Overview of Missing Routes

This document details all the API routes that are referenced in tests, imports, or the main router but are missing proper implementation. These issues are causing test failures and creating inconsistencies in the API structure.

## Critical Missing Routes

### 1. Actigraphy Endpoints

**Status**: Partially implemented

The `actigraphy.py` file exists in both `routes/` and `endpoints/` directories, but the implementation in the `routes/` directory is being used in the main router while tests may be referencing the `endpoints/` version. This causes confusion and potential test failures.

**Referenced In**:
- Main router (`api_router.py`): `from app.presentation.api.v1.routes.actigraphy import router as actigraphy_router`
- Tests: Referenced in test memory but actual test file location could not be found

**Required Actions**:
- Standardize on a single implementation location
- Ensure all required endpoints are implemented
- Update tests to reference the standardized location

### 2. Digital Twin Endpoints

**Status**: Partially implemented

The route file exists at `routes/digital_twin.py` but may be missing required endpoints based on test references.

**Referenced In**:
- Main router (`api_router.py`): `from app.presentation.api.v1.routes.digital_twin.py import router as digital_twin_router`
- Memory reference: "The API endpoint file for the digital twin (expected at `app/api/routes/digital_twin.py` or `app/presentation/api/v1/endpoints/digital_twin.py`) is currently missing."

**Required Actions**:
- Confirm all required endpoints are implemented according to test expectations
- Standardize location to either `routes/` or `endpoints/` directory
- Ensure proper error handling and HIPAA compliance

### 3. Biometric Alert Rules Endpoints

**Status**: Implementation exists but may be incomplete

The file exists at `endpoints/biometric_alert_rules.py` but tests indicate there may be missing functionality.

**Referenced In**:
- Main router (`api_router.py`): `from app.presentation.api.v1.endpoints.biometric_alert_rules import router as biometric_alert_rules_router_endpoint`
- Memory reference: "The import and `include_router` call in `app/presentation/api/v1/api_router.py` have been temporarily commented out to allow test collection to proceed."

**Missing Endpoints**:
- `PATCH /alerts/{id}/status` - Referenced in tests but not implemented
- `POST /patients/{id}/trigger` - Referenced in tests but not implemented

**Required Actions**:
- Implement missing endpoints
- Ensure consistent dependency injection
- Verify HIPAA compliance in error handling

### 4. Patient Endpoints

**Status**: Partially implemented

The route file exists at `routes/patient.py` but tests suggest missing functionality. SPARC analysis confirms this with evidence of TODO comments and placeholder implementations.

**Referenced In**:
- Main router (`api_router.py`): `from app.presentation.api.v1.routes.patient import router as patient_router`
- Memory reference: "The API route file `app/presentation/api/v1/routes/patient.py` is missing. Imports in the corresponding test file `app/tests/unit/presentation/api/v1/endpoints/test_patient_endpoints.py` have been temporarily commented out to allow test collection."

**SPARC Findings**:
```python
router = APIRouter()

# TODO: Implement patient endpoints
@router.post("/")
async def create_patient_endpoint(
    patient_data: dict[str, Any]) -> dict[str, Any]:
    """To be implemented."""
    pass
```

**Required Actions**:
- Complete implementation of all required endpoints
- Remove placeholder code and TODOs
- Ensure proper dependency injection with `get_patient_service`
- Verify that test imports can be uncommented and tests pass
- Add proper request validation with Pydantic models

## Other Missing or Problematic Routes

### 1. MentaLLaMA Endpoints

**Status**: Unknown - needs verification

**Referenced In**:
- Main router (`api_router.py`): `from app.presentation.api.v1.routes.mentallama import router as mentallama_router`

**Required Actions**:
- Verify implementation completeness
- Ensure standardized structure and naming

### 2. Temporal Neurotransmitter Endpoints

**Status**: Unknown - needs verification

**Referenced In**:
- Main router (`api_router.py`): `from app.presentation.api.v1.routes.temporal_neurotransmitter import router as temporal_neurotransmitter_router`

**Required Actions**:
- Verify implementation completeness
- Ensure standardized structure and naming

## Implementation Priorities

Based on test failures and system criticality, the implementation priorities should be:

1. **Patient Endpoints** - Core functionality needed for most other features
2. **Biometric Alert Rules** - Critical for alert functionality and referenced by multiple tests
3. **Actigraphy Endpoints** - Important for data collection and analysis
4. **Digital Twin Endpoints** - Central to the platform's unique value proposition
5. **Other Endpoints** - To be addressed after core functionality is stable

## Implementation Guidelines

When implementing missing routes:

1. Follow Clean Architecture principles
2. Maintain HIPAA compliance, especially in error handling
3. Use consistent dependency injection patterns
4. Implement comprehensive validation
5. Ensure proper authentication and authorization
6. Add appropriate logging and audit trails

For each route, consider these questions:
- Is it properly authenticated?
- Does it validate input data?
- Does it handle errors without exposing PHI?
- Does it follow the established naming and structure conventions?
- Is it properly tested?

See [Standardization Plan](./STANDARDIZATION_PLAN.md) for detailed implementation steps.
