# Development Roadmap

> **Last Updated**: May 19, 2025

## Strategic Implementation Plan

This document outlines the strategic approach to implementing missing components and addressing test issues in the Clarity-AI Backend. The roadmap is organized by priority and estimated effort to maximize development efficiency while ensuring HIPAA compliance and adherence to clean architecture principles.

## 1. Core Service Implementation (High Priority)

### AlertRuleTemplateService Implementation

**Status**: Partially implemented  
**Location**: `app/application/services/alert_rule_template_service.py`  
**Tests Blocked**: 2 tests in `test_biometric_alerts_endpoint.py`

**Implementation Tasks**:
- Complete the `apply_template()` method following the interface in `AlertRuleTemplateServiceInterface`
- Implement template retrieval from repository
- Add customization logic to apply user-defined parameters to templates
- Ensure proper error handling for missing templates
- Update service registration in dependency injection container

```python
# Example implementation for apply_template method
async def apply_template(
    self, 
    template_id: str, 
    patient_id: UUID, 
    customization: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Apply a template with customizations to create a new alert rule.
    
    Args:
        template_id: Template identifier
        patient_id: Patient this rule applies to
        customization: Template customization parameters
        
    Returns:
        New alert rule data
        
    Raises:
        ApplicationError: If template not found or customization invalid
    """
    # 1. Retrieve template from repository
    template = await self.template_repository.get_by_id(UUID(template_id))
    if not template:
        raise ApplicationError(
            code=ErrorCode.RESOURCE_NOT_FOUND,
            message=f"Template with ID {template_id} not found"
        )
    
    # 2. Create new rule from template with customizations
    rule_data = {
        "id": str(uuid.uuid4()),
        "template_id": template_id,
        "name": template.name,
        "description": template.description,
        "patient_id": str(patient_id),
        "conditions": [],
        "priority": customization.get("priority", template.default_priority),
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    # 3. Apply condition customizations
    threshold_values = customization.get("threshold_value", {})
    for condition_template in template.condition_templates:
        metric_name = condition_template.metric_name
        threshold = threshold_values.get(metric_name, condition_template.default_threshold)
        
        rule_data["conditions"].append({
            "metric_name": metric_name,
            "comparator_operator": condition_template.comparator_operator,
            "threshold_value": threshold,
            "duration_minutes": condition_template.duration_minutes,
            "description": condition_template.description,
            "id": None
        })
    
    # 4. Set logical operator (default to AND)
    rule_data["logical_operator"] = "and"
    
    return rule_data
```

### AlertRuleService Implementation

**Status**: Not implemented  
**Location**: `app/application/services/biometric_alert_rule_service.py`  
**Tests Blocked**: 5 tests in `test_biometric_alerts_endpoint.py`

**Implementation Tasks**:
- Create CRUD operations for alert rules
- Implement rule validation logic
- Add patient-specific rule filtering
- Ensure proper error handling for invalid rules
- Update service registration in dependency injection container

## 2. Warning Resolution (Medium Priority)

### Pydantic V2 Migration

**Status**: Partially completed  
**Affected Files**: Multiple files across the codebase

**Implementation Tasks**:
- Replace all instances of `.dict()` with `.model_dump()`
- Update any other deprecated Pydantic V1 patterns
- Priority locations:
  - `app/presentation/api/v1/endpoints/biometric_alert_rules.py` (Line 210)
  - Other endpoint files with validation logic

### HTTPX Client Modernization

**Status**: Not started  
**Affected Files**: Various test files

**Implementation Tasks**:
- Update test client initialization to use the recommended pattern:
```python
# Before
async with AsyncClient(app=app, base_url="http://test") as client:
    # test code

# After
async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
    # test code
```

### Asyncio Test Refactoring

**Status**: Not started  
**Affected Files**: Multiple test files

**Implementation Tasks**:
- Fix test event loop fixture redefinitions
- Update async test decorators

## 3. ML Component Implementation (Medium Priority)

### PyTorch-based Model Infrastructure

**Status**: Partially implemented  
**Affected Files**: Multiple ML test files  
**Tests Blocked**: 8 PyTorch-dependent test files

**Implementation Tasks**:

1. **Symptom Forecasting Service**
   - Implement ensemble architecture combining Transformer and XGBoost models
   - Add time series preprocessing for biometric data
   - Implement HIPAA-compliant data sanitization filters
   - Create visualization preprocessor for clinical dashboards
   - File: `app/infrastructure/ml/symptom_forecasting/model_service.py`

2. **Pharmacogenomics Models**
   - Complete gene-medication interaction prediction models
   - Implement treatment response forecasting
   - Add model versioning and performance tracking
   - Files: 
     - `app/infrastructure/ml/pharmacogenomics/gene_medication_model.py`
     - `app/infrastructure/ml/pharmacogenomics/treatment_model.py`

3. **MentaLLaMA Integration**
   - Update mock implementation to match new interface
   - Add prompt template management system
   - Implement HIPAA-compliant redaction for LLM inputs/outputs
   - File: `app/core/services/ml/mentallama/mentallama_service.py`

### AWS XGBoost Service

**Status**: Incomplete  
**Affected Files**: AWS XGBoost service tests  
**Tests Blocked**: 1 test file with multiple test cases

**Implementation Tasks**:
1. **AWS Client Integration**
   - Implement SageMaker client for model inference
   - Add S3 integration for model artifacts
   - Configure DynamoDB for prediction storage
   - File: `app/core/services/ml/xgboost/aws.py`

2. **Error Handling**
   - Implement comprehensive error handling for AWS service errors
   - Add retry logic for transient failures
   - Create detailed logging for HIPAA compliance
   - File: `app/core/services/ml/xgboost/exceptions.py`

3. **Risk Prediction Models**
   - Implement risk prediction interfaces
   - Add validation and verification workflows
   - Create model performance monitoring
   - File: `app/core/services/ml/xgboost/aws.py`

## 4. Integration Testing Infrastructure (Medium Priority)

### Temporal Neurotransmitter Testing

**Status**: Partially implemented  
**Affected Files**: Temporal integration tests  
**Tests Blocked**: 4 temporal neurotransmitter integration tests

**Implementation Tasks**:
1. **Mapping Service Updates**
   - Update mapping signature for brain region visualization
   - Implement complete neurotransmitter coverage
   - Add treatment simulation capabilities
   - File: `app/application/services/temporal_neurotransmitter_service.py`

2. **API Integration**
   - Complete endpoint implementation for neurotransmitter data
   - Add authentication integration
   - Implement query parameter validation
   - File: `app/presentation/api/v1/endpoints/neurotransmitter.py`

### Docker Database Environment

**Status**: Not started  
**Affected Files**: Database integration tests  
**Tests Blocked**: 2 database connection tests

**Implementation Tasks**:
- Create Docker Compose configuration for PostgreSQL
- Configure test database initialization scripts
- Add environment variable management for tests
- File: `docker-compose-test.yml`

### Mock Service Framework

**Status**: Partially implemented  
**Affected Files**: Various test files

**Implementation Tasks**:
- Implement consistent mocking framework for external services
- Add dynamic ID handling for test assertions
- Create flexible matching for test assertions
- File: `app/tests/utils/mock_helpers.py`

## 4. Code Quality Improvements (Continuous)

### Linting and Static Analysis

**Status**: Ongoing  
**Affected Files**: Codebase-wide

**Implementation Tasks**:
- Update flake8 configuration
- Implement pre-commit hooks
- Add typing annotations to improve mypy coverage

### Documentation Updates

**Status**: Ongoing  
**Affected Files**: Codebase-wide

**Implementation Tasks**:
- Complete API documentation
- Update architectural diagrams
- Add detailed HIPAA compliance documentation

## Timeline and Resource Allocation

### Phase 1: Core Service Implementation (1-2 weeks)
- Implement AlertRuleTemplateService
- Implement AlertRuleService
- Fix critical warnings

### Phase 2: Test Infrastructure (2-3 weeks)
- Set up ML testing environment
- Configure integration test infrastructure
- Fix remaining warnings

### Phase 3: Quality Improvements (Ongoing)
- Implement continuous linting
- Complete documentation
- Address technical debt

## HIPAA Compliance Considerations

All implementations must adhere to HIPAA compliance requirements:
- No PHI in URLs or logs
- All data encrypted at rest and in transit
- Proper audit logging
- Authentication and authorization
- Input/output sanitization

## Clean Architecture Guidelines

All implementations must follow clean architecture principles:
- Maintain strict layer separation
- Use dependency inversion
- Apply SOLID principles
- Follow repository pattern for data access
- Implement proper error handling at each layer

---

⚡ Generated by Clarity-AI Development Planning System
