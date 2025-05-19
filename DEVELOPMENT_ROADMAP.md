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

## 3. Testing Infrastructure Improvements (Lower Priority)

### ML Testing Environment

**Status**: Not started  
**Affected Files**: 11 skipped ML-related tests

**Implementation Tasks**:
- Create containerized ML testing environment with PyTorch
- Configure CI pipeline for ML-specific tests
- Document ML test setup requirements

### Integration Testing Infrastructure

**Status**: Not started  
**Affected Files**: 7 skipped integration tests

**Implementation Tasks**:
- Create Docker Compose environment for database tests
- Set up mock AWS services for integration testing
- Configure Temporal workflow testing environment

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
