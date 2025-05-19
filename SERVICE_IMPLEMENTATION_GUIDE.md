# Service Implementation Guide

> **Last Updated**: May 19, 2025

## Implementation Priority

The current development focus is on implementing two critical services that are blocking several tests:

1. **AlertRuleTemplateService** - For applying templates to create customized biometric alert rules
2. **AlertRuleService** - For CRUD operations on biometric alert rules

## AlertRuleTemplateService Implementation

### Interface Definition

```python
class AlertRuleTemplateServiceInterface(Protocol):
    """Interface for alert rule template service operations."""
    
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
        ...
```

### Implementation Steps

1. **Retrieve template from repository**
   - Convert template_id string to UUID
   - Use repository to fetch template
   - Raise appropriate error if template not found

2. **Apply customizations**
   - Extract threshold values from customization
   - Apply priority overrides if provided
   - Set rule metadata (name, description, etc.)

3. **Create condition instances**
   - For each condition template, create a condition
   - Apply threshold overrides where specified
   - Maintain original values where no override exists

4. **Return structured rule data**
   - Format as dictionary matching expected schema
   - Generate new UUID for rule ID
   - Include timestamp for creation date

### Example Implementation

```python
async def apply_template(
    self, 
    template_id: str, 
    patient_id: UUID, 
    customization: Dict[str, Any]
) -> Dict[str, Any]:
    """Apply a template with customizations to create a new alert rule."""
    # 1. Retrieve template from repository
    try:
        template_uuid = UUID(template_id)
    except ValueError:
        raise ApplicationError(
            code=ErrorCode.INVALID_INPUT,
            message=f"Invalid template ID format: {template_id}"
        )
        
    template = await self.template_repository.get_by_id(template_uuid)
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

## AlertRuleService Implementation

### Interface Definition

```python
class AlertRuleServiceInterface(Protocol):
    """Interface for alert rule service operations."""
    
    async def get_rules(
        self, 
        patient_id: Optional[UUID] = None,
        is_active: Optional[bool] = None,
        priority: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get alert rules with optional filtering."""
        ...
    
    async def get_rule_by_id(self, rule_id: UUID) -> Optional[Dict[str, Any]]:
        """Get a specific rule by ID."""
        ...
    
    async def create_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new alert rule."""
        ...
    
    async def update_rule(self, rule_id: UUID, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing alert rule."""
        ...
    
    async def delete_rule(self, rule_id: UUID) -> bool:
        """Delete an alert rule."""
        ...
    
    async def update_rule_active_status(self, rule_id: UUID, is_active: bool) -> Dict[str, Any]:
        """Update the active status of a rule."""
        ...
```

### Implementation Steps

1. **Repository Methods**
   - Implement all required repository methods first
   - Ensure proper error handling for database operations
   - Add transaction support where needed

2. **Service Methods**
   - Map from raw data to domain entities
   - Validate inputs before processing
   - Return consistent data structures

3. **Edge Cases**
   - Handle duplicate rule names
   - Validate rule conditions
   - Check for patient existence

### Example Implementation

```python
async def create_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a new alert rule.
    
    Args:
        rule_data: Alert rule data
        
    Returns:
        Created alert rule data
        
    Raises:
        ApplicationError: If rule data is invalid
    """
    # 1. Validate patient existence
    patient_id = UUID(rule_data["patient_id"])
    patient_exists = await self.patient_repository.exists(patient_id)
    if not patient_exists:
        raise ApplicationError(
            code=ErrorCode.RESOURCE_NOT_FOUND,
            message=f"Patient with ID {patient_id} not found"
        )
    
    # 2. Create rule entity
    try:
        rule = BiometricAlertRule(
            id=UUID(rule_data.get("id")) if rule_data.get("id") else uuid.uuid4(),
            name=rule_data["name"],
            description=rule_data.get("description", ""),
            patient_id=patient_id,
            conditions=[
                RuleCondition(
                    metric_name=c["metric_name"],
                    comparator_operator=c["comparator_operator"],
                    threshold_value=c["threshold_value"],
                    duration_minutes=c.get("duration_minutes", 0),
                    description=c.get("description", "")
                )
                for c in rule_data.get("conditions", [])
            ],
            logical_operator=rule_data.get("logical_operator", "and"),
            priority=rule_data.get("priority", "medium"),
            is_active=rule_data.get("is_active", True),
            created_at=datetime.now(timezone.utc),
            template_id=UUID(rule_data["template_id"]) if rule_data.get("template_id") else None
        )
    except (KeyError, ValueError) as e:
        raise ApplicationError(
            code=ErrorCode.INVALID_INPUT,
            message=f"Invalid rule data: {str(e)}"
        )
    
    # 3. Validate rule has at least one condition
    if not rule.conditions:
        raise ApplicationError(
            code=ErrorCode.INVALID_INPUT,
            message="Rule must have at least one condition"
        )
    
    # 4. Save to repository
    saved_rule = await self.rule_repository.create(rule)
    
    # 5. Return as dictionary
    return {
        "id": str(saved_rule.id),
        "name": saved_rule.name,
        "description": saved_rule.description,
        "patient_id": str(saved_rule.patient_id),
        "conditions": [
            {
                "id": str(c.id) if c.id else None,
                "metric_name": c.metric_name,
                "comparator_operator": c.comparator_operator,
                "threshold_value": c.threshold_value,
                "duration_minutes": c.duration_minutes,
                "description": c.description
            }
            for c in saved_rule.conditions
        ],
        "logical_operator": saved_rule.logical_operator,
        "priority": saved_rule.priority,
        "is_active": saved_rule.is_active,
        "created_at": saved_rule.created_at.isoformat(),
        "template_id": str(saved_rule.template_id) if saved_rule.template_id else None
    }
```

## Testing Strategy

### Unit Tests

1. **Service Method Tests**
   - Test each method with valid inputs
   - Test error handling for invalid inputs
   - Test edge cases (empty lists, etc.)

2. **Repository Mock Tests**
   - Create proper mocks for repository methods
   - Test service with mocked repositories
   - Verify repository method calls

### Integration Tests

1. **Database Tests**
   - Test with real database connections
   - Verify data persistence
   - Test transactions and rollbacks

2. **API Tests**
   - Test endpoints with service integration
   - Verify error responses
   - Test data validation

## Dependency Injection

Register services in the dependency injection container:

```python
# In dependencies.py or similar

def get_alert_rule_template_service(
    db_session = Depends(get_db_session),
) -> AlertRuleTemplateService:
    """Get alert rule template service with repository."""
    template_repo = get_repository_instance(BiometricAlertTemplateRepository, db_session)
    return AlertRuleTemplateService(template_repo)

def get_alert_rule_service(
    db_session = Depends(get_db_session),
) -> AlertRuleService:
    """Get alert rule service with repositories."""
    rule_repo = get_repository_instance(BiometricAlertRuleRepository, db_session)
    patient_repo = get_repository_instance(PatientRepository, db_session)
    return AlertRuleService(rule_repo, patient_repo)
```

## HIPAA Compliance Checks

Ensure all implementations adhere to HIPAA requirements:

1. **No PHI in Logs**
   - Use UUIDs for identification
   - No personal information in error messages

2. **Access Controls**
   - Add permission checks in services
   - Log all access to PHI

3. **Data Validation**
   - Strict validation of all inputs
   - Sanitization of outputs

4. **Audit Trails**
   - Log all operations on alert rules
   - Include provider ID for all changes

---

⚡ Clarity-AI Service Implementation Guide v1.0
