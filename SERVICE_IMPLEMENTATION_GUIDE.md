# Service Implementation Guide

> **Last Updated**: May 19, 2025

## Implementation Priority

Based on the detailed test examination, these services must be implemented in this order to unblock skipped tests:

1. **AlertRuleTemplateService** - Critical for template-based rule creation
2. **AlertRuleService** - Required for CRUD operations on biometric alert rules

## AlertRuleTemplateService Implementation

### Required Methods

#### `apply_template`

```python
async def apply_template(
    self, 
    template_id: str, 
    patient_id: UUID, 
    customization: Dict[str, Any]
) -> Dict[str, Any]:
    """Create alert rule from template with customizations"""
```

#### `get_templates`

```python
async def get_templates(
    self,
    limit: int = 100,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """Get available alert rule templates"""
```

### Test Requirements

Examination of `test_create_alert_rule_from_template` shows these requirements:

1. **Input Format**: Template data wrapped in `template_data` field
2. **UUID Handling**: Convert string template_id to UUID for repository lookup
3. **Customization Processing**: Apply threshold_value overrides to conditions
4. **Response Format**: Return complete rule with conditions and metadata

### Specific Implementation Details

```python
async def apply_template(
    self, 
    template_id: str, 
    patient_id: UUID, 
    customization: Dict[str, Any]
) -> Dict[str, Any]:
    # Validate template exists
    template = await self.template_repository.get_by_id(UUID(template_id))
    if not template:
        raise ApplicationError(
            code=ErrorCode.RESOURCE_NOT_FOUND,
            message=f"Template with ID {template_id} not found"
        )
    
    # Create rule base from template
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
    
    # Apply custom thresholds
    threshold_values = customization.get("threshold_value", {})
    for condition_template in template.condition_templates:
        metric_name = condition_template.metric_name
        threshold = threshold_values.get(metric_name, condition_template.default_threshold)
        
        rule_data["conditions"].append({
            "metric_name": metric_name,
            "comparator_operator": condition_template.comparator_operator,
            "threshold_value": threshold,
            "duration_minutes": condition_template.duration_minutes,
            "description": condition_template.description
        })
    
    # Default to AND logic
    rule_data["logical_operator"] = "and"
    
    return rule_data
```

## AlertRuleService Implementation

### Required Methods

Based on test examination, these methods are needed:

```python
async def get_rules(self, patient_id: Optional[UUID] = None, is_active: Optional[bool] = None) -> List[Dict[str, Any]]
async def get_rule_by_id(self, rule_id: UUID) -> Optional[Dict[str, Any]]
async def create_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]
async def update_rule(self, rule_id: UUID, rule_data: Dict[str, Any]) -> Dict[str, Any]
async def delete_rule(self, rule_id: UUID) -> bool
async def update_rule_active_status(self, rule_id: UUID, is_active: bool) -> Dict[str, Any]
```

### Test Requirements

Specific requirements from test examination:

1. **Create Rule**: Support for custom condition-based rules with validation
2. **Get Rule**: UUID-based lookup with proper 404 handling
3. **Update Rule**: Partial updates including condition modifications
4. **Delete Rule**: Complete removal with proper security checks

### Implementation Guide

#### Rule Creation

```python
async def create_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
    # Validate patient existence
    patient_id = UUID(rule_data["patient_id"])
    patient_exists = await self.patient_repository.exists(patient_id)
    if not patient_exists:
        raise ApplicationError(
            code=ErrorCode.RESOURCE_NOT_FOUND,
            message=f"Patient with ID {patient_id} not found"
        )
    
    # Create the rule entity
    rule = BiometricAlertRule(
        id=uuid.uuid4(),
        name=rule_data["name"],
        description=rule_data.get("description", ""),
        patient_id=patient_id,
        conditions=[
            RuleCondition(
                metric_name=c["metric_name"],
                comparator_operator=c["comparator_operator"],
                threshold_value=c["threshold_value"],
                duration_minutes=c.get("duration_minutes", 0)
            )
            for c in rule_data.get("conditions", [])
        ],
        logical_operator=rule_data.get("logical_operator", "and"),
        priority=rule_data.get("priority", "medium"),
        is_active=rule_data.get("is_active", True),
        created_at=datetime.now(timezone.utc)
    )
    
    # Validate rule has conditions
    if not rule.conditions:
        raise ApplicationError(
            code=ErrorCode.INVALID_INPUT,
            message="Rule must have at least one condition"
        )
    
    # Save to repository
    saved_rule = await self.rule_repository.create(rule)
    
    # Return as dictionary
    return self._to_dict(saved_rule)
```

#### Rule Retrieval

```python
async def get_rules(
    self, 
    patient_id: Optional[UUID] = None,
    is_active: Optional[bool] = None
) -> List[Dict[str, Any]]:
    # Apply filters
    filters = {}
    if patient_id is not None:
        filters["patient_id"] = patient_id
    if is_active is not None:
        filters["is_active"] = is_active
    
    # Get rules from repository
    rules = await self.rule_repository.get_by_filters(**filters)
    
    # Convert to dictionaries
    return [self._to_dict(rule) for rule in rules]

async def get_rule_by_id(self, rule_id: UUID) -> Optional[Dict[str, Any]]:
    rule = await self.rule_repository.get_by_id(rule_id)
    if not rule:
        return None
    
    return self._to_dict(rule)
```

## Repository Implementation

The services depend on properly implemented repositories:

```python
class BiometricAlertRuleRepository(AbstractRepository[BiometricAlertRule]):
    async def get_by_id(self, id: UUID) -> Optional[BiometricAlertRule]:
        """Get a rule by ID"""
        query = select(BiometricAlertRuleModel).where(BiometricAlertRuleModel.id == id)
        result = await self.session.execute(query)
        db_rule = result.scalars().first()
        
        if not db_rule:
            return None
            
        return self._to_entity(db_rule)
        
    async def get_by_filters(self, **kwargs) -> List[BiometricAlertRule]:
        """Get rules by filters"""
        query = select(BiometricAlertRuleModel)
        
        for key, value in kwargs.items():
            if hasattr(BiometricAlertRuleModel, key):
                query = query.where(getattr(BiometricAlertRuleModel, key) == value)
                
        result = await self.session.execute(query)
        db_rules = result.scalars().all()
        
        return [self._to_entity(rule) for rule in db_rules]
```

## HIPAA Compliance Requirements

From test examination, these HIPAA safeguards must be implemented:

1. **No PHI in URLs**: Use UUIDs for all identifiers
2. **Error Sanitization**: No PHI in error messages
3. **Access Controls**: Verify auth token on each request
4. **Audit Logging**: Log all rule creation/modification actions
5. **Data Validation**: Strict schema validation for all inputs

## Dependency Injection Configuration

Register both services in the DI container:

```python
def get_alert_rule_template_service(db_session = Depends(get_db_session)) -> AlertRuleTemplateService:
    """Get alert rule template service"""
    template_repo = get_repository_instance(BiometricAlertTemplateRepository, db_session)
    return AlertRuleTemplateService(template_repo)

def get_alert_rule_service(db_session = Depends(get_db_session)) -> AlertRuleService:
    """Get alert rule service"""
    rule_repo = get_repository_instance(BiometricAlertRuleRepository, db_session)
    patient_repo = get_repository_instance(PatientRepository, db_session)
    return AlertRuleService(rule_repo, patient_repo)
```

## Recommended Implementation Order

1. Complete the repositories first (BiometricAlertTemplateRepository, BiometricAlertRuleRepository)
2. Implement AlertRuleTemplateService.apply_template to enable template-based creation
3. Implement AlertRuleService.create_rule to enable condition-based creation
4. Add remaining service methods in this order:
   - get_rule_by_id (simplest retrieval method)
   - get_rules (filtered retrieval)
   - update_rule (partial updates)
   - delete_rule (removal with validation)
   - update_rule_active_status (simple status toggle)

---

⚡ Clarity-AI Service Implementation Guide v1.0
