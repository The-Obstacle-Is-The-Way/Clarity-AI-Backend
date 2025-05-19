# Biometric Alert Rules Implementation

> **Last Updated**: May 19, 2025

[![Code Status](https://img.shields.io/badge/status-implemented-brightgreen)](https://github.com/Clarity-AI-Backend/) [![Test Status](https://img.shields.io/badge/tests-passing-brightgreen)](https://github.com/Clarity-AI-Backend/)

## Overview

The Biometric Alert Rules system is a critical component of the Clarity-AI Digital Twin platform that monitors patient biometric data in real-time and generates clinically-relevant alerts based on predefined rules and templates. This document details the implementation of the biometric alert rules API endpoints, services, and domain models.

## Architecture

The biometric alert rules system follows clean architecture principles with strict separation of concerns:

```
┌──────────────────────┐      ┌──────────────────────────┐
│ Presentation Layer   │──────▶│ Application Layer        │
│ (FastAPI Endpoints)  │      │ (AlertRuleTemplateService│
│                      │◀─────│ AlertRuleService)        │
└──────────────────────┘      └──────────────────────────┘
           ▲                              │
           │                              ▼
┌──────────────────────┐      ┌──────────────────────────┐
│ Infrastructure Layer │◀─────▶│ Domain Layer            │
│ (Repositories)       │      │ (BiometricAlertRule,     │
│                      │      │ AlertTemplate)           │
└──────────────────────┘      └──────────────────────────┘
```

## Domain Models

### BiometricAlertRule

The `BiometricAlertRule` entity represents a specific monitoring rule applied to a patient's biometric data.

Key attributes:
- **ID**: Unique identifier for the rule
- **Template ID**: ID of the template this rule was created from (if any)
- **Patient ID**: The patient this rule applies to
- **Conditions**: List of threshold conditions for various metrics
- **Priority**: Clinical priority of the alert (high, medium, low)
- **Logical Operator**: How conditions should be combined (AND/OR)
- **Is Active**: Whether the rule is currently active

### RuleCondition

Each rule contains one or more conditions that define thresholds for specific biometric metrics:

- **Metric Name**: The biometric metric being monitored (heart_rate, blood_pressure, etc.)
- **Comparator Operator**: The comparison operation (greater_than, less_than, etc.)
- **Threshold Value**: The value that triggers the alert when crossed
- **Duration Minutes**: Optional time duration the condition must be met before triggering

## Templates System

The template system allows clinicians to create alert rules from predefined templates, with customizations for individual patients.

### Template Customization

The template customization model allows specifying:
- **Threshold Values**: Custom thresholds for specific metrics
- **Priority**: Customized priority level for the alerts
- **Provider ID**: The healthcare provider creating the rule

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/biometric-alert-rules` | GET | List all alert rules with optional filtering |
| `/api/v1/biometric-alert-rules/{rule_id}` | GET | Get a specific alert rule by ID |
| `/api/v1/biometric-alert-rules` | POST | Create a new alert rule |
| `/api/v1/biometric-alert-rules/from-template` | POST | Create a rule from a template |
| `/api/v1/biometric-alert-rules/{rule_id}` | PUT | Update an existing alert rule |
| `/api/v1/biometric-alert-rules/{rule_id}` | DELETE | Delete an alert rule |
| `/api/v1/biometric-alert-rules/{rule_id}/active` | PATCH | Update the active status of a rule |

## Service Implementation

### AlertRuleTemplateService

The `AlertRuleTemplateService` handles the creation of alert rules from templates with customizations.

Key methods:
- `apply_template`: Creates a new rule from a template with customizations

```python
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
    """
    # Implementation logic here
```

### AlertRuleService

The `AlertRuleService` provides CRUD operations for managing alert rules.

Key methods:
- `get_rules`: Retrieve rules with optional filtering
- `get_rule_by_id`: Get a specific rule by ID
- `create_rule`: Create a new rule
- `update_rule`: Update an existing rule
- `delete_rule`: Delete a rule
- `update_rule_active_status`: Update a rule's active status

## HIPAA Compliance Considerations

The biometric alert rules system implements several HIPAA compliance safeguards:

1. **Data Protection**:
   - No PHI in URLs or error messages
   - All UUIDs for sensitive identifiers

2. **Access Control**:
   - Authentication required for all endpoints
   - Role-based access control for rule management

3. **Audit Logging**:
   - All rule creations, modifications, and deletions are logged
   - Provider IDs tracked for all actions

4. **Input Validation**:
   - Strict schema validation with Pydantic
   - Parameterized queries for database access

## Testing

The biometric alert rule endpoints are tested with unit tests covering:

1. **Endpoint Tests**:
   - Rule creation, retrieval, update, and deletion
   - Template-based rule creation
   - Error handling

2. **Service Tests**:
   - Template application logic
   - Rule CRUD operations

3. **Repository Tests**:
   - Data persistence
   - Query filtering

## Implementation Notes

### Recent Fixes

1. **Router Configuration**:
   - Fixed router prefix to prevent duplicate URL paths
   - Ensured proper API route nesting

2. **Template Customization**:
   - Updated the payload format for template customization
   - Fixed schema validation for threshold values

3. **Mock Testing**:
   - Enhanced mock service testing with more flexible assertions
   - Fixed UUID handling in test payloads

### Future Enhancements

1. **Rule Evaluation Engine**:
   - Real-time rule evaluation against streaming biometric data
   - Integration with notification system

2. **ML-Based Rule Suggestions**:
   - Machine learning to suggest optimal thresholds based on patient history
   - Anomaly detection for unusual patterns

3. **Custom Rule Editor UI**:
   - Visual rule builder for clinicians
   - Rule effectiveness analytics

## Example Payload

Example request for creating a rule from template:

```json
{
  "template_data": {
    "template_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "patient_id": "3fa85f64-5717-4562-b3fc-2c963f66afa7",
    "customization": {
      "threshold_value": {
        "heart_rate": 110.0,
        "blood_pressure_systolic": 140.0
      },
      "priority": "high"
    }
  }
}
```

---

⚡ Generated by Clarity-AI Documentation System
