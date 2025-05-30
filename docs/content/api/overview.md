# API Overview

## API Structure

The Clarity AI REST API follows a versioned structure with the following endpoints:

```
/api/v1/
├── auth/                   # Authentication endpoints
├── biometric-alerts/       # Biometric alerting system
├── biometric-alert-rules/  # Alert rule management
├── analytics/              # Analytics data and events
├── actigraphy/             # Actigraphy data processing
├── biometrics/             # Biometric data endpoints
├── ml/                     # Machine learning services
├── mentallama/             # MentaLLaMA AI integration
├── temporal-neurotransmitter/ # Temporal analysis
├── xgboost/                # XGBoost ML endpoints
├── digital-twins/          # Digital twin models
└── patients/               # Patient management
```

## Implementation Status

This documentation clearly indicates the implementation status of each endpoint:

- ✅ **Fully Implemented**: Endpoint is fully functional with complete implementation
- 🚧 **Partially Implemented**: Endpoint exists but has incomplete functionality
- 📝 **Route Defined**: API route exists but implementation may be minimal
- 🔮 **Planned**: Endpoint is planned but not yet implemented

## Authentication

### JWT Authentication (✅ Fully Implemented)

```
POST /api/v1/auth/token
```

**Request:**
```json
{
  "username": "provider@example.com",
  "password": "secure_password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

### Logout (✅ Fully Implemented)

```
POST /api/v1/auth/logout
```

Blacklists the current token for security.

## Biometric Alert Endpoints

### Get Alerts (✅ Fully Implemented)

```
GET /api/v1/biometric-alerts?patient_id={patient_id}&status={status}
```

**Response:**
```json
{
  "items": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174002",
      "patient_id": "123e4567-e89b-12d3-a456-426614174000",
      "rule_id": "123e4567-e89b-12d3-a456-426614174003",
      "status": "new",
      "severity": "high",
      "metric_type": "heart_rate",
      "metric_value": 120.5,
      "created_at": "2025-05-24T10:30:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "size": 10
}
```

### Update Alert Status (✅ Fully Implemented)

```
PATCH /api/v1/biometric-alerts/{alert_id}/status
```

**Request:**
```json
{
  "status": "acknowledged",
  "notes": "Patient contacted"
}
```

## Biometric Alert Rules

### List Alert Rules (🚧 Partially Implemented)

```
GET /api/v1/biometric-alert-rules?patient_id={patient_id}
```

### Create Alert Rule (🚧 Partially Implemented)

```
POST /api/v1/biometric-alert-rules
```

## Digital Twin Endpoints

### Get Digital Twin (📝 Route Defined)

```
GET /api/v1/digital-twins/{twin_id}
```

### Update Digital Twin (📝 Route Defined)

```
PATCH /api/v1/digital-twins/{twin_id}
```

## Patient Endpoints

### Get Patient (📝 Route Defined)

```
GET /api/v1/patients/{patient_id}
```

### Create Patient (📝 Route Defined)

```
POST /api/v1/patients
```

## API Security

### Authentication

- JWT tokens required for all protected endpoints
- Tokens expire after configurable timeout (default: 30 minutes)
- Refresh tokens available for continuous sessions
- Token blacklisting on logout

### Authorization

- Role-based access control (Provider, Patient, Admin)
- Resource-based permissions for patient data
- Provider access limited to assigned patients

### Rate Limiting

The API includes rate limiting to prevent abuse:

- IP-based rate limiting for public endpoints
- User-based rate limiting for authenticated endpoints
- Tiered limits based on endpoint sensitivity

### Request Validation

All requests are validated using Pydantic models:

- Schema validation for all requests
- Strong typing with Pydantic models
- Input sanitization for all fields

## HIPAA Compliance

The API implements several measures to ensure HIPAA compliance:

- No PHI in URLs or query parameters
- All PHI encrypted in transit (TLS)
- Comprehensive audit logging of PHI access
- Sanitization of PHI in error responses
- Session timeouts for security
- Authentication and authorization for all PHI access