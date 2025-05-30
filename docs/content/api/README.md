# API Reference

## API Structure

The Clarity AI REST API follows a versioned structure with the following **currently implemented** endpoints:

```
/api/v1/
├── auth/                   # Authentication endpoints (IMPLEMENTED)
├── biometric-alerts/       # Biometric alerting system (IMPLEMENTED)
├── biometric-alert-rules/  # Alert rule management (ENDPOINT EXISTS)
├── analytics/              # Analytics data and events (IMPLEMENTED) 
├── actigraphy/             # Actigraphy data processing (ROUTES EXIST)
├── biometrics/             # Biometric data endpoints (ROUTES EXIST)
├── ml/                     # Machine learning services (ROUTES EXIST)
├── mentallama/             # MentaLLaMA AI integration (ROUTES EXIST)
├── temporal-neurotransmitter/ # Temporal analysis (ROUTES EXIST)
├── xgboost/                # XGBoost ML endpoints (ROUTES EXIST)
├── digital-twins/          # Digital twin models (ROUTES EXIST)
└── patients/               # Patient management (PLACEHOLDER ONLY)
```

**Note**: Some endpoints listed have route definitions but may have incomplete implementations.

## Authentication

### JWT Authentication

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

### Logout

```
POST /api/v1/auth/logout
```

Blacklists the current token for security.

## Biometric Alert Endpoints

### Get Alerts

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
      "created_at": "2025-05-24T10:23:54Z"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

### Create Alert

```
POST /api/v1/biometric-alerts
```

**Request:**

```json
{
  "patient_id": "123e4567-e89b-12d3-a456-426614174000",
  "rule_id": "123e4567-e89b-12d3-a456-426614174003",
  "metric_type": "heart_rate",
  "metric_value": 120.5
}
```

### Update Alert Status

```
PATCH /api/v1/biometric-alerts/{id}/status
```

**Request:**

```json
{
  "status": "acknowledged",
  "notes": "Patient contacted, monitoring situation"
}
```

## Biometric Alert Rules

### List Alert Rules

```
GET /api/v1/biometric-alert-rules
```

**Response:**

```json
{
  "items": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174003",
      "name": "Elevated Heart Rate",
      "metric_type": "heart_rate",
      "condition": "gt",
      "threshold": 100,
      "severity": "medium",
      "active": true
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20
}
```

### Create Alert Rule

```
POST /api/v1/biometric-alert-rules
```

**Request:**

```json
{
  "name": "Elevated Heart Rate",
  "metric_type": "heart_rate",
  "condition": "gt",
  "threshold": 100,
  "severity": "medium",
  "active": true
}
```

## Actigraphy Data

### Submit Actigraphy Data

```
POST /api/v1/actigraphy/{patient_id}/data
```

**Request:**

```json
{
  "device_id": "device_123456",
  "start_time": "2025-05-23T20:00:00Z",
  "end_time": "2025-05-24T08:00:00Z",
  "samples": [
    {
      "timestamp": "2025-05-23T20:15:00Z",
      "activity_level": 2.4,
      "step_count": 150
    },
    {
      "timestamp": "2025-05-23T20:30:00Z",
      "activity_level": 1.2,
      "step_count": 80
    }
  ]
}
```

### Get Sleep Analysis

```
GET /api/v1/actigraphy/{patient_id}/sleep?date=2025-05-23
```

**Response:**

```json
{
  "patient_id": "123e4567-e89b-12d3-a456-426614174000",
  "date": "2025-05-23",
  "sleep_duration_minutes": 465,
  "sleep_efficiency": 0.87,
  "sleep_onset": "2025-05-23T23:10:00Z",
  "wake_time": "2025-05-24T07:15:00Z",
  "interruptions": 3,
  "deep_sleep_percentage": 22.5,
  "rem_sleep_percentage": 18.3,
  "light_sleep_percentage": 59.2
}
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

- IP-based rate limiting for public endpoints
- User-based rate limiting for authenticated endpoints
- Tiered limits based on endpoint sensitivity

### Request Validation

- Schema validation for all requests
- Strong typing with Pydantic models
- Input sanitization for all fields

## API Versioning

The API uses URL path versioning (`/api/v1/`) to ensure backward compatibility as the system evolves.

### Versioning Strategy

1. **Minor Changes**: Non-breaking changes implemented in-place
2. **Major Changes**: New version with parallel support for previous version
3. **Deprecation Cycle**: 
   - Deprecated endpoints marked in documentation
   - Deprecation warning headers in responses
   - Minimum 6-month support for deprecated versions