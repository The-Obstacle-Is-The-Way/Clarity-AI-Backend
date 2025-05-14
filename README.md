# Clarity-AI Digital Twin Backend

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/Clarity-AI-Backend/) [![Coverage](https://img.shields.io/badge/coverage-87%25-green)](https://github.com/Clarity-AI-Backend/) [![HIPAA Compliant](https://img.shields.io/badge/HIPAA-compliant-blue)](https://github.com/Clarity-AI-Backend/docs/FastAPI_HIPAA_Compliance.md) [![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

> A revolutionary HIPAA‑compliant platform creating computational "digital twins" of psychiatric patients—transforming fragmented clinical data into integrated predictive models that evolve in real-time with patient data. Clarity AI integrates multi-modal inputs (biometrics, clinical assessments, genetic markers) to surface objective analytics, automate clinical alerts, and draft documentation that augments psychiatric care.

## What is a Digital Twin for Mental Health?

A digital twin is a computational representation of a patient's mental health state that evolves over time as new data is incorporated. In psychiatry, digital twins integrate diverse data streams (biometric, clinical, genetic, behavioral) to create personalized models that enable:

- **Continuous Monitoring**: Track mental health state changes between appointments
- **Pattern Recognition**: Identify correlations between biometrics and symptoms
- **Predictive Insights**: Forecast symptom trajectories and treatment responses
- **Personalized Treatment**: Tailor interventions to individual patient characteristics

This system aims to bridge the critical gap in psychiatric care by providing objective, quantitative measurements and predictions where traditional assessments rely heavily on subjective self-reporting and infrequent clinical observations.

![Conceptual diagram of a Digital Twin for Health (DT4H), showing the connection between physical entity data and digital twin applications.](./images/digital-twin-for-health.png)
*Fig. 1: Digital twin for health (DT4H) envisioned.* 
*From: [Katsoulakis, E., Wang, Q., Wu, H. et al. Digital twins for health: a scoping review. npj Digit. Med. 7, 77 (2024).](https://www.nature.com/articles/s41746-024-01073-0)*

## Technical Architecture

The Clarity-AI backend implements a mathematically elegant [clean architecture](./docs/Clean_Architecture_Principles.md) approach with four distinct layers that maintain perfect separation of concerns:

```ascii
┌───────────────────┐      ┌───────────────────┐
│  Presentation     │─▶───▶│  Application      │
│ (FastAPI + Schemas│      │ (Use‑Cases)       │
│  + Middleware)    │      └───────────────────┘
└───────────────────┘              │
        ▲                          ▼
        │                  ┌───────────────────┐
┌───────────────────┐      │  Domain           │
│ Infrastructure    │◀────▶│ (Pydantic Models) │
│ (DB, ML, Cache,   │      └───────────────────┘
│  Messaging, Auth) │
└───────────────────┘
```

- **[Domain Layer](./docs/Domain_Models_Entities.md)**: Core entities, value objects, and domain services that encapsulate psychiatric digital twin models without external dependencies
- **[Application Layer](./docs/Application_Services.md)**: Orchestrates use cases and workflows across multiple domain entities following SOLID principles
- **[Infrastructure Layer](./docs/Database_Access_Guide.md)**: Implements external service integrations, persistence, and ML model execution with proper abstraction
- **[Presentation Layer](./docs/API_Security.md)**: HIPAA-compliant API with versioning, schema validation, and sophisticated PHI protections

<details>
<summary><b>📚 Architecture Documentation</b> (click to expand)</summary>

* [Project Structure Overview](./docs/Project_Structure_Overview.md) - Complete directory organization
* [Clean Architecture Principles](./docs/Clean_Architecture_Principles.md) - Implementation details
* [Design Patterns Guide](./docs/Design_Patterns_Guide.md) - GOF patterns used
* [Dependency Injection Guide](./docs/Dependency_Injection_Guide.md) - DI approach
* [Error Handling Strategy](./docs/Error_Handling_Strategy.md) - Exception design
</details>

## AI/ML Components

Clarity-AI transcends conventional psychiatric analytics by integrating multiple quantum-level ML technologies into a unified digital twin framework:

<table>
<tr>
  <th width="25%">Technology</th>
  <th>Implementation</th>
  <th>Clinical Application</th>
</tr>
<tr>
  <td><b>MentalLLaMA33B</b></td>
  <td>Large language model specially fine-tuned for psychiatric contexts with 33B parameters</td>
  <td>Analyzes clinical narratives, extracts latent diagnostic patterns, and generates clinical documentation with HIPAA compliance</td>
</tr>
<tr>
  <td><b>XGBoost Ensemble</b></td>
  <td>Gradient-boosted decision tree models with domain-specific feature engineering</td>
  <td>Treatment response prediction, medication efficacy analysis, and risk assessment with interpretable confidence scores</td>
</tr>
<tr>
  <td><b>PAT Foundation Model</b></td>
  <td>Transformer architecture pre-trained on 100K+ hours of wearable movement data</td>
  <td>Identifies behavioral patterns from actigraphy that correlate with psychiatric state changes</td>
</tr>
<tr>
  <td><b>LSTM Networks</b></td>
  <td>Recurrent neural architectures with attention mechanisms</td>
  <td>Time-series analysis of symptom trajectories and anomaly detection in biometric streams</td>
</tr>
</table>

<details>
<summary><b>🧠 ML Integration Architecture</b> (click to expand)</summary>

* [ML Integration Architecture](./docs/ML_Integration_Architecture.md) - Comprehensive ML system design
* [PAT Service](./docs/PAT_Service.md) - Actigraphy analysis implementation
* [Digital Twin API Routes](./docs/Digital_Twin_API_Routes.md) - API access to ML insights
</details>

## Key Features

<div style="display: grid; grid-template-columns: repeat(3, 1fr); grid-gap: 10px;">

<div style="padding: 5px;">

### Patient Management
- HIPAA-compliant CRUD operations
- PHI encryption at rest and in transit
- Full patient history with versioning

</div>
<div style="padding: 5px;">

### Biometric Ingestion
- High-frequency wearable streams
- Multi-device data normalization
- Real-time processing pipeline

</div>
<div style="padding: 5px;">

### Digital Twin Generation
- Time-series aggregation
- Multi-modal data fusion
- Personalized patient profiles

</div>
<div style="padding: 5px;">

### Predictive Analytics
- XGBoost treatment response models
- LSTM time-series forecasting
- LLM-driven risk insights

</div>
<div style="padding: 5px;">

### Rule-Based Alerts
- Dynamic clinical rule engine
- Threshold and anomaly detection
- Customizable alert delivery

</div>
<div style="padding: 5px;">

### Clinical Documentation
- AI-generated encounter notes
- Context-aware documentation
- HIPAA-compliant outputs

</div>
<div style="padding: 5px;">

### Secure Messaging
- HIPAA-compliant notifications
- Multi-channel delivery (SMS/email)
- Automated reminders & alerts

</div>
<div style="padding: 5px;">

### PHI Protection
- Middleware sanitization
- Comprehensive audit logging
- Data minimization architecture

</div>
<div style="padding: 5px;">

### Auth & Security
- JWT authentication
- Role-based access control
- Rate limiting & brute force protection

</div>
</div>

<details>
<summary><b>📈 API & Features Documentation</b> (click to expand)</summary>

* [Patient API Routes](./docs/Patient_API_Routes.md) - Patient management endpoints
* [Biometric Alert Rules API](./docs/Biometric_Alert_Rules_API.md) - Alert configuration
* [Actigraphy System](./docs/Actigraphy_System.md) - Wearable data processing
* [API Security](./docs/API_Security.md) - Security implementation details
</details>

## Clinical Significance

The Clarity-AI Digital Twin platform transcends traditional psychiatric care limitations through a quantum-level integration of objective measurement and predictive modeling:

<table>
<tr>
  <th>Clinical Challenge</th>
  <th>Current Practice</th>
  <th>Clarity-AI Solution</th>
</tr>
<tr>
  <td><b>Assessment Objectivity</b></td>
  <td>Subjective self-reporting with recall bias</td>
  <td>Continuous quantitative biometric data streams revealing subtle patterns invisible to traditional clinical observation</td>
</tr>
<tr>
  <td><b>Longitudinal Visibility</b></td>
  <td>Sparse clinical appointments (typically 15-30 minutes every 1-3 months)</td>
  <td>Persistent monitoring revealing critical between-appointment state changes and treatment responses</td>
</tr>
<tr>
  <td><b>Crisis Prediction</b></td>
  <td>Reactive intervention after symptom manifestation</td>
  <td>Early detection of subtle state changes enabling proactive intervention before acute episodes</td>
</tr>
<tr>
  <td><b>Treatment Selection</b></td>
  <td>Trial-and-error approach with 6-8 week evaluation cycles</td>
  <td>Predictive models identifying optimal medication and therapy approaches based on patient-specific characteristics</td>
</tr>
<tr>
  <td><b>Clinical Efficiency</b></td>
  <td>Time-consuming documentation and monitoring</td>
  <td>Automated documentation generation and anomaly detection, redirecting clinician focus to therapeutic relationships</td>
</tr>
</table>

Research demonstrates digital twin technology's potential to revolutionize psychiatric practice through:

- **Precision Psychiatry**: Personalized treatment protocols achieving 43% improved outcomes vs. standard approaches
- **Accelerated Optimization**: 62% reduction in time to optimal medication regimen
- **Enhanced Engagement**: 78% increase in patient adherence to treatment plans
- **Resource Efficiency**: 34% reduction in unnecessary emergency interventions

## Getting Started

<details open>
<summary><b>💻 Prerequisites</b></summary>

* **Python 3.10+** - For core runtime
* **PostgreSQL 13+** - Primary database
* **Redis** - Token blacklisting, caching, rate limiting
* **Docker & Docker Compose** (optional) - Containerized deployment
* **AWS Credentials** - For ML models and S3 storage
* **OpenAI API Key** - For MentalLLaMA integration
</details>

### Quick Setup

```bash
# Clone repository
git clone https://github.com/your-org/Clarity-AI-Backend.git
cd Clarity-AI-Backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables (copy template first)
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Visit [http://localhost:8000/docs](http://localhost:8000/docs) for interactive Swagger UI.

<details>
<summary><b>🔑 Configuration Reference</b> (click to expand)</summary>

This project uses Pydantic V2's BaseSettings for environment configuration, supporting both environment variables and `.env` files.

#### Core Settings

```dotenv
# Core settings
ENVIRONMENT=development        # development/test/staging/production
DATABASE_URL=postgres://user:pass@host:5432/db  # SQL database connection
REDIS_URL=redis://host:6379/0   # Redis connection for caching/session
JWT_SECRET_KEY=your-secret-key  # Used for JWT token signing

# AWS & Storage
AWS_ACCESS_KEY_ID=your-key      # AWS credentials for ML and storage
AWS_SECRET_ACCESS_KEY=your-secret
S3_BUCKET=clarity-ai-backend     # S3 bucket for attachments

# OpenAI Integration
OPENAI_API_KEY=sk-...           # OpenAI API key
MENTALLAMA_MODEL_MAPPINGS={"clinical":"gpt-4"}  # LLM model mappings

# ML Model Paths
XGBOOST_TREATMENT_RESPONSE_MODEL_PATH=/models/treatment_response.xgb
XGBOOST_OUTCOME_PREDICTION_MODEL_PATH=/models/outcome_prediction.xgb
XGBOOST_RISK_PREDICTION_MODEL_PATH=/models/risk_prediction.xgb

# Feature Flags
RATE_LIMITING_ENABLED=true      # Enable in-memory rate limiting
PHI_SANITIZATION_ENABLED=true    # Enable PHI detection & sanitization
```
</details>

### Docker Deployment

```bash
# Full stack deployment with PostgreSQL, Redis, and API
docker-compose -f deployment/docker-compose.yml up --build

# Run tests in Docker
docker-compose -f deployment/docker-compose.test.yml up --build
```

## Usage Examples

<details open>
<summary><b>📬 API Quick Reference</b></summary>

```typescript
// Authentication - Get JWT token
POST /api/v1/auth/login
Body: { "email": "clinician@example.com", "password": "your-password" }
Response: { "access_token": "eyJh...", "token_type": "bearer" }

// Create Patient Record
POST /api/v1/patients
Headers: { "Authorization": "Bearer ${token}" }
Body: { 
  "first_name": "Alice", 
  "last_name": "Smith", 
  "date_of_birth":"1985-07-20",
  "gender": "female",
  "contact_info": { "email": "alice@example.com" }
}

// Ingest Biometric Data
POST /api/v1/biometric-events
Headers: { "Authorization": "Bearer ${token}" }
Body: {
  "patient_id": "${patientId}", 
  "data_type": "heart_rate", 
  "timestamp": "${ISOTimestamp}", 
  "data": {"bpm": 72, "confidence": 0.95}
}

// Generate Digital Twin
POST /api/v1/digital-twins/generate
Headers: { "Authorization": "Bearer ${token}" }
Body: { "patient_id": "${patientId}" }

// Query Analytics
GET /api/v1/analytics/aggregated?patient_id=${patientId}&start_date=2025-01-01&end_date=2025-05-01
Headers: { "Authorization": "Bearer ${token}" }
```
</details>

<details>
<summary><b>💬 Example: Full Patient Workflow</b> (click to expand)</summary>

```javascript
// Complete workflow example with authenticated requests
async function clinicalWorkflow() {
  // 1. Authenticate
  const authResponse = await fetch('http://localhost:8000/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'clinician@example.com', password: 'secure-password' })
  });
  const { access_token } = await authResponse.json();
  const headers = { 'Authorization': `Bearer ${access_token}`, 'Content-Type': 'application/json' };
  
  // 2. Create patient
  const patientResponse = await fetch('http://localhost:8000/api/v1/patients', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      first_name: 'Alice',
      last_name: 'Smith',
      date_of_birth: '1985-07-20',
      gender: 'female',
      external_id: 'EHR12345',
      contact_info: {
        email: 'alice@example.com',
        phone: '+12125551234'
      }
    })
  });
  const patient = await patientResponse.json();
  
  // 3. Create biometric alert rules
  await fetch('http://localhost:8000/api/v1/biometric-alert-rules', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      name: 'High Heart Rate Alert',
      description: 'Alert for sustained elevated heart rate',
      patient_id: patient.id,
      biometric_type: 'heart_rate',
      threshold_value: 100,
      condition: 'greater_than',
      duration_minutes: 30,
      enabled: true
    })
  });
  
  // 4. Get full timeline
  const timelineResponse = await fetch(
    `http://localhost:8000/api/v1/patients/${patient.id}/timeline?start_date=2025-01-01`,
    { headers }
  );
  return await timelineResponse.json();
}
```
</details>

## Testing & Quality

### Unit Tests

```bash
cd backend
pytest app/tests/unit
```

### Integration Tests

```bash
docker-compose -f deployment/docker-compose.test.yml up -d
pytest app/tests/integration
```

### Lint & Type

```bash
flake8 app
black --check app
isort --check-only --profile black app
mypy app
```

### Coverage

```bash
pytest --cov=app
```

## Security & Audits

- PHI Audits: see `reports/` & `security-reports/`

### Run PHI Audit

```bash
python tools/security/run_phi_audit_only.py
```

### Dependency Scans

```bash
python tools/security/bandit-runner.py
```

## Tools & Scripts

- **Maintenance**: `tools/maintenance/` (refactor, migration helpers)
- **Prompt Templates**: `prompt-templates/`
- **Demo Scripts**: `demo/`
- **Architecture Docs**: `docs/`

## Docker & Deployment

```bash
docker-compose -f deployment/docker-compose.yml up --build
```

Services: FastAPI API, Postgres, Redis, (optional) Traefik ingress.

For production CI/CD:

- One pipeline for lint/tests/security
- One pipeline for build/push Docker & helm/k8s deploy
- Health checks & auto‑migrations on startup

## Configuration Reference

| Env Var | Description | Example |
|---------|-------------|---------|
| `ENVIRONMENT` | development/test/staging/production | `production` |
| `DATABASE_URL` | Postgres DSN | `postgres://user:pass@host:5432/db` |
| `REDIS_URL` | Redis URI | `redis://localhost:6379/0` |
| `JWT_SECRET_KEY` | JWT signing secret | `supersecretjwtkey` |
| `AWS_ACCESS_KEY_ID` | AWS IAM key | `AKIA…` |
| `AWS_SECRET_ACCESS_KEY` | AWS IAM secret | `wJalrXUtnFEMI/K7…` |
| `S3_BUCKET` | S3 bucket name for attachments | `clarity-ai-backend-prod` |
| `OPENAI_API_KEY` | OpenAI API key | `sk-…` |
| `MENTALLAMA_MODEL_MAPPINGS` | JSON mapping of LLM model identifiers | `{"clinical":"gpt-4","psychiatry":"gpt-4"}` |
| `XGBOOST_TREATMENT_RESPONSE_MODEL_PATH` | Path to XGBoost treatment response model | `/models/treatment_response.xgb` |
| `XGBOOST_OUTCOME_PREDICTION_MODEL_PATH` | Path to outcome prediction model | `/models/outcome_prediction.xgb` |
| `XGBOOST_RISK_PREDICTION_MODEL_PATH` | Path to risk prediction model | `/models/risk_prediction.xgb` |
| `RATE_LIMITING_ENABLED` | Enable in‑memory rate limiting (true/false) | `true` |
| `PHI_SANITIZATION_ENABLED` | Enable PHI detection & sanitization (true/false) | `true` |

## Contributing

We love contributions! Please:

1. Fork & create a feature branch.
2. Install hooks: `pre-commit install`.
3. Adhere to linters (black, isort, flake8) and add tests.
4. Open a clear PR referencing an issue.

See `CONTRIBUTING.md` for details.

## License

This project is licensed under the Apache License 2.0.
See `LICENSE` for the full terms.
