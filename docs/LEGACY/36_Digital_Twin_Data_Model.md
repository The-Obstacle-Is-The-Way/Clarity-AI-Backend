# Digital Twin Data Model

## Overview

This document details the data model that powers the Novamind Digital Twin Platform. The Digital Twin data model is designed to capture and represent a patient's mental health state, behaviors, patterns, and interventions in a comprehensive computational model that enables analysis, prediction, and insight generation.

## Core Design Principles

- **Temporal Consistency**: All data is time-stamped and versioned to maintain historical accuracy
- **Schema Flexibility**: Support for structured, semi-structured, and unstructured data
- **Privacy by Design**: Inherent data protection and access controls at the data model level
- **Analytical Readiness**: Optimized for both transactional and analytical workloads
- **Domain Alignment**: Reflects clinical understanding of mental health processes
- **Traceability**: All data transformations and model predictions are traceable to source data

## Database Technologies

The Digital Twin data model is implemented across multiple database technologies, each selected for specific strengths:

1. **PostgreSQL**: Primary relational store for structured data, relationships, and transactional operations
2. **MongoDB**: Document store for semi-structured clinical data, assessments, and unstructured content
3. **Redis**: In-memory data store for real-time features, caching, and pub/sub messaging
4. **Elasticsearch**: Search and analytics engine for text analysis and complex querying
5. **TimescaleDB**: Time-series extension for PostgreSQL that handles temporal patient data efficiently

## Logical Data Model

### Core Entities

```
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│               │       │               │       │               │
│    Patient    │──────►│   TwinModel   │◄──────│    Feature    │
│               │       │               │       │               │
└───────┬───────┘       └───────┬───────┘       └───────────────┘
        │                       │                       ▲
        │                       │                       │
        │                       │                       │
        │                       │                       │
        ▼                       ▼                       │
┌───────────────┐       ┌───────────────┐       ┌────────────────┐
│               │       │               │       │                │
│  DataSource   │──────►│   DataPoint   │──────►│FeatureExtractor│
│               │       │               │       │                │
└───────────────┘       └───────────────┘       └────────────────┘
        │                       ▲                       │
        │                       │                       │
        │                       │                       │
        ▼                       │                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│               │       │               │       │               │
│ Integration   │──────►│   ETLJob      │──────►│   Insight     │
│               │       │               │       │               │
└───────────────┘       └───────────────┘       └───────────────┘
```

### Entity Descriptions

#### Patient
Represents an individual for whom a Digital Twin is constructed.

| Attribute | Type | Description |
|-----------|------|-------------|
| id | UUID | Unique identifier |
| external_id | String | External system identifier (encrypted) |
| created_at | Timestamp | Creation timestamp |
| updated_at | Timestamp | Last update timestamp |
| metadata | JSONB | Configurable metadata |
| status | Enum | Active, Inactive, Archived |

#### TwinModel
The computational representation of the patient's mental health.

| Attribute | Type | Description |
|-----------|------|-------------|
| id | UUID | Unique identifier |
| patient_id | UUID | Reference to Patient |
| version | String | Semantic version of model |
| created_at | Timestamp | Creation timestamp |
| updated_at | Timestamp | Last update timestamp |
| model_type | Enum | Type of predictive model |
| parameters | JSONB | Model parameters and configuration |
| active | Boolean | Whether this is the current active model |
| performance_metrics | JSONB | Metrics on model performance |

#### DataSource
External sources of patient data.

| Attribute | Type | Description |
|-----------|------|-------------|
| id | UUID | Unique identifier |
| name | String | Descriptive name |
| type | Enum | EHR, Device, Assessment, etc. |
| connection_details | Encrypted JSON | Connection parameters (encrypted) |
| refresh_frequency | Interval | How often data is refreshed |
| status | Enum | Active, Paused, Error |
| last_sync | Timestamp | Last successful synchronization |
| validation_schema | JSON | Expected data schema |

#### DataPoint
Individual data elements collected from data sources.

| Attribute | Type | Description |
|-----------|------|-------------|
| id | UUID | Unique identifier |
| source_id | UUID | Reference to DataSource |
| patient_id | UUID | Reference to Patient |
| collected_at | Timestamp | When the data was collected |
| imported_at | Timestamp | When the data was imported |
| data_type | Enum | Vitals, Assessment, Medication, etc. |
| value | JSONB | The actual data value |
| quality_score | Float | Data quality metric (0-1) |
| hash | String | Hash of the data for integrity |

#### Feature
Derived features used in the Digital Twin model.

| Attribute | Type | Description |
|-----------|------|-------------|
| id | UUID | Unique identifier |
| name | String | Descriptive name |
| description | Text | Detailed description |
| feature_type | Enum | Numerical, Categorical, Vector, etc. |
| extraction_logic | JSON | Logic to derive the feature |
| domain_area | Enum | Clinical domain area |
| importance_score | Float | Feature importance in model |
| unit | String | Unit of measure (if applicable) |

#### FeatureExtractor
Processes for transforming raw data into features.

| Attribute | Type | Description |
|-----------|------|-------------|
| id | UUID | Unique identifier |
| name | String | Descriptive name |
| extractor_type | Enum | Rule-Based, ML-Based, Statistical |
| input_types | Array[Enum] | Types of input data |
| output_feature_ids | Array[UUID] | Features produced |
| configuration | JSONB | Extractor parameters |
| version | String | Semantic version |
| performance_metrics | JSONB | Extractor performance metrics |

#### Integration
External systems integration configurations.

| Attribute | Type | Description |
|-----------|------|-------------|
| id | UUID | Unique identifier |
| name | String | Integration name |
| system_type | Enum | EHR, Device, API, etc. |
| credentials | Encrypted JSON | Access credentials (encrypted) |
| connection_parameters | JSONB | Configuration parameters |
| active | Boolean | Whether integration is active |
| last_health_check | Timestamp | Last connection verification |
| error_count | Integer | Recent error count |

#### ETLJob
Data extraction, transformation, and loading jobs.

| Attribute | Type | Description |
|-----------|------|-------------|
| id | UUID | Unique identifier |
| integration_id | UUID | Reference to Integration |
| job_type | Enum | Incremental, Full, Repair |
| status | Enum | Pending, Running, Completed, Failed |
| started_at | Timestamp | Start time |
| completed_at | Timestamp | Completion time |
| records_processed | Integer | Count of records processed |
| errors | JSONB | Error details if failed |
| parameters | JSONB | Job parameters |

#### Insight
Actionable insights derived from the Digital Twin.

| Attribute | Type | Description |
|-----------|------|-------------|
| id | UUID | Unique identifier |
| patient_id | UUID | Reference to Patient |
| twin_model_id | UUID | Reference to TwinModel |
| generated_at | Timestamp | Generation timestamp |
| insight_type | Enum | Risk, Trend, Anomaly, Recommendation |
| confidence | Float | Confidence score (0-1) |
| content | JSONB | The actual insight content |
| supporting_features | Array[UUID] | Features supporting this insight |
| presented_to_user | Boolean | Whether shown to a user |
| action_taken | Boolean | Whether action was taken |

## Physical Data Model

### PostgreSQL Schema

```sql
-- Core patient table
CREATE TABLE patients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    metadata JSONB,
    status VARCHAR(20) NOT NULL DEFAULT 'Active',
    CONSTRAINT patients_status_check CHECK (status IN ('Active', 'Inactive', 'Archived'))
);

-- Digital Twin models
CREATE TABLE twin_models (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID NOT NULL REFERENCES patients(id),
    version VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    model_type VARCHAR(50) NOT NULL,
    parameters JSONB NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    performance_metrics JSONB,
    CONSTRAINT twin_models_model_type_check CHECK (model_type IN 
        ('TimeSeries', 'NLP', 'Cognitive', 'Behavioral', 'Hybrid'))
);

-- Data sources
CREATE TABLE data_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    connection_details JSONB NOT NULL,
    refresh_frequency INTERVAL,
    status VARCHAR(20) NOT NULL DEFAULT 'Active',
    last_sync TIMESTAMP WITH TIME ZONE,
    validation_schema JSONB,
    CONSTRAINT data_sources_type_check CHECK (type IN 
        ('EHR', 'Device', 'Assessment', 'Survey', 'External', 'Manual'))
);

-- Data points collected from sources
CREATE TABLE data_points (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL REFERENCES data_sources(id),
    patient_id UUID NOT NULL REFERENCES patients(id),
    collected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    imported_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    data_type VARCHAR(50) NOT NULL,
    value JSONB NOT NULL,
    quality_score FLOAT,
    hash VARCHAR(64),
    CONSTRAINT data_points_quality_score_check CHECK (quality_score >= 0 AND quality_score <= 1)
);

-- Create TimescaleDB hypertable for time-series optimization
SELECT create_hypertable('data_points', 'collected_at');

-- Features used in models
CREATE TABLE features (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    feature_type VARCHAR(50) NOT NULL,
    extraction_logic JSONB NOT NULL,
    domain_area VARCHAR(50),
    importance_score FLOAT,
    unit VARCHAR(50),
    CONSTRAINT features_feature_type_check CHECK (feature_type IN 
        ('Numerical', 'Categorical', 'Temporal', 'Vector', 'Text'))
);

-- Feature extractors
CREATE TABLE feature_extractors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    extractor_type VARCHAR(50) NOT NULL,
    input_types VARCHAR(50)[] NOT NULL,
    output_feature_ids UUID[] NOT NULL,
    configuration JSONB NOT NULL,
    version VARCHAR(50) NOT NULL,
    performance_metrics JSONB,
    CONSTRAINT feature_extractors_type_check CHECK (extractor_type IN 
        ('Rule-Based', 'ML-Based', 'Statistical', 'Hybrid'))
);

-- External system integrations
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    system_type VARCHAR(50) NOT NULL,
    credentials JSONB NOT NULL,
    connection_parameters JSONB NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    last_health_check TIMESTAMP WITH TIME ZONE,
    error_count INTEGER NOT NULL DEFAULT 0
);

-- ETL jobs
CREATE TABLE etl_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id UUID NOT NULL REFERENCES integrations(id),
    job_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'Pending',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    records_processed INTEGER,
    errors JSONB,
    parameters JSONB,
    CONSTRAINT etl_jobs_job_type_check CHECK (job_type IN ('Incremental', 'Full', 'Repair')),
    CONSTRAINT etl_jobs_status_check CHECK (status IN 
        ('Pending', 'Running', 'Completed', 'Failed'))
);

-- Insights generated from the Digital Twin
CREATE TABLE insights (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID NOT NULL REFERENCES patients(id),
    twin_model_id UUID NOT NULL REFERENCES twin_models(id),
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    insight_type VARCHAR(50) NOT NULL,
    confidence FLOAT NOT NULL,
    content JSONB NOT NULL,
    supporting_features UUID[] NOT NULL,
    presented_to_user BOOLEAN NOT NULL DEFAULT false,
    action_taken BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT insights_confidence_check CHECK (confidence >= 0 AND confidence <= 1),
    CONSTRAINT insights_type_check CHECK (insight_type IN 
        ('Risk', 'Trend', 'Anomaly', 'Recommendation', 'Alert'))
);

-- Add indexes for performance
CREATE INDEX idx_data_points_patient_id ON data_points(patient_id);
CREATE INDEX idx_data_points_source_id ON data_points(source_id);
CREATE INDEX idx_twin_models_patient_id ON twin_models(patient_id);
CREATE INDEX idx_insights_patient_id ON insights(patient_id);
CREATE INDEX idx_insights_generated_at ON insights(generated_at);
```

### MongoDB Collections

```javascript
// Clinical document schema
db.createCollection("clinical_documents", {
   validator: {
      $jsonSchema: {
         bsonType: "object",
         required: ["patient_id", "document_type", "content", "collected_at"],
         properties: {
            patient_id: {
               bsonType: "string",
               description: "UUID of the patient"
            },
            document_type: {
               bsonType: "string",
               enum: ["Assessment", "Progress Note", "Treatment Plan", "Discharge Summary"],
               description: "Type of clinical document"
            },
            content: {
               bsonType: "object",
               description: "Document content in structured format"
            },
            collected_at: {
               bsonType: "date",
               description: "When the document was created"
            },
            provider_id: {
               bsonType: "string",
               description: "UUID of the provider who created the document"
            },
            metadata: {
               bsonType: "object",
               description: "Additional metadata about the document"
            }
         }
      }
   }
});

// Raw assessment data
db.createCollection("assessment_responses", {
   validator: {
      $jsonSchema: {
         bsonType: "object",
         required: ["patient_id", "assessment_id", "responses", "completed_at"],
         properties: {
            patient_id: {
               bsonType: "string",
               description: "UUID of the patient"
            },
            assessment_id: {
               bsonType: "string",
               description: "UUID of the assessment instrument"
            },
            responses: {
               bsonType: "array",
               description: "Array of question responses",
               items: {
                  bsonType: "object",
                  required: ["question_id", "response"],
                  properties: {
                     question_id: {
                        bsonType: "string",
                        description: "Question identifier"
                     },
                     response: {
                        description: "Response value - can be various types"
                     },
                     response_time_ms: {
                        bsonType: "int",
                        description: "Time taken to respond in milliseconds"
                     }
                  }
               }
            },
            completed_at: {
               bsonType: "date",
               description: "When the assessment was completed"
            },
            scores: {
               bsonType: "object",
               description: "Calculated scores for the assessment"
            }
         }
      }
   }
});

// Feature vectors for ML models
db.createCollection("feature_vectors", {
   validator: {
      $jsonSchema: {
         bsonType: "object",
         required: ["patient_id", "twin_model_id", "vector", "timestamp"],
         properties: {
            patient_id: {
               bsonType: "string",
               description: "UUID of the patient"
            },
            twin_model_id: {
               bsonType: "string",
               description: "UUID of the twin model"
            },
            vector: {
               bsonType: "object",
               description: "Feature vector as key-value pairs"
            },
            timestamp: {
               bsonType: "date",
               description: "When the vector was generated"
            },
            context: {
               bsonType: "object",
               description: "Contextual information about the vector generation"
            }
         }
      }
   }
});

// Create indexes
db.clinical_documents.createIndex({ "patient_id": 1 });
db.clinical_documents.createIndex({ "collected_at": 1 });
db.assessment_responses.createIndex({ "patient_id": 1 });
db.assessment_responses.createIndex({ "completed_at": 1 });
db.feature_vectors.createIndex({ "patient_id": 1, "timestamp": 1 });
```

## Data Flow Architecture

### Ingestion Flow

```
External Data Source
       │
       ▼
┌──────────────┐
│ Integration  │
│   Service    │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  ETL Service │
└──────┬───────┘
       │
       ▼
┌───────────────┐
│ Validation &  │
│ Normalization │
└──────┬────────┘
       │
       ▼
┌──────────────┐      ┌──────────────┐
│   Raw Data   │◄─────┤  Data Access │
│   Storage    │      │     Layer    │
└──────┬───────┘      └──────────────┘
       │
       ▼
┌──────────────┐
│ Event Stream │
└──────────────┘
```

### Feature Extraction Flow

```
┌──────────────┐      ┌──────────────┐
│  Raw Data    │─────►│ Feature      │
│  Storage     │      │ Extraction   │
└──────────────┘      │ Service      │
                      └──────┬───────┘
                             │
                             ▼
                      ┌──────────────┐
                      │ Feature      │
                      │ Registry     │
                      └──────┬───────┘
                             │
                             ▼
                      ┌──────────────┐
                      │ Feature      │
                      │ Storage      │
                      └──────┬───────┘
                             │
                             ▼
                      ┌──────────────┐
                      │ Event Stream │
                      └──────────────┘
```

### Model Update Flow

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ Feature      │─────►│ Model        │─────►│ Model        │
│ Storage      │      │ Training     │      │ Registry     │
└──────────────┘      │ Service      │      └──────┬───────┘
                      └──────────────┘             │
                                                   ▼
                                            ┌──────────────┐
                                            │ Twin Model   │
                                            │ Storage      │
                                            └──────┬───────┘
                                                   │
                                                   ▼
                                            ┌──────────────┐
                                            │ Event Stream │
                                            └──────────────┘
```

### Insight Generation Flow

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ Feature      │─────►│ Inference    │─────►│ Insight      │
│ Storage      │      │ Engine       │      │ Generator    │
└──────────────┘      └──────────────┘      └──────┬───────┘
                                                   │
                                                   ▼
                                            ┌──────────────┐
                                            │ Insight      │
                                            │ Storage      │
                                            └──────┬───────┘
                                                   │
                                                   ▼
                                            ┌──────────────┐
                                            │ Notification │
                                            │ Service      │
                                            └──────────────┘
```

## Security Considerations

### Data Encryption

- **At Rest**: All databases use volume encryption
- **Column-Level**: PHI fields are encrypted at the column level using application-managed keys
- **In Transit**: All database connections require TLS

### Access Control

- **Row-Level Security**: PostgreSQL policies restrict data access by patient and user role
- **Attribute-Based Access**: MongoDB field-level redaction based on user attributes
- **Parameterized Access**: All database queries use parameterized statements

### Audit

- **Record-Level**: All changes to patient data are recorded with timestamp, user, and reason
- **Query Logging**: High-risk queries are logged and monitored
- **Automatic Expiry**: Temporary access automatically expires

## Performance Considerations

### Partitioning Strategy

- **TimescaleDB Chunking**: Data points partitioned by time for efficient time-series queries
- **MongoDB Sharding**: Assessment data sharded by patient_id for horizontal scaling

### Indexing Strategy

- **Covering Indexes**: Designed to support common query patterns
- **Partial Indexes**: For frequently filtered subsets
- **Time-Based Queries**: Optimized for recent data retrieval

### Caching Layer

- **Redis Caching**: Feature vectors and model outputs cached for real-time access
- **Materialized Views**: For complex analytical queries that are accessed frequently
- **Cache Invalidation**: Event-driven invalidation on data updates

## Migration Strategies

### Schema Evolution

- **Backward Compatibility**: All schema changes maintain backward compatibility
- **Feature Flags**: New data structures can be enabled/disabled via configuration
- **Dual-Write Period**: During transitions, write to both old and new structures

### Data Migration

- **Incremental Processing**: Large datasets migrated in batches
- **Validation**: Post-migration consistency checks ensure data integrity
- **Rollback Plan**: All migrations have documented rollback procedures

## Appendix

### Data Dictionary

A comprehensive glossary of all entities, attributes, and their clinical significance.

### Embedded Ontologies

- **SNOMED CT**: Standard terminology for clinical terms
- **LOINC**: Standard for laboratory and clinical observations
- **DSM-5/ICD-10**: Diagnostic classification systems

### Data Quality Rules

Automated data quality checks applied during ingestion and processing.

---

Last Updated: 2025-04-20
