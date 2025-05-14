# Digital Twin System

**Status:** This document describes the **vision** for the Novamind Digital Twin. The **current implementation** is significantly simpler and partially realized. Sections will be updated to reflect the current state and differentiate it from aspirational goals.

This document provides a comprehensive overview of the Novamind Digital Twin system, including its conceptual foundations, architecture, implementation details, and usage guidelines.

---

## 1. Conceptual Overview

### 1.1. Definition and Purpose

The Digital Twin is the core conceptual model of the Novamind platform. It *is envisioned to represent* a comprehensive computational model of a patient's mental health, integrating diverse data sources to create a dynamic representation that evolves over time. It *aims to serve* as the foundation for personalized psychiatry by enabling:

-   **State Tracking**: Monitoring patient mental health state over time *(Partially implemented: Basic state tracking exists)*
-   **Prediction**: Forecasting potential symptom changes and treatment responses *(Aspirational: ML interfaces/endpoints exist, but core prediction logic in services is placeholder/missing)*
-   **Simulation**: Testing hypothetical interventions before clinical application *(Aspirational: Simulate endpoint documented but not implemented)*
-   **Personalization**: Tailoring treatment to individual patient characteristics *(Aspirational Goal)*

A Digital Twin in the Novamind context *is intended to be* a computational model that:

1.  **Mirrors a real patient** - Represents state, behaviors, patterns *(Current implementation is basic)*
2.  **Integrates multiple data sources** - Combines clinical, self-reports, behavioral, biomarkers, etc. *(Aspirational: Data integration pipelines TBD)*
3.  **Updates dynamically** - Evolves as new data becomes available *(Partially implemented: Basic update mechanisms exist)*
4.  **Enables prediction** - Anticipates future states and responses *(Aspirational)*
5.  **Facilitates personalization** - Supports individualized approaches *(Aspirational)*

### 1.2. Core Components (Vision)

The *envisioned* Digital Twin system integrates several key components:

-   **Neurotransmitter Modeling**: Mathematical models of neurotransmitter systems *(Aspirational: Detailed models not implemented; basic state dictionary exists)*
-   **Psychological State Tracking**: Quantitative modeling of psychological variables *(Aspirational: Detailed models not implemented; basic state dictionary exists)*
-   **Temporal Dynamics**: Time-series analysis of state changes *(Aspirational: History endpoint documented but not implemented)*
-   **Treatment Response Prediction**: ML-based forecasting *(Aspirational: ML interfaces/endpoints exist, core logic TBD)*
-   **Multimodal Data Integration**: Fusion of diverse data sources *(Aspirational)*

## 2. Architecture

### 2.1. System Overview (Target Architecture)

The Digital Twin implementation *should follow* clean architecture principles:

```
┌─────────────────────────────────────────────────────────────────────┐
│ Application Layer                                                   │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Digital Twin Service                                            │ │
│ │ ┌───────────────────┬─────────────────────┬─────────────────┐   │ │
│ │ │ Twin Creation     │ State Management    │ Analysis/Query  │   │ │
│ │ └───────────────────┴─────────────────────┴─────────────────┘   │ │
│ └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Domain Layer                                                           │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ Digital Twin Core                                                  │ │
│ │ ┌───────────────┬───────────────────────┬────────────────────────┐ │ │
│ │ │ Entities      │ Value Objects         │ Domain Services        │ │ │ 
│ │ │               │                       │                        │ │ │ 
│ │ │ DigitalTwin   │ NeurotransmitterState │ TwinAnalysisService    │ │ │
│ │ │ Patient       │ PsychologicalState    │ StateTransitionService │ │ │
│ │ │ Treatment     │ BiometricReading      │ PredictionService      │ │ │
│ │ └───────────────┴───────────────────────┴────────────────────────┘ │ │
│ └────────────────────────────────────────────────────────────────────┘ │ 
└────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Infrastructure Layer                                                │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ Digital Twin Infrastructure                                     │ │
│ │ ┌───────────────────┬─────────────────────┬─────────────────┐   │ │
│ │ │ Repositories      │ ML Services         │ Data Pipelines  │   │ │
│ │ └───────────────────┴─────────────────────┴─────────────────┘   │ │
│ └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```
*Current Status: The layers exist structurally, but the components within are partially implemented or aspirational. The `DigitalTwinService` exists but lacks much of the documented analysis/query functionality. The `DigitalTwin` entity is simpler than envisioned. Infrastructure (Repositories, ML Service implementations, Data Pipelines) is largely missing or mocked.*

### 2.2. Digital Twin Layers (Vision)

The Digital Twin architecture *is envisioned to consist* of hierarchical layers:

1.  **Data Integration Layer** *(Aspirational)*
2.  **Feature Extraction Layer** *(Aspirational)*
3.  **Model Layer** - Contains computational models *(Partially exists: Basic state model, ML interfaces)*
4.  **Inference Layer** - Generates insights, predictions *(Aspirational: Basic insight generation endpoint exists, complex inference TBD)*
5.  **Interface Layer** - Provides APIs *(Partially exists: See API documentation inconsistencies)*

### 2.3. Data Flow (Vision)

*The target data flow is as follows:*
1.  **Data Ingestion**: Patient data ingested and normalized *(Aspirational)*
2.  **Twin Creation/Update**: Twin created/updated *(Partially implemented)*
3.  **State Calculation**: Current state calculated *(Basic implementation)*
4.  **Analytics**: Twin state analyzed *(Aspirational/Placeholder)*
5.  **Prediction**: Future states predicted *(Aspirational/Placeholder)*
6.  **Feedback**: Results provided via API/tools *(Partially implemented)*

Full data flow (Vision):
```
External Data Sources → Data Integration → Feature Processing → Model Updating → Inference Generation → API Interfaces
```

Primary system components (Vision):

1.  **Data Connectors** *(Aspirational)*
2.  **Data Pipeline** *(Aspirational)*
3.  **Feature Store** *(Aspirational)*
4.  **Model Registry** *(Aspirational)*
5.  **Twin Engine** - Core computational system *(Partially implemented: Domain service)*
6.  **Inference Service** *(Aspirational)*
7.  **API Gateway** *(Partially implemented: FastAPI layer)*

## 3. Core Models (Vision / Aspirational)

### 3.1. Neurotransmitter Dynamics (Aspirational)

The Digital Twin *is intended to model* key neurotransmitter systems using mathematical models based on pharmacokinetic/pharmacodynamic principles:
-   **Serotonergic System**, **Dopaminergic System**, **GABAergic/Glutamatergic Balance**, **Noradrenergic System**.
*Current Status: Not implemented. The primary `DigitalTwin` entity has a simple `Dict[str, float]` for neurotransmitter state, and the more complex entities in `digital_twin_entity.py` are not fully integrated.*

### 3.2. Psychological State Modeling (Aspirational)

*The system is intended to track* psychological variables:
-   **Mood States**, **Cognitive Function**, **Behavioral Patterns**, **Symptom Profiles**.
*Current Status: Not implemented in detail. The primary `DigitalTwin` entity has a simple `Dict[str, float]` for psychological state.*

### 3.3. Predictive Models (Partially Implemented / Aspirational)

The Digital Twin *is intended to employ* multiple ML models for prediction:
-   **XGBoost-based**: Treatment response/relapse risk. *(Aspirational: Endpoint exists, service logic TBD)*
-   **LSTM Networks**: Temporal sequence modeling. *(Aspirational)*
-   **Pretrained Actigraphy Transformer (PAT)**: Behavioral signal analysis. *(Aspirational: Endpoint exists, service logic TBD)*
-   **MentalLLaMA33b**: NLP analysis. *(Aspirational: Endpoint exists, service logic TBD)*

*Current Status: Interfaces for ML services and API endpoints for XGBoost, PAT, and MentalLLaMA exist. However, the core logic within the services coordinating these models and integrating results into the Digital Twin appears to be placeholder or missing.*

## 4. Implementation Details

### 4.1. Core Entities (Actual vs. Aspirational)

**CRITICAL NOTE:** Codebase analysis reveals **multiple distinct Digital Twin entity definitions** across files like `digital_twin.py`, `digital_twin_entity.py`, `biometric_twin.py`, and `biometric_twin_enhanced.py`, leading to potential confusion and redundancy. It is essential to clarify which entity is canonical for development and refactor accordingly. The descriptions below summarize the findings:

*The codebase currently utilizes a specific `DigitalTwin` entity definition located in `backend/app/domain/entities/digital_twin.py`. This definition focuses on configuration and high-level state summaries and is the one primarily used by `DigitalTwinService`.*

**Current Canonical Entity (`backend/app/domain/entities/digital_twin.py`):**

```python
# Representation based on backend/app/domain/entities/digital_twin.py
@dataclass
class DigitalTwinConfiguration:
    # ... fields like simulation_granularity_hours, models_enabled, etc.
    pass

@dataclass
class DigitalTwinState:
    # ... fields like last_sync_time, overall_risk_level, dominant_symptoms, etc.
    pass

@dataclass
class DigitalTwin:
    patient_id: UUID
    id: UUID = field(default_factory=uuid4)
    configuration: DigitalTwinConfiguration = field(default_factory=DigitalTwinConfiguration)
    state: DigitalTwinState = field(default_factory=DigitalTwinState)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow) # Note: Field name might be last_updated in code
    version: int = 1

    # Methods like update_configuration, update_state (likely summary), touch exist
```
*Developers should primarily focus on the canonical entity in `digital_twin.py` for current development, while being aware of the aspirational structure for future direction.*

**Aspirational/Alternative Entity Structure (`backend/app/domain/entities/digital_twin_entity.py`):**
*This file defines a more complex structure closer to the original vision outlined in Section 1 & 3 of this document. It includes detailed brain regions, granular neurotransmitter states, and related concepts like `ClinicalInsight`. Its integration with the main `DigitalTwinService` is unclear and potentially incomplete or intended for future refactoring. The presence of `model_adapter.py` might indicate attempts to bridge these definitions.*

```python
# Snippet illustrating complexity based on backend/app/domain/entities/digital_twin_entity.py
class BrainRegion(Enum): ...
class Neurotransmitter(Enum): ...

@dataclass
class BrainRegionState: ...
@dataclass
class NeurotransmitterState: ... # Note: Different from the summary state object
@dataclass
class ClinicalInsight: ...

@dataclass
class DigitalTwinState: # Note: Different definition from the summary state object used above!
    patient_id: UUID
    timestamp: datetime
    brain_regions: dict[BrainRegion, BrainRegionState]
    neurotransmitters: dict[Neurotransmitter, NeurotransmitterState]
    # ... other complex fields
```
*Developers should primarily focus on the canonical entity in `digital_twin.py` for current development, while being aware of the aspirational structure for future direction.*

### 4.2. Application Services (Actual)

The Digital Twin is managed by `DigitalTwinService` (`backend/app/domain/services/digital_twin_service.py`).

```python
# Simplified representation based on backend/app/domain/services/digital_twin_service.py
class DigitalTwinService:
    def __init__(
        self,
        digital_twin_repository: DigitalTwinRepository,
        patient_repository: PatientRepository,
        # Interfaces to ML services (e.g., DigitalTwinServiceInterface, SymptomForecastingInterface)
        ...
    ):
        # ... initialization ...

    async def create_digital_twin(
        self, patient_id: UUID, initial_data: Optional[Dict[str, Any]] = None
    ) -> DigitalTwin:
        """Create a new Digital Twin (using the simpler entity)."""
        # Implementation exists

    async def update_digital_twin(
        self, patient_id: UUID, new_data_points: dict[str, Any]
    ) -> DigitalTwin:
        """Update a Digital Twin (placeholder logic for updating state)."""
        # Implementation exists but notes TODO for actual state update logic

    async def generate_new_twin_model(
        self, patient_id: UUID, model_type: str, model_parameters: dict[str, Any]
    ) -> DigitalTwin:
        """Intended to generate complex models, currently raises NotImplementedError."""
        # Raises NotImplementedError

    async def get_digital_twin(self, patient_id: UUID) -> DigitalTwin | None:
        """Get a twin by patient ID."""
        # Implementation exists

    async def analyze_treatment_response(
        self, ...
    ) -> dict[str, Any]:
        """Analyze treatment response (currently returns placeholder result)."""
        # Returns placeholder

    # Other methods exist, often calling interfaces to other services
    # Methods related to the complex twin model (e.g., get_twin_model_history) raise NotImplementedError
```
*Current Status: The service handles basic CRUD-like operations for the simpler `DigitalTwin` entity. It depends on interfaces for ML services but lacks significant implementation for complex analysis, prediction, or management of the more detailed twin model. Many functionalities are placeholder or not implemented.*

### 4.3. Data Schema (Aspirational)

The Digital Twin data *should be* organized flexibly:
-   Core State, Condition-Specific Extensions, Treatment-Related Fields, Temporal Data, Confidence Metrics.
*Current Status: The actual schema is primarily defined by the simpler `DigitalTwin` entity in `digital_twin.py`. The more complex schema implied by `digital_twin_entity.py` is not fully integrated.*

### 4.4. Security and Privacy (Partially Implemented / Aspirational)

The Digital Twin system *is intended to implement* strict security controls:
-   PHI Protection, Data Encryption, Access Controls, Audit Logging.
*Current Status: Basic non-PHI identifiers (UUIDs) are used. However, core security features like robust Access Controls and Audit Logging appear missing in the service/API layers. Encryption status TBD (likely aspirational).*

## 5. Integration Points (Aspirational)

### 5.1. Data Sources

The Digital Twin *is intended to integrate* data from:
-   EHRs, Assessment Instruments, Wearable Devices, Patient-Reported Outcomes, Genomic Data, Environmental Data.
*Current Status: Primarily aspirational. Data ingestion pipelines and specific connectors are not implemented.*

### 5.2. External Systems

The Digital Twin *is planned to interact* with:
-   Clinical Dashboards, Research Platforms, Treatment Planning Systems, Alerting Systems, EHR Integration.
*Current Status: Aspirational.*

## 6. Usage Guidelines (Reflects Aspirational API)

*Note: The following guidelines are based on the **documented (but largely unimplemented)** API endpoints found in `37_Digital_Twin_API.md`. The actual implemented API (`digital_twins.py`) has different endpoints and capabilities.*

### 6.1. Creating a Digital Twin (Aspirational API)

*Use the (currently unimplemented) `POST /digital-twins` endpoint.*

### 6.2. Updating the Twin State (Aspirational API)

*Use the (currently unimplemented) `POST /digital-twins/{twin_id}/data` or `POST /digital-twins/{twin_id}/data-points` endpoints.*

### 6.3. Generating Predictions (Aspirational)

*Use the (currently placeholder/unimplemented) prediction capabilities, potentially via insight generation or simulation endpoints (which are also unimplemented).*

### 6.4. Best Practices (General)

-   Consider uncertainty *(Confidence scores exist in simpler entity, TBD in complex one)*
-   Validate predictions against outcomes *(Requires implementation)*
-   Interpret insights with clinical expertise
-   Follow security protocols *(Requires implementation)*
-   Document discrepancies *(Ongoing process)*

## 7. Future Development (Revised based on current state)

The Digital Twin system requires significant development:

-   **Implement Core Functionality:** Build out missing service logic for state updates, analysis, prediction, simulation.
-   **Consolidate/Refine Entities:** Resolve the conflict between the simple and complex Digital Twin entity definitions. Fully integrate the chosen model.
-   **Build Infrastructure:** Implement real repositories, data pipelines, ML service integrations.
-   **Implement API:** Create missing documented API endpoints, align existing ones, fix inconsistencies.
-   **Integrate Data Sources:** Develop connectors and pipelines for EHR, wearables, etc.
-   **Enhance Models:** Implement detailed neurotransmitter/psychological models if the complex entity is chosen.
-   **Add Explainable AI:** Improve transparency.
-   **Implement Patient-Specific Calibration.**

## Appendix: Related Documentation

-   [36. Digital Twin Data Model](36_Digital_Twin_Data_Model.md) - *Needs review/update based on chosen entity structure.*
-   [37. Digital Twin API](37_Digital_Twin_API.md) - *Needs significant update to reflect implemented vs. missing endpoints.*
-   [30. Domain Model](30_Domain_Model.md) - *Needs review/update.* 

Last Updated: 2025-04-20
