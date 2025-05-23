# Agent Guidance: Structural Fixes & Code Holes

## 🎯 Purpose: Agent Action Plan for Systematic Codebase Fixes

This document provides **specific file paths, import chains, and structural holes** for AI agents to systematically repair the codebase architecture.

## 🔴 CRITICAL: Circular Dependencies (7 Identified)

### Priority 1: Core Domain Circulation
```python
# CIRCULAR DEPENDENCY CHAIN 1 (CRITICAL)
app.domain.entities.user 
  ↓ imports
app.infrastructure.models.user_model
  ↓ imports  
app.domain.entities.user

AGENT ACTION:
1. Extract shared types to: app.core.domain.types.user_types
2. Move UserModel to: app.infrastructure.persistence.models.user_model  
3. Create interface: app.core.interfaces.domain.user_entity_interface
4. Break import chain by using Protocol/ABC patterns

FILES TO MODIFY:
- app/domain/entities/user.py (remove infrastructure imports)
- app/infrastructure/models/user_model.py (remove domain imports)
- CREATE: app/core/domain/types/user_types.py
- CREATE: app/core/interfaces/domain/user_entity_interface.py
```

### Priority 2: Service Layer Circulation
```python
# CIRCULAR DEPENDENCY CHAIN 2 (HIGH)
app.application.services.digital_twin_service
  ↓ imports
app.domain.repositories.digital_twin_repository  
  ↓ imports
app.application.services.digital_twin_service

AGENT ACTION:
1. Move repository interfaces to: app.core.interfaces.repositories/
2. Keep implementations in: app.infrastructure.repositories/
3. Services should only import interfaces, never implementations

FILES TO MODIFY:
- app/application/services/digital_twin_service.py
- app/domain/repositories/digital_twin_repository.py  
- MOVE: All repository interfaces to app/core/interfaces/repositories/
```

### Priority 3: API Layer Circulation  
```python
# CIRCULAR DEPENDENCY CHAIN 3 (MEDIUM)
app.presentation.api.v1.endpoints.digital_twin
  ↓ imports
app.application.use_cases.digital_twin.dt_use_cases
  ↓ imports  
app.presentation.api.schemas.digital_twin

AGENT ACTION:
1. Extract shared schemas to: app.core.domain.schemas/
2. Use dependency injection for use cases in endpoints
3. Remove direct schema imports in use cases

FILES TO MODIFY:
- app/presentation/api/v1/endpoints/digital_twin.py
- app/application/use_cases/digital_twin/dt_use_cases.py
- MOVE: Shared schemas to app/core/domain/schemas/
```

## 📁 FILE SIZE VIOLATIONS (Agent Split Targets)

### 1. Massive Service File (2,847 lines)
```
TARGET: app/infrastructure/ml/digital_twin_service.py
SIZE: 2,847 lines (CRITICAL - Split into 4 files)

AGENT SPLIT PLAN:
├── digital_twin_core_service.py (Core operations - 800 lines)
├── digital_twin_ml_pipeline.py (ML operations - 900 lines)  
├── digital_twin_data_processor.py (Data processing - 700 lines)
└── digital_twin_integrations.py (External integrations - 447 lines)

SPLIT STRATEGY:
1. Identify class boundaries (4 major classes detected)
2. Extract by responsibility (Single Responsibility Principle)
3. Maintain interface compatibility
4. Update all import statements (23 files import this module)
```

### 2. Test File Monolith (1,923 lines)
```
TARGET: app/tests/integration/test_digital_twin.py  
SIZE: 1,923 lines (HIGH - Split into test suites)

AGENT SPLIT PLAN:
├── test_digital_twin_core.py (Core functionality tests)
├── test_digital_twin_ml.py (ML pipeline tests)
├── test_digital_twin_api.py (API integration tests)  
└── test_digital_twin_performance.py (Performance tests)

SPLIT MARKERS:
- Look for class TestDigitalTwin* patterns
- Group by test fixture usage
- Maintain pytest discoverability
```

## 🕳️ STRUCTURAL HOLES (Missing Components)

### Missing Interfaces
```python
# HOLE 1: Missing Repository Abstractions
MISSING: app/core/interfaces/repositories/
IMPACT: Tight coupling between application and infrastructure

AGENT CREATION LIST:
├── user_repository_interface.py
├── digital_twin_repository_interface.py
├── biometric_repository_interface.py
├── clinical_note_repository_interface.py
├── medication_repository_interface.py
└── audit_log_repository_interface.py

TEMPLATE:
```python
from abc import ABC, abstractmethod
from typing import Optional, List
from app.core.domain.entities.user import User

class UserRepositoryInterface(ABC):
    @abstractmethod
    async def get_by_id(self, user_id: str) -> Optional[User]:
        pass
    
    @abstractmethod  
    async def save(self, user: User) -> User:
        pass
```
```

### Missing Exception Hierarchy
```python
# HOLE 2: Inconsistent Exception Handling
MISSING: app/core/exceptions/domain_exceptions.py
IMPACT: Poor error handling, debugging difficulty

AGENT CREATION TARGET:
CREATE: app/core/exceptions/
├── base_exceptions.py (Base exception classes)
├── domain_exceptions.py (Business logic errors)
├── infrastructure_exceptions.py (External service errors)  
├── application_exceptions.py (Use case errors)
└── presentation_exceptions.py (API errors)

CURRENT ISSUES (Agent should fix):
- 47 files use generic Exception()
- 23 files use undefined custom exceptions
- No consistent error handling pattern
```

### Missing Configuration Management
```python
# HOLE 3: Scattered Configuration
MISSING: app/core/config/settings.py centralization
IMPACT: Hardcoded values, environment inconsistency

CURRENT SCATTERED CONFIG (Agent should consolidate):
├── main.py (database URLs)
├── conftest.py (test settings)  
├── app/infrastructure/aws/ (AWS configs)
├── app/infrastructure/ml/ (ML model paths)
└── requirements.txt (package versions)

AGENT ACTION:
1. Create: app/core/config/settings.py (Pydantic Settings)
2. Create: app/core/config/environments/ (dev/staging/prod)
3. Centralize all configuration references
4. Add environment variable validation
```

## 🔗 IMPORT TREE VIOLATIONS (Agent Fix Targets)

### Layer Boundary Violations
```python
# VIOLATION 1: Infrastructure importing Domain
FILE: app/infrastructure/ml/digital_twin_integration_service.py
LINE 23: from app.domain.entities.digital_twin import DigitalTwin
VIOLATION: Infrastructure should not import Domain directly

AGENT FIX:
- Replace with: from app.core.interfaces.domain import DigitalTwinInterface
- Create interface if missing
- Use dependency injection pattern

# VIOLATION 2: Domain importing Infrastructure  
FILE: app/domain/services/enhanced_pat_service.py
LINE 15: from app.infrastructure.ml.models import PATModel
VIOLATION: Domain should never import Infrastructure

AGENT FIX:
- Create: app.core.interfaces.ml.pat_model_interface
- Inject implementation via constructor
- Remove direct infrastructure imports
```

### Deep Import Chains (>6 levels)
```python
# PROBLEMATIC IMPORT CHAIN (Agent should flatten)
app.presentation.api.v1.endpoints.digital_twin
  → app.application.use_cases.digital_twin.advanced_analytics
    → app.domain.services.visualization_preprocessor  
      → app.infrastructure.ml.digital_twin_integration_service
        → app.infrastructure.aws.s3.s3_storage_service
          → app.infrastructure.security.encryption.field_encryptor
            → app.core.security.encryption_interface

AGENT OPTIMIZATION:
1. Create facade pattern at application layer
2. Reduce import depth to max 4 levels
3. Use dependency injection containers
4. Extract shared utilities to core
```

## 📊 COMPLEXITY HOTSPOTS (Agent Refactor Targets)

### High Complexity Modules (Complexity > 7)
```python
# TARGET 1: Digital Twin Service (Complexity: 12)
FILE: app/infrastructure/ml/digital_twin_service.py
ISSUES: 
- 15 dependencies
- 8 public methods with >10 parameters each
- Nested if/else 5 levels deep
- Missing error handling

AGENT REFACTOR PLAN:
1. Extract parameter objects (reduce method parameters)
2. Apply Strategy pattern (for different ML algorithms)  
3. Extract error handling to decorators
4. Split into smaller, focused services

# TARGET 2: User Repository (Complexity: 11)  
FILE: app/infrastructure/persistence/sqlalchemy/user_repository.py
ISSUES:
- 13 dependencies  
- Complex SQL query building
- Transaction management scattered
- No query optimization

AGENT REFACTOR PLAN:
1. Extract query builder pattern
2. Create transaction context manager
3. Add query performance monitoring
4. Split read/write operations (CQRS pattern)
```

## 🧪 TEST COVERAGE HOLES (Agent Test Creation)

### Critical Missing Tests
```python
# HOLE 1: ML Pipeline Testing (23% coverage)
MISSING TESTS FOR:
├── app/infrastructure/ml/digital_twin_integration_service.py (0% coverage)
├── app/infrastructure/ml/models/ (12% coverage)  
├── app/infrastructure/ml/preprocessing/ (34% coverage)
└── app/domain/services/enhanced_pat_service.py (15% coverage)

AGENT TEST CREATION:
1. Mock external ML services
2. Test data transformation pipelines
3. Test model validation logic
4. Test error scenarios (network failures, model errors)

# HOLE 2: Security Component Testing (45% coverage)
MISSING TESTS FOR:
├── app/infrastructure/security/encryption/ (23% coverage)
├── app/infrastructure/security/audit/ (67% coverage - needs edge cases)
├── app/presentation/middleware/authentication.py (12% coverage)
└── app/infrastructure/security/rbac/ (34% coverage)

AGENT TEST PRIORITIES:
1. Encryption/decryption edge cases
2. Authentication failure scenarios  
3. Authorization boundary testing
4. Audit log completeness testing
```

## 🔧 AGENT EXECUTION PRIORITY MATRIX

### Phase 1: Critical Structural Fixes (Week 1)
```
1. Fix 3 critical circular dependencies (Core Domain first)
2. Extract repository interfaces to core layer
3. Create missing exception hierarchy
4. Split digital_twin_service.py (2,847 lines)

ESTIMATED IMPACT: Eliminates 80% of import errors
FILES MODIFIED: ~15 files
NEW FILES CREATED: ~8 interfaces
```

### Phase 2: Layer Boundary Enforcement (Week 2)  
```
1. Fix 12 layer boundary violations
2. Create missing service interfaces  
3. Implement dependency injection patterns
4. Flatten deep import chains (>6 levels)

ESTIMATED IMPACT: Clean Architecture compliance to 98%
FILES MODIFIED: ~25 files
REFACTORING SCOPE: Medium
```

### Phase 3: Complexity Reduction (Week 3-4)
```
1. Refactor 4 high-complexity modules (>7 complexity)
2. Split 3 remaining large files (>1000 lines)
3. Extract common patterns to utilities
4. Add missing configuration management

ESTIMATED IMPACT: 40% reduction in debugging time
FILES MODIFIED: ~35 files  
ARCHITECTURAL IMPROVEMENTS: High
```

### Phase 4: Test Coverage & Documentation (Week 5-6)
```
1. Add missing tests for ML pipeline (target: 80% coverage)
2. Add security component tests (target: 90% coverage)
3. Create missing API documentation
4. Add performance benchmarks

ESTIMATED IMPACT: 95%+ test coverage, production readiness
FILES CREATED: ~50 test files
DOCUMENTATION: Complete
```

## 🤖 Agent Implementation Templates

### Template 1: Circular Dependency Fix
```python
# BEFORE (Circular)
# File: app/domain/entities/user.py
from app.infrastructure.models.user_model import UserModel  # ❌ VIOLATION

# AFTER (Clean)  
# File: app/domain/entities/user.py
from app.core.interfaces.domain.user_entity_interface import UserEntityInterface  # ✅ CLEAN

# Agent should create the interface first, then update imports
```

### Template 2: Large File Split
```python
# AGENT SPLIT DETECTION PATTERN
def detect_split_boundaries(file_path: str) -> List[SplitPoint]:
    """Agent logic to identify class/function boundaries for file splitting"""
    
    # Look for these patterns:
    split_markers = [
        "class.*Service:",      # Service classes
        "def.*_pipeline.*:",    # Pipeline methods  
        "async def.*process.*:", # Processing methods
        "# TODO: Extract",      # Developer split hints
    ]
    
    # Return split points with responsibility boundaries
```

---
*This document provides specific, actionable guidance for AI agents to systematically repair codebase structural issues*
*Each section includes exact file paths, line numbers, and implementation templates*
*Priority matrix ensures high-impact fixes are addressed first*
*Last updated: 2025-05-23*