# Data Access

## Database Architecture

Clarity AI uses a layered approach to database access that ensures clean separation between domain logic and persistence details:

```
┌────────────────────┐     ┌────────────────────┐
│ Application Layer  │────▶│ Repository         │
│ (Services)         │     │ Interfaces         │
└────────────────────┘     └────────────────────┘
                                    │
                                    ▼
┌────────────────────┐     ┌────────────────────┐
│ ORM Models         │◀───▶│ Repository         │
│ (SQLAlchemy)       │     │ Implementations    │
└────────────────────┘     └────────────────────┘
         │
         ▼
┌────────────────────┐
│ Database           │
│ (PostgreSQL/SQLite)│
└────────────────────┘
```

## Repository Pattern

Repositories provide an abstraction layer over data persistence mechanisms:

### Interface Definition

```python
# app/core/interfaces/repositories/patient_repository_interface.py
class IPatientRepository(Protocol):
    """Interface for patient repository operations."""
    
    async def get_by_id(self, id: UUID) -> Optional[Patient]:
        """Get a patient by ID."""
        ...
    
    async def get_by_provider(self, provider_id: UUID) -> List[Patient]:
        """Get patients by provider ID."""
        ...
    
    async def create(self, patient: Patient) -> Patient:
        """Create a new patient."""
        ...
    
    async def update(self, patient: Patient) -> Patient:
        """Update an existing patient."""
        ...
    
    async def delete(self, id: UUID) -> bool:
        """Delete a patient by ID."""
        ...
```

### Implementation

```python
# app/infrastructure/persistence/repositories/sqla/patient_repository.py
class SQLAlchemyPatientRepository:
    """SQLAlchemy implementation of patient repository."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def get_by_id(self, id: UUID) -> Optional[Patient]:
        stmt = select(PatientModel).where(PatientModel.id == id)
        result = await self.session.execute(stmt)
        patient_model = result.scalars().first()
        
        if not patient_model:
            return None
            
        return self._map_to_entity(patient_model)
    
    async def create(self, patient: Patient) -> Patient:
        patient_model = PatientModel(
            id=patient.id,
            name=patient.name,
            date_of_birth=patient.date_of_birth,
            status=patient.status.value,
            provider_id=patient.provider_id,
            digital_twin_id=patient.digital_twin_id
        )
        
        self.session.add(patient_model)
        await self.session.commit()
        await self.session.refresh(patient_model)
        
        return self._map_to_entity(patient_model)
    
    def _map_to_entity(self, model: PatientModel) -> Patient:
        return Patient(
            id=model.id,
            name=model.name,
            date_of_birth=model.date_of_birth,
            status=PatientStatus(model.status),
            provider_id=model.provider_id,
            digital_twin_id=model.digital_twin_id
        )
```

## Database Models

SQLAlchemy ORM models define the database schema:

```python
# app/infrastructure/persistence/models/patient.py
class PatientModel(Base):
    """SQLAlchemy model for patients table."""
    
    __tablename__ = "patients"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String, nullable=False)
    date_of_birth = Column(Date, nullable=False)
    status = Column(String, nullable=False)
    provider_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    digital_twin_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Relationships
    provider = relationship("UserModel", back_populates="patients")
    alerts = relationship("BiometricAlertModel", back_populates="patient")
    
    # Audit columns
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime, onupdate=lambda: datetime.now(UTC))
    
    # Encryption
    __mapper_args__ = {
        "polymorphic_identity": "patient"
    }
```

## Database Session Management

FastAPI dependency injection for database sessions:

```python
# app/presentation/api/dependencies/database.py
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Create and yield a database session.
    
    This dependency should be used for all database operations
    to ensure proper session lifecycle management.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
```

## Redis Integration

Clarity AI uses Redis for caching, token blacklisting, and rate limiting:

### Redis Service Interface

```python
# app/core/interfaces/services/redis_service_interface.py
class IRedisService(Protocol):
    """Interface for Redis operations."""
    
    async def get(self, key: str) -> Optional[str]:
        """Get a value by key."""
        ...
    
    async def set(
        self,
        key: str,
        value: str,
        expiration: Optional[int] = None
    ) -> bool:
        """Set a key-value pair with optional expiration in seconds."""
        ...
    
    async def delete(self, key: str) -> bool:
        """Delete a key."""
        ...
    
    async def exists(self, key: str) -> bool:
        """Check if a key exists."""
        ...
```

### Redis Service Implementation

```python
# app/infrastructure/cache/redis_service.py
class RedisService:
    """Redis service implementation."""
    
    def __init__(self, redis: Redis):
        self.redis = redis
    
    async def get(self, key: str) -> Optional[str]:
        return await self.redis.get(key)
    
    async def set(
        self,
        key: str,
        value: str,
        expiration: Optional[int] = None
    ) -> bool:
        return await self.redis.set(key, value, ex=expiration)
    
    async def delete(self, key: str) -> bool:
        return await self.redis.delete(key) > 0
    
    async def exists(self, key: str) -> bool:
        return await self.redis.exists(key) > 0
```

### Redis Dependency

```python
# app/presentation/api/dependencies/redis.py
def get_redis_service(request: Request) -> IRedisService:
    """
    Get the Redis service from the application state.
    """
    if not hasattr(request.app.state, "redis"):
        raise RuntimeError("Redis client not initialized")
        
    return RedisService(request.app.state.redis)
```

## Caching Strategy

Clarity AI implements a multi-tiered caching strategy:

1. **Response Caching**: Common API responses with cache-control headers
2. **Data Caching**: Frequently accessed domain entities
3. **Computed Results**: ML model inference results

### Cache Implementation

```python
# app/application/services/cache_service.py
class CacheService:
    """Service for caching operations."""
    
    def __init__(self, redis_service: IRedisService):
        self.redis_service = redis_service
    
    async def get_cached_entity(
        self,
        entity_type: str,
        entity_id: UUID
    ) -> Optional[Dict[str, Any]]:
        """Get a cached entity by type and ID."""
        key = f"{entity_type}:{entity_id}"
        data = await self.redis_service.get(key)
        
        if not data:
            return None
            
        return json.loads(data)
    
    async def cache_entity(
        self,
        entity_type: str,
        entity_id: UUID,
        data: Dict[str, Any],
        expiration: int = 3600
    ) -> None:
        """Cache an entity with optional expiration."""
        key = f"{entity_type}:{entity_id}"
        await self.redis_service.set(
            key,
            json.dumps(data),
            expiration=expiration
        )
```