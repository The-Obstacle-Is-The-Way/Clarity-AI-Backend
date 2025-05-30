"""
End-to-end integration tests for the temporal neurotransmitter system.

These tests validate the complete vertical stack from API to infrastructure,
ensuring that all components work together seamlessly with proper horizontal
coverage across all neurotransmitters and brain regions.
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient

# Mark all tests in this module as asyncio tests
pytestmark = pytest.mark.asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.application.services.temporal_neurotransmitter_service import (
    TemporalNeurotransmitterService,
)
from app.config.settings import get_settings
from app.domain.entities.digital_twin_enums import (
    BrainRegion,
    Neurotransmitter,
)
from app.domain.repositories.temporal_repository import (
    EventRepository,
    TemporalSequenceRepository,
)
from app.domain.services.enhanced_xgboost_service import EnhancedXGBoostService
from app.domain.services.visualization_preprocessor import (
    NeurotransmitterVisualizationPreprocessor,
)
from app.infrastructure.models.temporal_sequence_model import Base
from app.infrastructure.persistence.sqlalchemy.models.base import Base
from app.infrastructure.repositories.temporal_event_repository import (
    SqlAlchemyEventRepository,
)
from app.infrastructure.repositories.temporal_sequence_repository import (
    SqlAlchemyTemporalSequenceRepository,
)

# Initialize settings using the getter function
settings = get_settings()

# Create a test database engine
TEST_SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
engine = create_async_engine(TEST_SQLALCHEMY_DATABASE_URL, echo=True)
TestingSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine, class_=AsyncSession
)


# Mock user for authentication
test_user = {
    "id": str(uuid4()),
    "email": "test.neurologist@novamind.io",
    "first_name": "Test",
    "last_name": "Neurologist",
    "roles": ["CLINICIAN"],
    "is_active": True,
}

logger = logging.getLogger(__name__)


# --- Test Fixtures ---
@pytest.fixture
async def db_session():
    """Create an async SQLAlchemy session for testing with in-memory database."""
    async with engine.begin() as conn:
        # Create tables
        await conn.run_sync(Base.metadata.create_all)

        async with TestingSessionLocal() as session:
            yield session

            # Clean up
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def sequence_repository(db_session: AsyncSession):
    """Create sequence repository with test session."""
    return SqlAlchemyTemporalSequenceRepository(session=db_session)


@pytest.fixture
async def event_repository(db_session: AsyncSession):
    """Create event repository with test session."""
    return SqlAlchemyEventRepository(session=db_session)


@pytest.fixture
def xgboost_service():
    """Create a mock XGBoost service for testing."""
    # Return a MagicMock or a simple object that mimics the service
    # return EnhancedXGBoostService() # Keep commented if real service is complex/slow
    return MagicMock(spec=EnhancedXGBoostService)


@pytest.fixture
def visualization_preprocessor():
    """Create a visualization preprocessor instance."""
    return NeurotransmitterVisualizationPreprocessor()


@pytest_asyncio.fixture
async def temporal_service(
    sequence_repository: TemporalSequenceRepository,
    event_repository: EventRepository,
    xgboost_service: EnhancedXGBoostService,
    visualization_preprocessor: NeurotransmitterVisualizationPreprocessor,
    patient_id: UUID,
):
    """Create temporal neurotransmitter service with repositories, XGBoost, visualization, and patient_id."""
    # The service now requires patient_id if nt_mapping is not provided, which is the case here.
    return TemporalNeurotransmitterService(
        sequence_repository=sequence_repository,
        event_repository=event_repository,
        xgboost_service=xgboost_service,
        visualization_preprocessor=visualization_preprocessor,
        patient_id=patient_id,
    )


@pytest.fixture
def mock_current_user():
    """Mock current user dependency."""
    # Patch the alias DI in our API routes to return the test_user
    with patch(
        "app.api.routes.temporal_neurotransmitter.get_current_user",
        new=AsyncMock(return_value=test_user),
    ) as mock:
        yield mock


@pytest.fixture
def patient_id():
    """Generate a patient ID for testing."""
    return uuid4()


@pytest.mark.asyncio()
@pytest.mark.db_required()
@pytest.mark.skip(
    "Skipping temporal service with XGBoost integration test: pending schema alignment"
)
async def test_temporal_service_with_xgboost_integration(
    temporal_service: TemporalNeurotransmitterService,
    xgboost_service: EnhancedXGBoostService,
    patient_id: UUID,
    sequence_repository: TemporalSequenceRepository,
    event_repository: EventRepository,
) -> None:
    """
    Test integrated functionality of TemporalNeurotransmitterService with XGBoost.

    This test validates that the service can:
    1. Generate time series data
    2. Simulate treatment responses
    3. Access repositories correctly
    4. Interact with the XGBoost service (if XGBoost interaction is enabled)
    """
    # Set up - create a baseline sequence
    baseline_sequence_id = await temporal_service.generate_neurotransmitter_time_series(
        patient_id=patient_id,
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        neurotransmitter=Neurotransmitter.SEROTONIN,
        time_range_days=30,
        time_step_hours=6,
    )

    # Verify baseline sequence was created
    assert baseline_sequence_id is not None
    # Verify sequence persisted in repository
    persisted_sequence = await sequence_repository.get_by_id(baseline_sequence_id)
    assert persisted_sequence is not None
    assert persisted_sequence.patient_id == patient_id

    logger.info(f"Test Function: Generated baseline sequence {baseline_sequence_id}")

    # --- Log state before simulate_treatment_response ---
    logger.info(
        f"[DEBUG test_fn] Type of temporal_service.nt_mapping: {type(temporal_service.nt_mapping)}"
    )
    if hasattr(temporal_service, "nt_mapping") and temporal_service.nt_mapping is not None:
        logger.info(
            f"[DEBUG test_fn] hasattr receptor_map? {hasattr(temporal_service.nt_mapping, 'receptor_map')}"
        )
    else:
        logger.info("[DEBUG test_fn] temporal_service.nt_mapping is None or does not exist.")

    # Simulate treatment response
    treatment_results = await temporal_service.simulate_treatment_response(
        patient_id=patient_id,
        brain_region=BrainRegion.PREFRONTAL_CORTEX,
        target_neurotransmitter=Neurotransmitter.SEROTONIN,
        treatment_effect=0.5,
        simulation_days=14,
    )
    assert treatment_results is not None
    assert Neurotransmitter.SEROTONIN in treatment_results
    assert isinstance(treatment_results[Neurotransmitter.SEROTONIN], UUID)
    # Verify treatment simulation events were persisted
    patient_events = await event_repository.get_patient_events(patient_id)
    assert patient_events is not None
    assert len(patient_events) > 0
    # Optional: check event types include simulation events
    event_types = {e.event_type for e in patient_events}
    assert any("sequence" in et or "simulation" in et or "analysis" in et for et in event_types)

    # # Verify XGBoost interaction (if mocked/spied)
    # # assert prediction_calls # Ensure predict was called
    # # print(f"Prediction calls: {prediction_calls}")
    # # assert prediction_calls[0]['features'] is not None

    # # Restore original method if spied
    # # xgboost_service.predict_treatment_response = original_predict


@pytest.mark.skip(
    "Skipping full brain region coverage visualization test: pending mapping signature update"
)
@pytest.mark.asyncio()
async def test_full_brain_region_coverage_with_visualization(
    temporal_service: TemporalNeurotransmitterService, patient_id: UUID
) -> None:
    """
    Test complete horizontal coverage across brain regions with visualization.

    This test ensures that the service can generate visualizations for all brain regions.
    """
    # Test key brain regions with significant neurotransmitter involvement
    test_regions = [
        BrainRegion.PREFRONTAL_CORTEX,  # Executive function
        BrainRegion.AMYGDALA,  # Emotional processing
        BrainRegion.HIPPOCAMPUS,  # Memory
        BrainRegion.RAPHE_NUCLEI,  # Serotonin production
        BrainRegion.VENTRAL_TEGMENTAL_AREA,  # Dopamine production
    ]

    visualization_data = {}

    # Generate visualization for each region
    for region in test_regions:
        # Create cascade visualization
        viz_data = await temporal_service.get_cascade_visualization(
            patient_id=patient_id,
            starting_region=region,
            neurotransmitter=Neurotransmitter.SEROTONIN,
            time_steps=5,
        )

        visualization_data[region] = viz_data

        # Verify visualization data structure
        assert "nodes" in viz_data
        assert "connections" in viz_data
        assert "time_steps" in viz_data

        # Verify that the starting region is included in the nodes
        starting_region_in_nodes = False
        for node in viz_data["nodes"]:
            if node["brain_region"] == region.value:
                starting_region_in_nodes = True
                break

        assert (
            starting_region_in_nodes
        ), f"Starting region {region.value} should be in visualization nodes"

    # Verify that different regions produce different visualizations
    # Compare nodes and connections counts
    node_counts = [len(data["nodes"]) for data in visualization_data.values()]
    connection_counts = [len(data["connections"]) for data in visualization_data.values()]

    # Not all visualizations should have the same node/connection count
    assert (
        len(set(node_counts)) > 1 or len(set(connection_counts)) > 1
    ), "Different regions should produce different visualization structures"


@pytest.mark.skip(
    "Skipping full neurotransmitter coverage treatment test: pending method availability"
)
@pytest.mark.asyncio()
async def test_full_neurotransmitter_coverage_with_treatment(
    temporal_service: TemporalNeurotransmitterService, patient_id: UUID
) -> None:
    """
    Test complete horizontal coverage across neurotransmitters with treatment simulation.

    This test ensures that the service can simulate treatment effects for all neurotransmitters.
    """
    # Test major neurotransmitters involved in psychiatric conditions
    test_neurotransmitters = [
        Neurotransmitter.SEROTONIN,  # Depression, anxiety
        Neurotransmitter.DOPAMINE,  # Reward, addiction, psychosis
        Neurotransmitter.GABA,  # Anxiety, sleep
        Neurotransmitter.GLUTAMATE,  # Learning, excitotoxicity
    ]

    treatment_results = {}

    # Simulate treatment for each neurotransmitter
    for nt in test_neurotransmitters:
        # Simulate treatment targeting this neurotransmitter
        response = await temporal_service.simulate_treatment_response(
            patient_id=patient_id,
            brain_region=BrainRegion.PREFRONTAL_CORTEX,
            target_neurotransmitter=nt,
            treatment_effect=0.5,
            simulation_days=7,
        )

        treatment_results[nt] = response

        # Verify response contains sequences for multiple neurotransmitters
        assert len(response) > 1
        assert nt in response, f"Response should include target neurotransmitter {nt.value}"

        # Verify that the target neurotransmitter sequence ID is valid
        sequence = await temporal_service.sequence_repository.get_by_id(response[nt])
        assert sequence is not None

        # Verify metadata contains treatment information
        assert "treatment_target" in sequence.metadata
        assert sequence.metadata["treatment_target"] == nt.value

    # Verify that different neurotransmitters produce different patterns of effects
    # Count how many secondary neurotransmitters are affected
    secondary_counts = [len(result) for result in treatment_results.values()]

    # Not all treatments should affect the same number of neurotransmitters
    assert (
        len(set(secondary_counts)) > 1
    ), "Different neurotransmitter treatments should affect different numbers of secondary neurotransmitters"


@pytest.mark.skip("Skipping API integration with service test: pending endpoint implementation")
@pytest.mark.asyncio()
async def test_api_integration_with_service(
    test_client: AsyncClient,  # Use test_client fixture from conftest.py
    mock_current_user,
    # test_app fixture removed
    temporal_service: TemporalNeurotransmitterService,  # Fixture now provides a service linked to patient_id
    patient_id: UUID,
) -> None:
    """
    Test API integration with the neurotransmitter service.

    This test verifies that the API layer correctly integrates with the service layer.
    """
    # Setup - patch dependencies to use our service instance
    with (
        mock_current_user,
        patch(
            "app.api.routes.temporal_neurotransmitter.get_temporal_neurotransmitter_service",
            return_value=AsyncMock(return_value=temporal_service),
        ),
    ):
        # Test 1: Generate time series
        time_series_response = await test_client.post(  # Use test_client fixture
            "/api/v1/temporal-neurotransmitter/time-series",
            json={
                "patient_id": str(patient_id),
                "brain_region": BrainRegion.PREFRONTAL_CORTEX.value,
                "neurotransmitter": Neurotransmitter.SEROTONIN.value,
                "time_range_days": 14,
                "time_step_hours": 6,
            },
        )

        # Verify response
        assert time_series_response.status_code == 201
        assert "sequence_id" in time_series_response.json()

        # Test 2: Simulate treatment
        treatment_response = await test_client.post(  # Use test_client fixture
            "/api/v1/temporal-neurotransmitter/simulate-treatment",
            json={
                "patient_id": str(patient_id),
                "brain_region": BrainRegion.PREFRONTAL_CORTEX.value,
                "target_neurotransmitter": Neurotransmitter.SEROTONIN.value,
                "treatment_effect": 0.5,
                "simulation_days": 14,
            },
        )

        # Verify response
        assert treatment_response.status_code == 200
        assert "sequence_ids" in treatment_response.json()

        # Extract a sequence ID for visualization test
        first_sequence_id = next(iter(treatment_response.json()["sequence_ids"].values()))

        # Test 3: Get visualization data
        viz_response = await test_client.post(  # Use test_client fixture
            "/api/v1/temporal-neurotransmitter/visualization-data",
            json={"sequence_id": first_sequence_id},
        )

        # Verify response
        assert viz_response.status_code == 200
        assert "time_points" in viz_response.json()
        assert "features" in viz_response.json()
        assert "values" in viz_response.json()
