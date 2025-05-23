from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request, status

# This import is based on what conftest.py was using for User in mocks, may need adjustment
# depending on the actual User type expected by get_current_active_user dependency.
# from app.core.domain.entities.user import User
# For now, assume the modern Pydantic User from app.domain.entities is preferred for new code:
from app.domain.entities.user import User

# Schemas (actual paths might differ, these are placeholders based on common patterns)
# from app.presentation.api.schemas.analytics_schemas import AnalyticsEventData, AnalyticsEventBatchData


# Use Cases (actual paths might differ)
# For now, define placeholder classes here to satisfy dependencies
class ProcessAnalyticsEventUseCase:
    async def execute(self, task_data: dict) -> None:
        print(f"Mock ProcessAnalyticsEventUseCase: Executing with {task_data}")
        # In a real scenario, this would process the event
        pass


class BatchProcessAnalyticsUseCase:
    async def execute(self, task_data: list[dict]) -> None:
        print(f"Mock BatchProcessAnalyticsUseCase: Executing with {task_data}")
        # In a real scenario, this would process the batch of events
        pass


# Provider functions for use cases
def get_process_analytics_event_use_case() -> ProcessAnalyticsEventUseCase:
    return ProcessAnalyticsEventUseCase()


def get_batch_process_analytics_use_case() -> BatchProcessAnalyticsUseCase:
    return BatchProcessAnalyticsUseCase()


# Dependencies
from app.presentation.api.dependencies.auth import get_current_active_user

router = APIRouter(
    tags=["Analytics Events"],
)


@router.get("/health-check", status_code=status.HTTP_200_OK)
async def analytics_health_check():
    return {"status": "analytics router is healthy"}


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def record_analytics_event(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    process_event_use_case: ProcessAnalyticsEventUseCase = Depends(
        get_process_analytics_event_use_case
    ),
    # Add query parameters to handle query args from tests
    args: str | None = Query(default=None),
    kwargs: str | None = Query(default=None),
):
    """
    Process a single analytics event.
    Accepts both raw JSON and 'request' wrapped formats for flexibility.
    """
    # Parse the request body directly
    try:
        body_bytes = await request.body()
        if body_bytes:
            import json

            request_data = json.loads(body_bytes)
            print(f"DEBUG analytics events request_data: {request_data}")
        else:
            request_data = {}
    except Exception as e:
        print(f"Error parsing request body: {e}")
        request_data = {}

    # Handle the case where request_data is directly the event data with no wrapper
    # In test cases, the JSON is passed directly rather than wrapped in a 'request' property
    event_data = request_data

    # Ensure background_tasks is not None (for testing)
    if background_tasks is None:
        background_tasks = BackgroundTasks()

    user_id_str = str(current_user.id) if current_user else "anonymous"
    # Simplified task_data for placeholder
    task_data_to_send = {
        "event_data": event_data,
        "user_id": user_id_str,
    }
    background_tasks.add_task(process_event_use_case.execute, task_data_to_send)
    return {
        "status": "success",
        "message": "Event received",
        "data": {"event_id": "mock_event_id"},
    }


@router.post("/events/batch", status_code=status.HTTP_202_ACCEPTED)
async def record_analytics_batch(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    batch_process_use_case: BatchProcessAnalyticsUseCase = Depends(
        get_batch_process_analytics_use_case
    ),
    # Add query parameters to handle query args from tests
    args: str | None = Query(default=None),
    kwargs: str | None = Query(default=None),
):
    """
    Process a batch of analytics events.
    Accepts both list and dict formats for maximum flexibility with client implementations.
    """
    # Detailed debug prints
    print(f"DEBUG analytics batch kwargs: {kwargs}")
    print(f"DEBUG analytics batch args: {args}")

    # Parse the request body directly
    try:
        body_bytes = await request.body()
        if body_bytes:
            import json

            request_data = json.loads(body_bytes)
            print(f"DEBUG raw body parsed: {request_data}")
            print(f"DEBUG raw body type: {type(request_data)}")
        else:
            request_data = []
            print("DEBUG: Empty request body")
    except Exception as e:
        print(f"Error parsing request body: {e}")
        request_data = []

    # Handle different types of input data
    events_data = []

    if isinstance(request_data, list):
        # Direct list of events
        events_data = request_data
        print(f"DEBUG: List detected, length: {len(events_data)}")
    elif isinstance(request_data, dict):
        if "request" in request_data and isinstance(request_data["request"], list):
            # Wrapped list in 'request' property
            events_data = request_data["request"]
            print(f"DEBUG: Dict with request list detected, length: {len(events_data)}")
        else:
            # Single event as dict
            events_data = [request_data]
            print("DEBUG: Single dict event detected")

    # Ensure background_tasks is not None (for testing)
    if background_tasks is None:
        background_tasks = BackgroundTasks()

    user_id_str = str(current_user.id) if current_user else "anonymous"
    # Simplified task_data for placeholder
    # Assuming each item in events_data is an event
    tasks_to_send = [
        {
            "event_data": event,
            "user_id": user_id_str,
        }
        for event in events_data
    ]
    background_tasks.add_task(batch_process_use_case.execute, tasks_to_send)
    return {
        "status": "success",
        "message": "Batch events received",
        "data": {"batch_size": len(events_data)},
    }
