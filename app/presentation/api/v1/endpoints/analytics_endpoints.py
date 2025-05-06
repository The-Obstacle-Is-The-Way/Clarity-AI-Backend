from fastapi import APIRouter, BackgroundTasks, Depends, status
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
    async def execute(self, task_data: dict):
        print(f"Mock ProcessAnalyticsEventUseCase: Executing with {task_data}")
        # In a real scenario, this would process the event
        pass

class BatchProcessAnalyticsUseCase:
    async def execute(self, task_data: list[dict]):
        print(f"Mock BatchProcessAnalyticsUseCase: Executing with {task_data}")
        # In a real scenario, this would process the batch of events
        pass


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
    event_data: dict, # Replace with actual AnalyticsEventData schema
    background_tasks: BackgroundTasks, # FastAPI will inject the real one
    current_user: User = Depends(get_current_active_user),
    process_event_use_case: ProcessAnalyticsEventUseCase = Depends()
):
    print(f"[DEBUG] Type of background_tasks in endpoint: {type(background_tasks)}") # Debug print
    user_id_str = str(current_user.id) if current_user else "anonymous"
    # Simplified task_data for placeholder
    task_data_to_send = {
        "event_data": event_data,
        "user_id": user_id_str,
    }
    background_tasks.add_task(process_event_use_case.execute, task_data_to_send)
    return {"status": "success", "message": "Event received", "data": {"event_id": "mock_event_id"}}

@router.post("/events/batch", status_code=status.HTTP_202_ACCEPTED)
async def record_analytics_batch(
    events_data: list[dict], # Replace with actual AnalyticsEventBatchData schema
    background_tasks: BackgroundTasks, # FastAPI will inject the real one
    current_user: User = Depends(get_current_active_user),
    batch_process_use_case: BatchProcessAnalyticsUseCase = Depends()
):
    user_id_str = str(current_user.id) if current_user else "anonymous"
    # Simplified task_data for placeholder
    # Assuming each item in events_data is an event
    tasks_to_send = [
        {
            "event_data": event,
            "user_id": user_id_str,
        } for event in events_data
    ]
    background_tasks.add_task(batch_process_use_case.execute, tasks_to_send)
    return {"status": "success", "message": "Batch events received", "data": {"batch_size": len(events_data)}} 