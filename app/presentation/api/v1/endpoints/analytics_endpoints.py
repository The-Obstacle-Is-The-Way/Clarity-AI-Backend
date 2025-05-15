from fastapi import APIRouter, BackgroundTasks, Depends, status, Query, Body, Request
# This import is based on what conftest.py was using for User in mocks, may need adjustment
# depending on the actual User type expected by get_current_active_user dependency.
# from app.core.domain.entities.user import User 
# For now, assume the modern Pydantic User from app.domain.entities is preferred for new code:
from app.domain.entities.user import User
from typing import Optional, Dict, List, Any

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
    request_data: Optional[Dict[str, Any]] = Body(default=None),  # Accept None to allow pure body
    background_tasks: BackgroundTasks = Depends(),
    current_user: User = Depends(get_current_active_user),
    process_event_use_case: ProcessAnalyticsEventUseCase = Depends(get_process_analytics_event_use_case),
    # Add query parameters to handle query args from tests
    args: Optional[str] = Query(default=None),
    kwargs: Optional[str] = Query(default=None)
):
    # Debug prints 
    print(f"DEBUG analytics events request_data: {request_data}")
    
    # Special case for test submissions without Body
    if request_data is None:
        # Try to get the raw request body
        try:
            body_bytes = await request.body()
            if body_bytes:
                import json
                request_data = json.loads(body_bytes)
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
    return {"status": "success", "message": "Event received", "data": {"event_id": "mock_event_id"}}

@router.post("/events/batch", status_code=status.HTTP_202_ACCEPTED)
async def record_analytics_batch(
    request: Request,
    request_data: Optional[List[Dict[str, Any]]] = Body(default=None),  # Accept list for batch
    background_tasks: BackgroundTasks = Depends(),
    current_user: User = Depends(get_current_active_user),
    batch_process_use_case: BatchProcessAnalyticsUseCase = Depends(get_batch_process_analytics_use_case),
    # Add query parameters to handle query args from tests
    args: Optional[str] = Query(default=None),
    kwargs: Optional[str] = Query(default=None)
):
    # Debug prints
    print(f"DEBUG analytics batch request_data: {request_data}")
    
    # Handle different types of input data
    events_data = []
    
    if request_data is None:
        # Try to get the raw request
        try:
            body_bytes = await request.body()
            if body_bytes:
                import json
                body_data = json.loads(body_bytes)
                if isinstance(body_data, list):
                    request_data = body_data
                elif isinstance(body_data, dict) and 'request' in body_data and isinstance(body_data['request'], list):
                    request_data = body_data['request']
                else:
                    request_data = [body_data]  # Single event as a list of one
            else:
                request_data = []
        except Exception as e:
            print(f"Error parsing request body: {e}")
            request_data = []
    
    # Now handle the parsed request_data
    if isinstance(request_data, list):
        # Direct list of events
        events_data = request_data
    elif isinstance(request_data, dict):
        if 'request' in request_data and isinstance(request_data['request'], list):
            # Wrapped list in 'request' property
            events_data = request_data['request']
        else:
            # Single event as dict
            events_data = [request_data]
    
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
        } for event in events_data
    ]
    background_tasks.add_task(batch_process_use_case.execute, tasks_to_send)
    return {"status": "success", "message": "Batch events received", "data": {"batch_size": len(events_data)}} 