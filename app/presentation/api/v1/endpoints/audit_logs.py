"""
Audit Logs API endpoints.

This module provides API endpoints for retrieving and managing audit logs
in compliance with HIPAA requirements.
"""

import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import FileResponse

from app.application.services.audit_log_service import AuditLogService
from app.core.interfaces.services.audit_logger_interface import (
    IAuditLogger,
    AuditEventType,
    AuditSeverity,
)
from app.core.interfaces.repositories.audit_log_repository_interface import (
    IAuditLogRepository,
)
from app.domain.entities.audit_log import AuditLog
from app.presentation.api.dependencies.repositories import get_audit_log_repository
from app.presentation.api.dependencies.services import get_audit_logger
from app.presentation.api.dependencies.auth import get_current_user_with_permission
from app.domain.entities.user import User
from app.presentation.api.models.audit_log import (
    AuditLogResponseModel,
    AuditSearchRequest,
    SecurityDashboardResponse,
)

router = APIRouter(tags=["audit"], prefix="/audit")


@router.get(
    "/logs",
    response_model=List[AuditLogResponseModel],
    summary="Get audit logs by filters",
    description="Retrieve audit logs with optional filtering. Requires admin or security officer role.",
)
async def get_audit_logs(
    event_type: Optional[AuditEventType] = None,
    actor_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    audit_service: IAuditLogger = Depends(get_audit_logger),
    current_user: User = Depends(
        get_current_user_with_permission(["admin", "security_officer"])
    ),
) -> List[Dict[str, Any]]:
    """
    Get audit logs with optional filtering.

    This endpoint provides access to the HIPAA-compliant audit logs with various
    filtering options. Due to the sensitive nature of audit logs, this endpoint
    requires administrative privileges.
    """
    # Build filters from parameters
    filters = {}
    if event_type:
        filters["event_type"] = event_type
    if actor_id:
        filters["actor_id"] = actor_id
    if resource_type:
        filters["resource_type"] = resource_type
    if resource_id:
        filters["resource_id"] = resource_id

    # End date defaults to now if start_date is provided but end_date isn't
    if start_date and not end_date:
        end_date = datetime.now()

    # Get the audit logs
    logs = await audit_service.get_audit_trail(
        filters=filters,
        start_time=start_date,
        end_time=end_date,
        limit=limit,
        offset=offset,
    )

    # Log this access to the audit logs (meta-audit)
    await audit_service.log_security_event(
        description="Audit logs accessed",
        actor_id=str(current_user.id),
        status="success",
        details={
            "filters": filters,
            "start_date": start_date.isoformat() if start_date else None,
            "end_date": end_date.isoformat() if end_date else None,
            "limit": limit,
            "offset": offset,
            "results_count": len(logs),
        },
    )

    return logs


@router.post(
    "/search",
    response_model=List[AuditLogResponseModel],
    summary="Search audit logs with advanced filters",
    description="Search audit logs with advanced filtering options. Requires admin or security officer role.",
)
async def search_audit_logs(
    search_request: AuditSearchRequest,
    audit_service: IAuditLogger = Depends(get_audit_logger),
    current_user: User = Depends(
        get_current_user_with_permission(["admin", "security_officer"])
    ),
) -> List[Dict[str, Any]]:
    """
    Search audit logs with advanced filtering.

    This endpoint provides more advanced search capabilities for audit logs
    than the GET endpoint, allowing for more complex filtering.
    """
    # Get the audit logs
    logs = await audit_service.get_audit_trail(
        filters=search_request.filters,
        start_time=search_request.start_date,
        end_time=search_request.end_date,
        limit=search_request.limit,
        offset=search_request.offset,
    )

    # Log this access to the audit logs (meta-audit)
    await audit_service.log_security_event(
        description="Audit logs searched",
        actor_id=str(current_user.id),
        status="success",
        details={
            "filters": search_request.filters,
            "start_date": search_request.start_date.isoformat()
            if search_request.start_date
            else None,
            "end_date": search_request.end_date.isoformat()
            if search_request.end_date
            else None,
            "limit": search_request.limit,
            "offset": search_request.offset,
            "results_count": len(logs),
        },
    )

    return logs


@router.get(
    "/dashboard",
    response_model=SecurityDashboardResponse,
    summary="Get security dashboard data",
    description="Get data for the security dashboard. Requires admin or security officer role.",
)
async def get_security_dashboard(
    days: int = Query(7, ge=1, le=90),
    audit_service: AuditLogService = Depends(get_audit_logger),
    current_user: User = Depends(
        get_current_user_with_permission(["admin", "security_officer"])
    ),
) -> Dict[str, Any]:
    """
    Get data for the security dashboard.

    This endpoint provides aggregated data for a security dashboard,
    including statistics on audit logs and recent security events.
    """
    # Get dashboard data
    dashboard_data = await audit_service.get_security_dashboard_data(days=days)

    # Log this access
    await audit_service.log_security_event(
        description="Security dashboard accessed",
        actor_id=str(current_user.id),
        status="success",
        details={"days": days},
    )

    return dashboard_data


@router.get(
    "/export",
    summary="Export audit logs",
    description="Export audit logs for compliance reporting. Requires admin role.",
)
async def export_audit_logs(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    format: str = Query("json", regex="^(json|csv)$"),
    audit_service: AuditLogService = Depends(get_audit_logger),
    current_user: User = Depends(get_current_user_with_permission(["admin"])),
) -> FileResponse:
    """
    Export audit logs for compliance reporting.

    This endpoint exports audit logs for compliance reporting, creating
    a downloadable file with the logs for the specified time period.
    """
    # Default to last 30 days if no dates provided
    if not start_date:
        end_date = end_date or datetime.now()
        start_date = end_date - timedelta(days=30)

    # Export logs
    file_path = await audit_service.export_audit_logs(
        start_time=start_date, end_time=end_date, format=format
    )

    # Log this export
    await audit_service.log_security_event(
        description="Audit logs exported",
        actor_id=str(current_user.id),
        status="success",
        severity=AuditSeverity.HIGH,
        details={
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat()
            if end_date
            else datetime.now().isoformat(),
            "format": format,
            "file_path": file_path,
        },
    )

    return FileResponse(
        path=file_path,
        filename=f"audit_logs_{start_date.strftime('%Y%m%d')}_to_{end_date.strftime('%Y%m%d') if end_date else 'now'}.{format}",
        media_type="application/json" if format == "json" else "text/csv",
    )
