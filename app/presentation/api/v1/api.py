from app.presentation.api.v1.endpoints.audit_logs import router as audit_logs_router

api_router.include_router(
    alerts_router, prefix="/biometric-alerts", tags=["biometric_alerts"]
)
api_router.include_router(audit_logs_router, tags=["audit"])
