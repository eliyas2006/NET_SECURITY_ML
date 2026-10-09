"""
Dashboard REST API Endpoints.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.app.database.connection import get_db
from backend.app.services.audit_service import AuditService
from backend.app.schemas.api import DashboardSummary

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def api_get_dashboard_summary(db: Session = Depends(get_db)):
    """Retrieves high-level posture KPIs, risk distribution, and recent audits for the dashboard."""
    service = AuditService(db)
    return service.get_dashboard_summary()
