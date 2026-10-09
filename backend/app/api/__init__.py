"""
API routers init.
"""

from backend.app.api.audits import router as audits_router
from backend.app.api.dashboard import router as dashboard_router

__all__ = ["audits_router", "dashboard_router"]
