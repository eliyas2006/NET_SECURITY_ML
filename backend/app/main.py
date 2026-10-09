"""
FastAPI Application Entry Point.
AI-Driven Multi-Vendor Network Security Compliance Auditor.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.app.database.connection import init_db
from backend.app.api.audits import router as audits_router
from backend.app.api.dashboard import router as dashboard_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB tables on application startup
    init_db()
    yield


app = FastAPI(
    title="AI-Driven Multi-Vendor Network Security Compliance Auditor API",
    description=(
        "Production-grade compliance auditing platform analyzing Cisco, Fortinet, and Palo Alto "
        "network security configurations using deterministic CIS/NIST rule engines and Machine Learning."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Environment-configured CORS Allowed Origins
cors_origins_env = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:8000,http://localhost:8000"
)
allowed_origins = [orig.strip() for orig in cors_origins_env.split(",") if orig.strip()]
is_wildcard = "*" in allowed_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if not is_wildcard else ["*"],
    allow_credentials=not is_wildcard,  # W3C CORS specification: credentials disallowed with wildcard origins
    allow_methods=["GET", "POST", "DELETE", "PUT", "OPTIONS"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(audits_router)
app.include_router(dashboard_router)


@app.get("/api/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "AI Network Compliance Auditor",
        "supported_vendors": ["Cisco", "Fortinet", "Palo Alto"],
        "version": "1.0.0"
    }


# If frontend build exists, serve it as static files
frontend_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../frontend/dist"))
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(frontend_dist, "index.html"))
