"""
Audits REST API Endpoints.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, Response
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from backend.app.database.connection import get_db
from backend.app.parsers.detector import detect_vendor
from backend.app.services.audit_service import AuditService
from backend.app.reports.generator import generate_html_report
from backend.app.schemas.api import (
    AuditDetailResponse, AuditListItem, AnalyzeTextRequest, VendorDetectionResponse
)
from backend.app.remediation.models import RemediationPlan

router = APIRouter(prefix="/api/audits", tags=["Audits"])


@router.post("/detect-vendor", response_model=VendorDetectionResponse)
def api_detect_vendor(req: AnalyzeTextRequest):
    """Inspects configuration snippet to identify vendor and confidence."""
    res = detect_vendor(req.content)
    return VendorDetectionResponse(
        vendor=res.vendor,
        confidence=res.confidence,
        confidence_level=res.confidence_level,
        reason=res.reason,
        detected_syntax=res.detected_syntax,
        suggested_device_type=res.suggested_device_type
    )


@router.post("/upload", response_model=AuditDetailResponse)
async def api_upload_configuration(
    file: UploadFile = File(...),
    vendor_override: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Accepts a network device configuration file upload (.cfg, .conf, .txt),
    detects vendor, parses syntax, normalizes, executes compliance rules,
    runs ML risk/anomaly inference, and returns complete audit findings.
    """
    # File validation: max size 10MB
    contents = await file.read()
    if len(contents) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds maximum allowed limit (10MB).")

    try:
        text_content = contents.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text_content = contents.decode("latin-1")
        except Exception:
            raise HTTPException(status_code=400, detail="Unable to decode file content as text.")

    service = AuditService(db)
    try:
        return service.process_configuration(
            content=text_content,
            filename=file.filename or "uploaded_config.txt",
            vendor_override=vendor_override
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit execution error: {str(e)}")


@router.post("/analyze", response_model=AuditDetailResponse)
def api_analyze_raw_text(
    req: AnalyzeTextRequest,
    db: Session = Depends(get_db)
):
    """Accepts raw configuration text and executes the complete audit pipeline."""
    if len(req.content.encode("utf-8")) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Configuration size exceeds maximum allowed limit (10MB).")

    service = AuditService(db)
    try:
        return service.process_configuration(
            content=req.content,
            filename=req.filename or "manual_input.txt",
            vendor_override=req.vendor_override
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Audit execution error: {str(e)}")


@router.get("", response_model=List[AuditListItem])
def api_list_audits(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieves list of past audit records."""
    service = AuditService(db)
    return service.list_audits(limit=limit)


@router.get("/{audit_id}", response_model=AuditDetailResponse)
def api_get_audit(
    audit_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves full details, compliance findings, and ML insights for a specific audit."""
    service = AuditService(db)
    audit = service.get_audit(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail=f"Audit '{audit_id}' not found.")
    return audit


@router.get("/{audit_id}/report", response_class=HTMLResponse)
def api_get_audit_report(
    audit_id: str,
    db: Session = Depends(get_db)
):
    """Generates and renders an executive standalone HTML/Printable audit report."""
    service = AuditService(db)
    audit = service.get_audit(audit_id)
    if not audit:
        raise HTTPException(status_code=404, detail=f"Audit '{audit_id}' not found.")
    return generate_html_report(audit)


@router.get("/{audit_id}/remediation", response_model=RemediationPlan)
def api_get_audit_remediation(
    audit_id: str,
    db: Session = Depends(get_db)
):
    """Retrieves structured, vendor-specific remediation plan for all non-compliant controls."""
    service = AuditService(db)
    plan = service.get_remediation_plan(audit_id)
    if not plan:
        raise HTTPException(status_code=404, detail=f"Audit '{audit_id}' not found.")
    return plan


@router.get("/{audit_id}/remediation/download")
def api_download_remediation_script(
    audit_id: str,
    db: Session = Depends(get_db)
):
    """Downloads reviewable, vendor-specific remediation configuration script (.cfg, .conf, .set)."""
    service = AuditService(db)
    plan = service.get_remediation_plan(audit_id)
    if not plan:
        raise HTTPException(status_code=404, detail=f"Audit '{audit_id}' not found.")

    clean_vendor = plan.vendor.lower().replace(" ", "_")
    filename = f"remediation_{clean_vendor}_{plan.audit_id}{plan.file_extension}"

    return Response(
        content=plan.full_script,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


@router.delete("/{audit_id}")
def api_delete_audit(
    audit_id: str,
    db: Session = Depends(get_db)
):
    """Deletes an audit record and its associated findings."""
    from backend.app.database.models import AuditRecord
    record = db.query(AuditRecord).filter(AuditRecord.id == audit_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Audit not found.")
    db.delete(record)
    db.commit()
    return {"status": "success", "message": f"Audit {audit_id} deleted."}
