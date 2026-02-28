"""Report generation API routes.

Provides:
- GET    /reports              — list reports (paginated, filtered)
- POST   /reports              — create a new report
- GET    /reports/templates     — list available report templates
- GET    /reports/stats         — aggregate report statistics
- GET    /reports/{id}          — get a single report with linked items
- PUT    /reports/{id}          — update a report
- DELETE /reports/{id}          — delete a report
- POST   /reports/{id}/items    — add linked item (intel/IOC/technique)
- DELETE /reports/{id}/items/{item_id} — remove linked item
- POST   /reports/{id}/ai-summary     — generate AI executive summary
- GET    /reports/{id}/export          — export (markdown, pdf, stix, html, csv)
"""

from __future__ import annotations

import json
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.middleware.auth import require_analyst, require_viewer
from app.models.models import User
from app.schemas import (
    ReportAISummaryRequest,
    ReportCreate,
    ReportItemCreate,
    ReportItemResponse,
    ReportListResponse,
    ReportResponse,
    ReportStatsResponse,
    ReportUpdate,
)
from app.services import reports as report_service

router = APIRouter(prefix="/reports", tags=["reports"])


# ─── List & Create ────────────────────────────────────────


@router.get("", response_model=ReportListResponse)
async def list_reports(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    report_type: str | None = Query(None),
    search: str | None = Query(None),
    sort_by: str = Query("updated_at"),
    sort_order: str = Query("desc"),
):
    """List reports with pagination and filters."""
    reports, total = await report_service.list_reports(
        db,
        page=page,
        page_size=page_size,
        status=status,
        report_type=report_type,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    pages = max(1, -(-total // page_size))  # ceil division

    # Enrich with author email and items
    enriched = []
    for r in reports:
        resp = ReportResponse.model_validate(r)
        # Items will be loaded per-detail, not in list
        resp.items = []
        enriched.append(resp)

    return ReportListResponse(
        reports=enriched,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.post("", response_model=ReportResponse, status_code=201)
async def create_report(
    body: ReportCreate,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new report. Requires analyst role."""
    report = await report_service.create_report(db, user.id, body.model_dump())
    await db.commit()
    return ReportResponse.model_validate(report)


# ─── Templates & Stats ───────────────────────────────────


@router.get("/templates")
async def get_templates(
    user: Annotated[User, Depends(require_viewer)],
):
    """Get available report templates."""
    return report_service.get_templates()


@router.get("/stats", response_model=ReportStatsResponse)
async def get_stats(
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get aggregate report statistics."""
    stats = await report_service.get_report_stats(db)
    return ReportStatsResponse(**stats)


# ─── Single Report ────────────────────────────────────────


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a report with its linked items."""
    report = await report_service.get_report(db, report_id)
    if not report:
        raise HTTPException(404, "Report not found")

    items = await report_service.get_report_items(db, report_id)
    resp = ReportResponse.model_validate(report)
    resp.items = [ReportItemResponse.model_validate(i) for i in items]

    # Get author email
    from sqlalchemy import select
    from app.models.models import User as UserModel
    author = (await db.execute(
        select(UserModel).where(UserModel.id == report.author_id)
    )).scalar_one_or_none()
    if author:
        resp.author_email = author.email

    return resp


@router.put("/{report_id}", response_model=ReportResponse)
async def update_report(
    report_id: uuid.UUID,
    body: ReportUpdate,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update report fields. Requires analyst role."""
    data = body.model_dump(exclude_none=True)
    if not data:
        raise HTTPException(400, "No fields to update")

    # Convert enum values to their string form
    for key in ("status", "severity", "report_type", "tlp"):
        if key in data and hasattr(data[key], "value"):
            data[key] = data[key].value

    report = await report_service.update_report(db, report_id, data)
    if not report:
        raise HTTPException(404, "Report not found")
    await db.commit()
    return ReportResponse.model_validate(report)


@router.delete("/{report_id}")
async def delete_report(
    report_id: uuid.UUID,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Delete a report and its linked items. Requires analyst role."""
    ok = await report_service.delete_report(db, report_id)
    if not ok:
        raise HTTPException(404, "Report not found")
    await db.commit()
    return {"deleted": True}


# ─── Linked Items ─────────────────────────────────────────


@router.post("/{report_id}/items", response_model=ReportItemResponse, status_code=201)
async def add_item(
    report_id: uuid.UUID,
    body: ReportItemCreate,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Add an intel item, IOC, or technique to a report."""
    item = await report_service.add_report_item(db, report_id, user.id, body.model_dump())
    if not item:
        raise HTTPException(400, "Report not found or item already linked")
    await db.commit()
    return ReportItemResponse.model_validate(item)


@router.delete("/{report_id}/items/{item_id}")
async def remove_item(
    report_id: uuid.UUID,
    item_id: uuid.UUID,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Remove a linked item from a report."""
    ok = await report_service.remove_report_item(db, report_id, item_id)
    if not ok:
        raise HTTPException(404, "Item not found")
    await db.commit()
    return {"deleted": True}


# ─── AI Summary ───────────────────────────────────────────


@router.post("/{report_id}/ai-summary")
async def generate_ai_summary(
    report_id: uuid.UUID,
    user: Annotated[User, Depends(require_analyst)],
    db: Annotated[AsyncSession, Depends(get_db)],
    body: ReportAISummaryRequest | None = None,
):
    """Generate AI executive summary for the report."""
    include = body.include_linked_items if body else True
    summary = await report_service.generate_ai_summary(db, report_id, include)
    if summary is None:
        raise HTTPException(503, "AI service unavailable or report not found")
    await db.commit()
    return {"summary": summary}


# ─── Export ───────────────────────────────────────────────


@router.get("/{report_id}/export")
async def export_report(
    report_id: uuid.UUID,
    user: Annotated[User, Depends(require_viewer)],
    db: Annotated[AsyncSession, Depends(get_db)],
    format: str = Query("markdown"),
    include_tlp_watermark: bool = Query(True),
):
    """Export a report. Supports: markdown, pdf, stix, html, csv."""
    if format == "markdown":
        md = await report_service.export_markdown(db, report_id, include_tlp_watermark)
        if not md:
            raise HTTPException(404, "Report not found")
        return PlainTextResponse(
            content=md,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="report-{report_id}.md"'},
        )

    if format == "pdf":
        pdf_bytes = await report_service.export_pdf(db, report_id, include_tlp_watermark)
        if not pdf_bytes:
            raise HTTPException(404, "Report not found")
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="report-{report_id}.pdf"'},
        )

    if format == "stix":
        bundle = await report_service.export_stix(db, report_id)
        if not bundle:
            raise HTTPException(404, "Report not found")
        stix_json = json.dumps(bundle, indent=2, default=str)
        return Response(
            content=stix_json,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="report-{report_id}-stix.json"'},
        )

    if format == "html":
        html_str = await report_service.export_html(db, report_id, include_tlp_watermark)
        if not html_str:
            raise HTTPException(404, "Report not found")
        return Response(
            content=html_str,
            media_type="text/html",
            headers={"Content-Disposition": f'attachment; filename="report-{report_id}.html"'},
        )

    if format == "csv":
        csv_str = await report_service.export_csv(db, report_id)
        if not csv_str:
            raise HTTPException(404, "Report not found")
        return PlainTextResponse(
            content=csv_str,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="report-{report_id}.csv"'},
        )

    raise HTTPException(400, f"Unsupported export format: {format}. Supported: markdown, pdf, stix, html, csv")
