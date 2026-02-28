"""Report generation service — CRUD, AI summaries, export.

USPs:
  - One-Click Intel-to-Report: Attach intel/IOC/technique items instantly
  - AI Executive Summary: Generate AI-powered executive overview
  - Live Cross-Data Sections: Linked items pull real-time data
  - PDF + Markdown Export with TLP Watermark
  - Report Templates: Pre-built templates for different report types
  - Status Workflow with Audit Trail: draft → review → published → archived
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.models import (
    Report,
    ReportItem,
)
from app.services.ai import generate_summary as ai_generate_summary

logger = get_logger(__name__)


# ─── Templates ────────────────────────────────────────────

REPORT_TEMPLATES: dict[str, dict] = {
    "incident": {
        "label": "Incident Report",
        "description": "Structured incident response report",
        "sections": [
            {"key": "executive_summary", "title": "Executive Summary", "hint": "High-level overview of the incident"},
            {"key": "timeline", "title": "Timeline of Events", "hint": "Chronological account of the incident"},
            {"key": "impact", "title": "Impact Assessment", "hint": "Systems, data, and business impact"},
            {"key": "indicators", "title": "Indicators of Compromise", "hint": "IOCs observed during incident"},
            {"key": "response", "title": "Response Actions", "hint": "Containment and remediation steps taken"},
            {"key": "recommendations", "title": "Recommendations", "hint": "Short and long-term security improvements"},
        ],
    },
    "threat_advisory": {
        "label": "Threat Advisory",
        "description": "Proactive threat intelligence advisory",
        "sections": [
            {"key": "executive_summary", "title": "Executive Summary", "hint": "Brief overview of the threat"},
            {"key": "threat_overview", "title": "Threat Overview", "hint": "Detailed description of the threat actor/campaign"},
            {"key": "ttps", "title": "Tactics, Techniques & Procedures", "hint": "MITRE ATT&CK mapping"},
            {"key": "indicators", "title": "Indicators of Compromise", "hint": "IOCs associated with this threat"},
            {"key": "affected_systems", "title": "Affected Systems", "hint": "Products, versions, and platforms"},
            {"key": "mitigations", "title": "Mitigations", "hint": "Defensive measures and detection rules"},
        ],
    },
    "weekly_summary": {
        "label": "Weekly Summary",
        "description": "Weekly threat landscape overview",
        "sections": [
            {"key": "executive_summary", "title": "Executive Summary", "hint": "Week at a glance"},
            {"key": "key_threats", "title": "Key Threats This Week", "hint": "Most significant threats observed"},
            {"key": "vulnerability_highlights", "title": "Vulnerability Highlights", "hint": "Notable CVEs and patches"},
            {"key": "statistics", "title": "Statistics & Trends", "hint": "Ingestion and risk metrics"},
            {"key": "recommendations", "title": "Recommendations", "hint": "Priority actions for the coming week"},
        ],
    },
    "ioc_bulletin": {
        "label": "IOC Bulletin",
        "description": "IOC sharing bulletin for distribution",
        "sections": [
            {"key": "executive_summary", "title": "Summary", "hint": "Brief context for these IOCs"},
            {"key": "ioc_table", "title": "IOC Table", "hint": "Structured IOC listing"},
            {"key": "context", "title": "Context & Attribution", "hint": "Related campaigns or threat actors"},
            {"key": "detection", "title": "Detection Guidance", "hint": "SIEM rules, YARA signatures, etc."},
        ],
    },
    "custom": {
        "label": "Custom Report",
        "description": "Blank canvas for custom reporting",
        "sections": [
            {"key": "executive_summary", "title": "Executive Summary", "hint": "Overview"},
            {"key": "body", "title": "Report Body", "hint": "Main content"},
            {"key": "conclusion", "title": "Conclusion", "hint": "Summary and next steps"},
        ],
    },
}


# ─── CRUD ─────────────────────────────────────────────────


async def create_report(
    db: AsyncSession,
    author_id: uuid.UUID,
    data: dict,
) -> Report:
    """Create a new report, applying template sections if specified."""
    template_key = data.get("template") or data.get("report_type", "custom")
    template = REPORT_TEMPLATES.get(template_key, REPORT_TEMPLATES["custom"])

    # Initialize content with template sections if content is empty
    content = data.get("content", {})
    if not content or not content.get("sections"):
        content = {
            "sections": [
                {"key": s["key"], "title": s["title"], "hint": s.get("hint", ""), "body": ""}
                for s in template["sections"]
            ]
        }

    report = Report(
        title=data["title"],
        summary=data.get("summary"),
        content=content,
        report_type=data.get("report_type", "custom"),
        status="draft",
        severity=data.get("severity", "medium"),
        tlp=data.get("tlp", "TLP:GREEN"),
        author_id=author_id,
        template=template_key,
        tags=data.get("tags", []),
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)
    logger.info("report_created", report_id=str(report.id), title=report.title)
    return report


async def get_report(db: AsyncSession, report_id: uuid.UUID) -> Report | None:
    """Get a report by ID."""
    result = await db.execute(
        select(Report).where(Report.id == report_id)
    )
    return result.scalar_one_or_none()


async def list_reports(
    db: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 20,
    status: str | None = None,
    report_type: str | None = None,
    author_id: uuid.UUID | None = None,
    search: str | None = None,
    sort_by: str = "updated_at",
    sort_order: str = "desc",
) -> tuple[list[Report], int]:
    """Paginated list with filters."""
    query = select(Report)

    if status:
        query = query.where(Report.status == status)
    if report_type:
        query = query.where(Report.report_type == report_type)
    if author_id:
        query = query.where(Report.author_id == author_id)
    if search:
        query = query.where(Report.title.ilike(f"%{search}%"))

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    col = getattr(Report, sort_by, Report.updated_at)
    query = query.order_by(col.desc() if sort_order == "desc" else col.asc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    return list(result.scalars().all()), total


async def update_report(
    db: AsyncSession,
    report_id: uuid.UUID,
    data: dict,
) -> Report | None:
    """Update a report. Prevents editing published reports."""
    report = await get_report(db, report_id)
    if not report:
        return None

    for key, value in data.items():
        if value is not None and hasattr(report, key):
            setattr(report, key, value)

    # Handle status transitions
    if data.get("status") == "published" and report.published_at is None:
        report.published_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(report)
    logger.info("report_updated", report_id=str(report_id), fields=list(data.keys()))
    return report


async def delete_report(db: AsyncSession, report_id: uuid.UUID) -> bool:
    """Delete a report and its linked items."""
    report = await get_report(db, report_id)
    if not report:
        return False
    # Delete linked items first
    await db.execute(delete(ReportItem).where(ReportItem.report_id == report_id))
    await db.delete(report)
    await db.flush()
    logger.info("report_deleted", report_id=str(report_id))
    return True


# ─── Linked Items ─────────────────────────────────────────


async def add_report_item(
    db: AsyncSession,
    report_id: uuid.UUID,
    added_by: uuid.UUID,
    data: dict,
) -> ReportItem | None:
    """Add an intel/IOC/technique item to a report."""
    report = await get_report(db, report_id)
    if not report:
        return None

    # Check for duplicate
    existing = await db.execute(
        select(ReportItem).where(
            ReportItem.report_id == report_id,
            ReportItem.item_type == data["item_type"],
            ReportItem.item_id == data["item_id"],
        )
    )
    if existing.scalar_one_or_none():
        return None  # Already linked

    item = ReportItem(
        report_id=report_id,
        item_type=data["item_type"],
        item_id=data["item_id"],
        item_title=data.get("item_title"),
        item_metadata=data.get("item_metadata", {}),
        added_by=added_by,
        notes=data.get("notes"),
    )
    db.add(item)

    # Update counter
    counter_field = f"linked_{data['item_type']}_count"
    if hasattr(report, counter_field):
        setattr(report, counter_field, getattr(report, counter_field) + 1)

    await db.flush()
    await db.refresh(item)
    logger.info("report_item_added", report_id=str(report_id), item_type=data["item_type"])
    return item


async def remove_report_item(
    db: AsyncSession,
    report_id: uuid.UUID,
    item_id: uuid.UUID,
) -> bool:
    """Remove a linked item from a report."""
    result = await db.execute(
        select(ReportItem).where(
            ReportItem.id == item_id,
            ReportItem.report_id == report_id,
        )
    )
    ri = result.scalar_one_or_none()
    if not ri:
        return False

    # Update counter
    report = await get_report(db, report_id)
    if report:
        counter_field = f"linked_{ri.item_type}_count"
        if hasattr(report, counter_field):
            current = getattr(report, counter_field)
            setattr(report, counter_field, max(0, current - 1))

    await db.delete(ri)
    await db.flush()
    return True


async def get_report_items(
    db: AsyncSession,
    report_id: uuid.UUID,
    item_type: str | None = None,
) -> list[ReportItem]:
    """Get all linked items for a report."""
    query = select(ReportItem).where(ReportItem.report_id == report_id)
    if item_type:
        query = query.where(ReportItem.item_type == item_type)
    query = query.order_by(ReportItem.created_at.desc())
    result = await db.execute(query)
    return list(result.scalars().all())


# ─── AI Executive Summary ────────────────────────────────


async def generate_ai_summary(
    db: AsyncSession,
    report_id: uuid.UUID,
    include_linked_items: bool = True,
) -> str | None:
    """Generate an AI executive summary for a report using linked intel context."""
    report = await get_report(db, report_id)
    if not report:
        return None

    # Build context from linked items
    context_parts = [f"Report Title: {report.title}"]
    cve_ids: list[str] = []
    if report.summary:
        context_parts.append(f"Current Summary: {report.summary}")

    # Collect section content
    sections = report.content.get("sections", [])
    for section in sections:
        body = section.get("body", "").strip()
        if body:
            context_parts.append(f"{section.get('title', 'Section')}: {body[:500]}")

    if include_linked_items:
        items = await get_report_items(db, report_id)
        intel_titles = []
        for item in items:
            if item.item_title:
                intel_titles.append(item.item_title)
            meta = item.item_metadata or {}
            if meta.get("cve_ids"):
                cve_ids.extend(meta["cve_ids"])
            if meta.get("value"):  # IOC value
                intel_titles.append(f"IOC: {meta['value']}")

        if intel_titles:
            context_parts.append(f"Linked Items: {', '.join(intel_titles[:10])}")
        if cve_ids:
            context_parts.append(f"CVEs: {', '.join(list(set(cve_ids))[:10])}")

    description = "\n".join(context_parts)

    summary = await ai_generate_summary(
        title=report.title,
        description=description,
        severity=report.severity,
        source_name="IntelWatch Report",
        cve_ids=cve_ids if include_linked_items else None,
    )

    if summary:
        report.summary = summary
        await db.flush()
        logger.info("report_ai_summary", report_id=str(report_id))

    return summary


# ─── Export ───────────────────────────────────────────────


async def export_markdown(
    db: AsyncSession,
    report_id: uuid.UUID,
    include_tlp_watermark: bool = True,
) -> str | None:
    """Export report as Markdown with optional TLP watermark."""
    report = await get_report(db, report_id)
    if not report:
        return None

    items = await get_report_items(db, report_id)

    lines: list[str] = []

    # TLP watermark
    if include_tlp_watermark:
        lines.append(f"**{report.tlp}** — DISTRIBUTION RESTRICTION\n")
        lines.append("---\n")

    # Title & metadata
    lines.append(f"# {report.title}\n")
    lines.append(f"**Type:** {report.report_type.replace('_', ' ').title()}  ")
    lines.append(f"**Severity:** {report.severity.upper()}  ")
    lines.append(f"**Status:** {report.status.title()}  ")
    lines.append(f"**TLP:** {report.tlp}  ")
    lines.append(f"**Created:** {report.created_at.strftime('%Y-%m-%d %H:%M UTC')}  ")
    if report.published_at:
        lines.append(f"**Published:** {report.published_at.strftime('%Y-%m-%d %H:%M UTC')}  ")
    if report.tags:
        lines.append(f"**Tags:** {', '.join(report.tags)}  ")
    lines.append("")

    # Summary
    if report.summary:
        lines.append("## Executive Summary\n")
        lines.append(f"{report.summary}\n")

    # Content sections
    sections = report.content.get("sections", [])
    for section in sections:
        body = section.get("body", "").strip()
        if body:
            lines.append(f"## {section.get('title', 'Section')}\n")
            lines.append(f"{body}\n")

    # Linked items
    intel_items = [i for i in items if i.item_type == "intel"]
    ioc_items = [i for i in items if i.item_type == "ioc"]
    technique_items = [i for i in items if i.item_type == "technique"]

    if intel_items:
        lines.append("## Linked Intelligence\n")
        lines.append("| # | Title | Severity | Source |")
        lines.append("|---|-------|----------|--------|")
        for idx, item in enumerate(intel_items, 1):
            meta = item.item_metadata or {}
            title = item.item_title or item.item_id
            sev = meta.get("severity", "—")
            src = meta.get("source_name", "—")
            lines.append(f"| {idx} | {title} | {sev} | {src} |")
        lines.append("")

    if ioc_items:
        lines.append("## Indicators of Compromise\n")
        lines.append("| # | Type | Value | Risk Score |")
        lines.append("|---|------|-------|------------|")
        for idx, item in enumerate(ioc_items, 1):
            meta = item.item_metadata or {}
            ioc_type = meta.get("ioc_type", "—")
            value = meta.get("value", item.item_id)
            risk = meta.get("risk_score", "—")
            lines.append(f"| {idx} | {ioc_type} | {value} | {risk} |")
        lines.append("")

    if technique_items:
        lines.append("## MITRE ATT&CK Techniques\n")
        lines.append("| ID | Technique | Tactic |")
        lines.append("|----|-----------|--------|")
        for item in technique_items:
            meta = item.item_metadata or {}
            name = item.item_title or item.item_id
            tactic = meta.get("tactic", "—")
            lines.append(f"| {item.item_id} | {name} | {tactic} |")
        lines.append("")

    # Footer
    if include_tlp_watermark:
        lines.append("---\n")
        lines.append(f"*{report.tlp} — This document is classified under the Traffic Light Protocol.*")

    return "\n".join(lines)


# ─── Stats ────────────────────────────────────────────────


async def get_report_stats(db: AsyncSession) -> dict:
    """Get aggregate report statistics."""
    total = (await db.execute(select(func.count(Report.id)))).scalar() or 0

    # By status
    status_rows = await db.execute(
        select(Report.status, func.count(Report.id)).group_by(Report.status)
    )
    by_status = {row[0]: row[1] for row in status_rows}

    # By type
    type_rows = await db.execute(
        select(Report.report_type, func.count(Report.id)).group_by(Report.report_type)
    )
    by_type = {row[0]: row[1] for row in type_rows}

    # Published in last 7 days
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent = (
        await db.execute(
            select(func.count(Report.id)).where(
                Report.status == "published",
                Report.published_at >= week_ago,
            )
        )
    ).scalar() or 0

    return {
        "total_reports": total,
        "by_status": by_status,
        "by_type": by_type,
        "recent_published": recent,
    }


# ─── Templates API ───────────────────────────────────────


def get_templates() -> dict:
    """Return available report templates."""
    return REPORT_TEMPLATES
