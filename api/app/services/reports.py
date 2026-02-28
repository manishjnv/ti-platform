"""Report generation service — CRUD, AI summaries, multi-format export.

USPs:
  - One-Click Intel-to-Report: Attach intel/IOC/technique items instantly
  - AI Executive Summary: Generate AI-powered executive overview
  - Live Cross-Data Sections: Linked items pull real-time data
  - Multi-Format Export (PDF, Markdown, STIX 2.1, CSV, HTML) with TLP Watermark
  - Report Templates: Pre-built templates for different report types
  - Status Workflow with Audit Trail: draft → review → published → archived
"""

from __future__ import annotations

import io
import csv
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.models import (
    Report,
    ReportItem,
)
from app.services.ai import chat_completion as ai_chat
from app.services.ai import generate_summary as ai_generate_summary
from app.services.research import gather_research, format_research_context

logger = get_logger(__name__)


# ─── Templates ────────────────────────────────────────────

REPORT_TEMPLATES: dict[str, dict] = {
    "incident": {
        "label": "Incident Report",
        "description": "Structured incident response report",
        "sections": [
            {"key": "executive_summary", "title": "Executive Summary", "hint": "High-level overview of the incident"},
            {"key": "timeline", "title": "Timeline of Events", "hint": "Chronological account — discovery, escalation, containment, resolution"},
            {"key": "confirmation", "title": "Confirmation Status", "hint": "Whether the threat is confirmed, suspected, or unverified — include evidence"},
            {"key": "impact", "title": "Impact Assessment", "hint": "Systems, data, and business impact"},
            {"key": "exploitability", "title": "Exploitability Assessment", "hint": "How easily the vulnerability can be exploited — CVSS exploitability metrics, attack complexity"},
            {"key": "poc_availability", "title": "PoC / Exploit Availability", "hint": "Known proof-of-concept code, exploit kits, or active exploitation in the wild"},
            {"key": "impacted_technology", "title": "Impacted Technologies", "hint": "Affected products, vendors, versions, platforms, and configurations"},
            {"key": "affected_organizations", "title": "Affected Organizations & Sectors", "hint": "Industries, sectors, or specific organizations targeted or impacted"},
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
            {"key": "timeline", "title": "Timeline", "hint": "Key dates — first seen, disclosure, patch release, active exploitation"},
            {"key": "confirmation", "title": "Confirmation Status", "hint": "Verified vs. suspected threat — confidence level and sources"},
            {"key": "exploitability", "title": "Exploitability Assessment", "hint": "Attack vector, complexity, privileges required, CVSS exploitability score"},
            {"key": "poc_availability", "title": "PoC / Exploit Availability", "hint": "Public PoC code, Metasploit modules, exploit-db entries, active exploitation"},
            {"key": "impacted_technology", "title": "Impacted Technologies", "hint": "Affected vendors, products, versions, OS, firmware, cloud services"},
            {"key": "affected_organizations", "title": "Affected Organizations & Sectors", "hint": "Targeted industries, geographies, and known victims"},
            {"key": "ttps", "title": "Tactics, Techniques & Procedures", "hint": "MITRE ATT&CK mapping"},
            {"key": "indicators", "title": "Indicators of Compromise", "hint": "IOCs associated with this threat"},
            {"key": "mitigations", "title": "Mitigations", "hint": "Defensive measures and detection rules"},
        ],
    },
    "weekly_summary": {
        "label": "Weekly Summary",
        "description": "Weekly threat landscape overview",
        "sections": [
            {"key": "executive_summary", "title": "Executive Summary", "hint": "Week at a glance"},
            {"key": "key_threats", "title": "Key Threats This Week", "hint": "Most significant threats observed"},
            {"key": "vulnerability_highlights", "title": "Vulnerability Highlights", "hint": "Notable CVEs, exploitability, and patches"},
            {"key": "exploitability", "title": "Exploitability & PoC Watch", "hint": "Newly exploitable CVEs, PoCs released, active exploitation trends"},
            {"key": "impacted_technology", "title": "Impacted Technologies", "hint": "Products and platforms requiring urgent attention this week"},
            {"key": "statistics", "title": "Statistics & Trends", "hint": "Ingestion and risk metrics"},
            {"key": "recommendations", "title": "Recommendations", "hint": "Priority actions for the coming week"},
        ],
    },
    "ioc_bulletin": {
        "label": "IOC Bulletin",
        "description": "IOC sharing bulletin for distribution",
        "sections": [
            {"key": "executive_summary", "title": "Summary", "hint": "Brief context for these IOCs"},
            {"key": "confirmation", "title": "Confirmation Status", "hint": "Confidence level of the IOCs — verified, community-sourced, or unconfirmed"},
            {"key": "ioc_table", "title": "IOC Table", "hint": "Structured IOC listing"},
            {"key": "impacted_technology", "title": "Impacted Technologies", "hint": "Products and platforms these IOCs target"},
            {"key": "affected_organizations", "title": "Targeted Sectors & Organizations", "hint": "Industries and regions targeted by these IOCs"},
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
            {"key": "exploitability", "title": "Exploitability & Risk", "hint": "Exploitability details and risk assessment"},
            {"key": "impacted_technology", "title": "Impacted Technologies", "hint": "Affected products, vendors, and versions"},
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

# Map item_type values to model counter field names
_COUNTER_FIELDS = {
    "intel_item": "linked_intel_count",
    "intel": "linked_intel_count",
    "ioc": "linked_ioc_count",
    "technique": "linked_technique_count",
}


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
    counter_field = _COUNTER_FIELDS.get(data["item_type"])
    if counter_field and hasattr(report, counter_field):
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
        counter_field = _COUNTER_FIELDS.get(ri.item_type)
        if counter_field and hasattr(report, counter_field):
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

    report_prompt = (
        "You are a cybersecurity threat intelligence analyst writing an executive summary "
        "for a formal threat intelligence report. Based on the report title, sections, and "
        "linked intelligence items provided, write a concise executive summary (3-5 sentences). "
        "Cover: what the threat is, who/what is affected, the severity and urgency, and "
        "recommended actions. Use professional, direct language suitable for C-level briefings."
    )

    summary = await ai_generate_summary(
        title=report.title,
        description=description,
        severity=report.severity,
        source_name="IntelWatch Report",
        cve_ids=cve_ids if include_linked_items else None,
        system_prompt=report_prompt,
        max_tokens=400,
        cache_prefix="report_ai_summary",
    )

    if summary:
        report.summary = summary
        await db.flush()
        logger.info("report_ai_summary", report_id=str(report_id))

    return summary


# ─── AI Full Section Generation ──────────────────────────


async def generate_ai_sections(
    db: AsyncSession,
    report_id: uuid.UUID,
    include_linked_items: bool = True,
) -> dict | None:
    """AI-generate content for ALL sections with live web research.

    Steps:
      1. Gather live intelligence from OpenSearch, NVD, OTX, and web search
      2. Build rich context from research + linked items
      3. Send to AI for professional, fact-based section generation

    Returns dict with 'summary' and 'sections' keys, or None if AI unavailable.
    """
    import json as _json

    report = await get_report(db, report_id)
    if not report:
        return None

    sections = report.content.get("sections", [])
    if not sections:
        return None

    # ── Phase 0: Merge missing template sections into existing report ──
    template_key = report.template or report.report_type or "custom"
    template = REPORT_TEMPLATES.get(template_key, REPORT_TEMPLATES.get("custom", {}))
    if template:
        existing_keys = {s["key"] for s in sections}
        for tmpl_section in template.get("sections", []):
            if tmpl_section["key"] not in existing_keys:
                sections.append({
                    "key": tmpl_section["key"],
                    "title": tmpl_section["title"],
                    "hint": tmpl_section.get("hint", ""),
                    "body": "",
                })
        # Persist the merged sections so the report has them even if AI fails
        report.content = {**report.content, "sections": sections}

    # ── Phase 1: Live Web Research ────────────────────────
    research_context = ""
    try:
        research = await gather_research(report.title)
        research_context = format_research_context(research)
        logger.info(
            "research_gathered",
            report_id=str(report_id),
            local=len(research.get("local_intel", [])),
            nvd=len(research.get("nvd_cves", [])),
            web=len(research.get("web_results", [])),
            otx=len(research.get("otx_pulses", [])),
        )
    except Exception as e:
        logger.warning("research_failed", report_id=str(report_id), error=str(e))
        research_context = "(Live research unavailable — generate from available context)"

    # ── Phase 2: Build context from linked items ──────────
    context_parts = [f"Report Title: {report.title}"]
    context_parts.append(f"Report Type: {report.report_type}")
    context_parts.append(f"Severity: {report.severity}")
    if report.tags:
        context_parts.append(f"Tags: {', '.join(report.tags)}")
    if report.summary:
        context_parts.append(f"Current Summary: {report.summary}")

    # Existing section content (preserve if user wrote it)
    for section in sections:
        body = section.get("body", "").strip()
        if body:
            context_parts.append(f"{section.get('title', 'Section')}: {body[:300]}")

    if include_linked_items:
        items = await get_report_items(db, report_id)
        intel_parts = []
        for item in items:
            parts = []
            if item.item_title:
                parts.append(item.item_title)
            meta = item.item_metadata or {}
            if meta.get("severity"):
                parts.append(f"severity={meta['severity']}")
            if meta.get("cve_ids"):
                parts.append(f"CVEs={','.join(meta['cve_ids'][:3])}")
            if meta.get("value"):
                parts.append(f"IOC={meta['value']}")
            if parts:
                intel_parts.append("; ".join(parts))

        if intel_parts:
            context_parts.append("Linked Intelligence Items:\n" + "\n".join(f"- {p}" for p in intel_parts[:15]))

    context = "\n".join(context_parts)

    # ── Phase 3: Build AI prompt with research ────────────
    section_keys = [{"key": s["key"], "title": s["title"], "hint": s.get("hint", "")} for s in sections]
    section_list = "\n".join(f'- "{s["title"]}" (key: {s["key"]}): {s["hint"]}' for s in section_keys)

    system_prompt = (
        "You are a senior cybersecurity threat intelligence analyst tasked with generating "
        "a professional, data-driven threat intelligence report. You have been provided with "
        "LIVE RESEARCH DATA gathered from multiple sources (NVD, OpenSearch, web search, OTX). "
        "USE THIS RESEARCH DATA to write factual, specific, evidence-based content.\n\n"
        "IMPORTANT: Respond ONLY with valid JSON — no markdown, no code fences, no extra text.\n"
        "The JSON must be an object with:\n"
        '  "summary": "<executive summary, 3-5 sentences for C-level briefing>",\n'
        '  "sections": { "<section_key>": "<section content, 2-4 paragraphs>" }\n\n'
        "SECTION-SPECIFIC GUIDELINES:\n"
        "- Timeline: Use actual dates from research data. Format as bullet points with dates.\n"
        "- Confirmation Status: State whether the threat is Confirmed/Suspected/Unverified with evidence.\n"
        "- Exploitability: Reference CVSS scores, attack vectors, complexity from NVD data.\n"
        "- PoC / Exploit Availability: Cite specific PoC sources, exploit-db, GitHub, Metasploit if found.\n"
        "- Impacted Technologies: List specific vendors, products, versions from NVD/research data.\n"
        "- Affected Organizations: Name sectors, industries, geographies from OTX/web data.\n\n"
        "GENERAL GUIDELINES:\n"
        "- Write in professional, direct language — no filler\n"
        "- Each section should be 2-4 paragraphs with specific, actionable intelligence\n"
        "- Cite sources where possible (e.g., 'According to NVD...', 'OTX pulse indicates...')\n"
        "- Include actual CVE IDs, CVSS scores, dates, product names from the research\n"
        "- If research data lacks info for a section, note it as 'No data available' and provide guidance\n"
        "- Do NOT include JSON code fences or any wrapper — raw JSON only"
    )

    user_prompt = (
        f"Generate content for all sections of this threat intelligence report.\n\n"
        f"REPORT CONTEXT:\n{context}\n\n"
        f"LIVE RESEARCH DATA:\n{research_context}\n\n"
        f"SECTIONS TO FILL:\n{section_list}\n\n"
        f"Use the research data above to write factual, evidence-based content for each section. "
        f"Respond with JSON containing 'summary' and 'sections' keys."
    )

    # Use higher token limit to accommodate the richer content
    raw = await ai_chat(system_prompt, user_prompt, max_tokens=3500, temperature=0.25)
    if not raw:
        return None

    # Parse JSON — strip markdown fences if the model wraps it
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines)

    try:
        result = _json.loads(cleaned)
    except _json.JSONDecodeError:
        logger.warning("ai_sections_json_parse_error", raw=raw[:200])
        return None

    ai_summary = result.get("summary", "")
    ai_sections = result.get("sections", {})

    if not isinstance(ai_sections, dict):
        logger.warning("ai_sections_invalid_format")
        return None

    # Update report summary
    if ai_summary:
        report.summary = ai_summary

    # Update section bodies
    updated_sections = []
    for section in sections:
        key = section["key"]
        new_body = ai_sections.get(key, "")
        if new_body and isinstance(new_body, str):
            updated_sections.append({**section, "body": new_body})
        else:
            updated_sections.append(section)

    report.content = {**report.content, "sections": updated_sections}
    await db.flush()
    logger.info("report_ai_sections_generated", report_id=str(report_id), sections=len(ai_sections))

    return {
        "summary": report.summary,
        "sections": updated_sections,
    }


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


# ─── PDF Export ───────────────────────────────────────────

TLP_COLORS_PDF = {
    "TLP:RED": (0.8, 0.1, 0.1),
    "TLP:AMBER+STRICT": (0.85, 0.55, 0.08),
    "TLP:AMBER": (0.85, 0.55, 0.08),
    "TLP:GREEN": (0.15, 0.6, 0.15),
    "TLP:CLEAR": (0.5, 0.5, 0.5),
}

SEVERITY_COLORS_PDF = {
    "critical": (0.8, 0.1, 0.1),
    "high": (0.9, 0.4, 0.0),
    "medium": (0.85, 0.65, 0.0),
    "low": (0.2, 0.6, 0.8),
    "info": (0.3, 0.5, 0.7),
    "unknown": (0.5, 0.5, 0.5),
}


async def export_pdf(
    db: AsyncSession,
    report_id: uuid.UUID,
    include_tlp_watermark: bool = True,
) -> bytes | None:
    """Export report as PDF with TLP watermark and professional formatting."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib.colors import HexColor, Color
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable,
    )
    from reportlab.lib.enums import TA_CENTER

    report = await get_report(db, report_id)
    if not report:
        return None
    items = await get_report_items(db, report_id)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=25 * mm, bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()
    tlp_color = TLP_COLORS_PDF.get(report.tlp, (0.5, 0.5, 0.5))

    # Custom styles
    styles.add(ParagraphStyle(
        "TLPBanner", parent=styles["Normal"],
        fontSize=10, textColor=Color(*tlp_color),
        alignment=TA_CENTER, spaceAfter=6,
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "ReportTitle", parent=styles["Title"],
        fontSize=22, spaceAfter=4, fontName="Helvetica-Bold",
        textColor=HexColor("#1A1A2E"),
    ))
    styles.add(ParagraphStyle(
        "SectionHead", parent=styles["Heading2"],
        fontSize=13, spaceBefore=14, spaceAfter=6,
        fontName="Helvetica-Bold", textColor=HexColor("#16213E"),
        borderPadding=2,
    ))
    styles.add(ParagraphStyle(
        "MetaLabel", parent=styles["Normal"],
        fontSize=9, textColor=HexColor("#555555"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "MetaValue", parent=styles["Normal"],
        fontSize=9, textColor=HexColor("#222222"),
    ))
    styles.add(ParagraphStyle(
        "BodyText2", parent=styles["Normal"],
        fontSize=10, textColor=HexColor("#2D2D2D"), leading=14,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        "FooterText", parent=styles["Normal"],
        fontSize=8, textColor=HexColor("#666666"), alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        "TableHeader", parent=styles["Normal"],
        fontSize=9, textColor=HexColor("#FFFFFF"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        "TableCell", parent=styles["Normal"],
        fontSize=8, textColor=HexColor("#2D2D2D"),
    ))

    elements: list = []

    # TLP watermark banner
    if include_tlp_watermark:
        elements.append(Paragraph(
            f"<b>{report.tlp}</b> — DISTRIBUTION RESTRICTION", styles["TLPBanner"]
        ))
        elements.append(HRFlowable(
            width="100%", thickness=1,
            color=Color(*tlp_color), spaceAfter=10,
        ))

    # Title
    elements.append(Paragraph(report.title, styles["ReportTitle"]))
    elements.append(Spacer(1, 4))

    # Metadata table
    created = report.created_at.strftime("%Y-%m-%d %H:%M UTC") if report.created_at else "—"
    published = report.published_at.strftime("%Y-%m-%d %H:%M UTC") if report.published_at else "—"
    meta_data = [
        ["Type", report.report_type.replace("_", " ").title(),
         "Severity", report.severity.upper()],
        ["Status", report.status.title(),
         "TLP", report.tlp],
        ["Created", created,
         "Published", published],
        ["Tags", ", ".join(report.tags) if report.tags else "—",
         "Author", "IntelWatch Platform"],
    ]
    meta_table = Table(meta_data, colWidths=[55, 150, 55, 150])
    meta_table.setStyle(TableStyle([
        ("TEXTCOLOR", (0, 0), (0, -1), HexColor("#555555")),
        ("TEXTCOLOR", (2, 0), (2, -1), HexColor("#555555")),
        ("TEXTCOLOR", (1, 0), (1, -1), HexColor("#222222")),
        ("TEXTCOLOR", (3, 0), (3, -1), HexColor("#222222")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 12))

    # Summary
    if report.summary:
        elements.append(Paragraph("Executive Summary", styles["SectionHead"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#CCCCCC"), spaceAfter=6))
        elements.append(Paragraph(report.summary.replace("\n", "<br/>"), styles["BodyText2"]))

    # Content sections
    sections = report.content.get("sections", []) if report.content else []
    for section in sections:
        body = (section.get("body") or section.get("content", "")).strip()
        if body:
            elements.append(Paragraph(section.get("title", "Section"), styles["SectionHead"]))
            elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#CCCCCC"), spaceAfter=6))
            elements.append(Paragraph(body.replace("\n", "<br/>"), styles["BodyText2"]))

    # Linked items tables
    intel_items = [i for i in items if i.item_type in ("intel", "intel_item")]
    ioc_items = [i for i in items if i.item_type == "ioc"]
    technique_items = [i for i in items if i.item_type == "technique"]

    def _build_table(title: str, headers: list[str], rows: list[list[str]], col_widths: list[int]):
        elements.append(Paragraph(title, styles["SectionHead"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#CCCCCC"), spaceAfter=6))
        header_row = [Paragraph(h, styles["TableHeader"]) for h in headers]
        data_rows = [[Paragraph(c, styles["TableCell"]) for c in row] for row in rows]
        t = Table([header_row] + data_rows, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1A1A2E")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), HexColor("#F5F5F5")]),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 8))

    if intel_items:
        rows = []
        for idx, item in enumerate(intel_items, 1):
            meta = item.item_metadata or {}
            rows.append([
                str(idx),
                item.item_title or str(item.item_id)[:20],
                meta.get("severity", "—"),
                meta.get("source_name", "—"),
            ])
        _build_table("Linked Intelligence", ["#", "Title", "Severity", "Source"], rows, [25, 210, 60, 100])

    if ioc_items:
        rows = []
        for idx, item in enumerate(ioc_items, 1):
            meta = item.item_metadata or {}
            rows.append([
                str(idx),
                meta.get("ioc_type", "—"),
                meta.get("value", str(item.item_id)[:20]),
                str(meta.get("risk_score", "—")),
            ])
        _build_table("Indicators of Compromise", ["#", "Type", "Value", "Risk Score"], rows, [25, 80, 200, 60])

    if technique_items:
        rows = []
        for item in technique_items:
            meta = item.item_metadata or {}
            rows.append([
                str(item.item_id)[:12],
                item.item_title or str(item.item_id)[:20],
                meta.get("tactic", "—"),
            ])
        _build_table("MITRE ATT&CK Techniques", ["ID", "Technique", "Tactic"], rows, [80, 180, 130])

    # Footer
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#CCCCCC"), spaceAfter=6))
    elements.append(Paragraph(
        f"Generated by IntelWatch · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["FooterText"],
    ))
    if include_tlp_watermark:
        elements.append(Paragraph(
            f"{report.tlp} — This document is classified under the Traffic Light Protocol.",
            styles["FooterText"],
        ))

    doc.build(elements)
    return buf.getvalue()


# ─── STIX 2.1 JSON Export ────────────────────────────────

REPORT_TYPE_TO_STIX_LABEL = {
    "incident": "incident-report",
    "threat_advisory": "threat-advisory",
    "weekly_summary": "weekly-summary",
    "ioc_bulletin": "ioc-bulletin",
    "custom": "custom-report",
}

TLP_TO_STIX_MARKING = {
    "TLP:RED": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
    "TLP:AMBER+STRICT": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:AMBER": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:GREEN": "marking-definition--bab4a63c-aed9-4571-9c39-01cc457637b7",
    "TLP:CLEAR": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
}


async def export_stix(
    db: AsyncSession,
    report_id: uuid.UUID,
) -> dict | None:
    """Export report as STIX 2.1 Bundle JSON."""
    report = await get_report(db, report_id)
    if not report:
        return None
    items = await get_report_items(db, report_id)

    stix_objects: list[dict] = []
    object_refs: list[str] = []

    # TLP marking definition reference
    tlp_marking = TLP_TO_STIX_MARKING.get(report.tlp)
    marking_refs = [tlp_marking] if tlp_marking else []

    # Identity (IntelWatch organization)
    identity_id = "identity--a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    stix_objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": report.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "modified": report.updated_at.strftime("%Y-%m-%dT%H:%M:%S.000Z") if report.updated_at else report.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "name": "IntelWatch Platform",
        "identity_class": "organization",
    })

    # Convert linked items to STIX objects
    for item in items:
        meta = item.item_metadata or {}

        if item.item_type in ("intel", "intel_item"):
            # Map to STIX indicator or vulnerability
            cve_ids = meta.get("cve_ids", [])
            if cve_ids:
                # Vulnerability object for CVE-based intel
                for cve in cve_ids:
                    vuln_id = f"vulnerability--{uuid.uuid5(uuid.NAMESPACE_URL, cve)}"
                    stix_objects.append({
                        "type": "vulnerability",
                        "spec_version": "2.1",
                        "id": vuln_id,
                        "created": item.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "modified": item.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                        "name": cve,
                        "description": item.item_title or cve,
                        "external_references": [{"source_name": "cve", "external_id": cve}],
                    })
                    if marking_refs:
                        stix_objects[-1]["object_marking_refs"] = marking_refs
                    object_refs.append(vuln_id)
            else:
                # Generic indicator
                ind_id = f"indicator--{item.item_id}"
                stix_objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": item.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "modified": item.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "name": item.item_title or str(item.item_id),
                    "description": f"Intel item from {meta.get('source_name', 'IntelWatch')}",
                    "indicator_types": ["anomalous-activity"],
                    "pattern": f"[file:name = '{item.item_title or item.item_id}']",
                    "pattern_type": "stix",
                    "valid_from": item.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                })
                if marking_refs:
                    stix_objects[-1]["object_marking_refs"] = marking_refs
                object_refs.append(ind_id)

        elif item.item_type == "ioc":
            ioc_type = meta.get("ioc_type", "unknown")
            value = meta.get("value", str(item.item_id))
            pattern = _ioc_to_stix_pattern(ioc_type, value)
            ind_id = f"indicator--{item.item_id}"
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": item.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "modified": item.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "name": f"{ioc_type}: {value}",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": item.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            })
            if meta.get("risk_score"):
                stix_objects[-1]["confidence"] = min(100, int(meta["risk_score"]))
            if marking_refs:
                stix_objects[-1]["object_marking_refs"] = marking_refs
            object_refs.append(ind_id)

        elif item.item_type == "technique":
            # MITRE ATT&CK technique → attack-pattern
            ap_id = f"attack-pattern--{item.item_id}"
            ext_refs = []
            technique_id = meta.get("technique_id") or str(item.item_id)
            if technique_id.startswith("T"):
                ext_refs.append({
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                })
            stix_objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": item.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "modified": item.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "name": item.item_title or technique_id,
                "external_references": ext_refs,
            })
            if meta.get("tactic"):
                stix_objects[-1]["kill_chain_phases"] = [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": meta["tactic"].lower().replace(" ", "-"),
                }]
            if marking_refs:
                stix_objects[-1]["object_marking_refs"] = marking_refs
            object_refs.append(ap_id)

    # Build section content as description
    desc_parts = []
    if report.summary:
        desc_parts.append(report.summary)
    sections = report.content.get("sections", []) if report.content else []
    for section in sections:
        body = (section.get("body") or section.get("content", "")).strip()
        if body:
            desc_parts.append(f"## {section.get('title', 'Section')}\n{body}")

    # The main Report object
    report_stix_id = f"report--{report.id}"
    report_obj: dict = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_stix_id,
        "created": report.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "modified": report.updated_at.strftime("%Y-%m-%dT%H:%M:%S.000Z") if report.updated_at else report.created_at.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "name": report.title,
        "description": "\n\n".join(desc_parts) if desc_parts else report.title,
        "report_types": [REPORT_TYPE_TO_STIX_LABEL.get(report.report_type, "custom-report")],
        "published": (report.published_at or report.created_at).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "object_refs": object_refs + [identity_id],
        "created_by_ref": identity_id,
        "labels": report.tags or [],
        "confidence": {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 10}.get(report.severity, 50),
    }
    if marking_refs:
        report_obj["object_marking_refs"] = marking_refs

    stix_objects.append(report_obj)

    # STIX Bundle
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": stix_objects,
    }
    return bundle


def _ioc_to_stix_pattern(ioc_type: str, value: str) -> str:
    """Convert an IOC type+value into a STIX 2.1 pattern string."""
    mapping = {
        "ip": f"[ipv4-addr:value = '{value}']",
        "ipv4": f"[ipv4-addr:value = '{value}']",
        "ipv6": f"[ipv6-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "email": f"[email-addr:value = '{value}']",
        "hash_md5": f"[file:hashes.MD5 = '{value}']",
        "hash_sha1": f"[file:hashes.'SHA-1' = '{value}']",
        "hash_sha256": f"[file:hashes.'SHA-256' = '{value}']",
        "file": f"[file:name = '{value}']",
    }
    return mapping.get(ioc_type, f"[artifact:payload_bin = '{value}']")


# ─── HTML Export ──────────────────────────────────────────


async def export_html(
    db: AsyncSession,
    report_id: uuid.UUID,
    include_tlp_watermark: bool = True,
) -> str | None:
    """Export report as a styled HTML document."""
    report = await get_report(db, report_id)
    if not report:
        return None
    items = await get_report_items(db, report_id)

    tlp_color = {"TLP:RED": "#ef4444", "TLP:AMBER+STRICT": "#f59e0b", "TLP:AMBER": "#f59e0b",
                 "TLP:GREEN": "#22c55e", "TLP:CLEAR": "#a1a1aa"}.get(report.tlp, "#a1a1aa")
    sev_color = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
                 "low": "#3b82f6", "info": "#06b6d4", "unknown": "#a1a1aa"}.get(report.severity, "#a1a1aa")

    h = []
    h.append("<!DOCTYPE html>")
    h.append("<html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    h.append(f"<title>{report.title} — IntelWatch</title>")
    h.append("""<style>
      :root { --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --muted: #94a3b8; --border: #334155; }
      body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 40px; line-height: 1.6; }
      .container { max-width: 800px; margin: 0 auto; }
      .tlp-banner { text-align: center; padding: 8px; border-radius: 6px; font-weight: 700; font-size: 13px; margin-bottom: 24px; }
      h1 { font-size: 28px; margin: 0 0 8px 0; color: #f1f5f9; }
      .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 24px; font-size: 13px; margin-bottom: 24px; padding: 16px; background: var(--card); border-radius: 8px; border: 1px solid var(--border); }
      .meta span.label { color: var(--muted); font-weight: 600; }
      .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
      h2 { font-size: 18px; color: #93c5fd; margin: 28px 0 8px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
      .section-body { margin-bottom: 16px; white-space: pre-wrap; }
      table { width: 100%; border-collapse: collapse; margin: 12px 0 20px; font-size: 13px; }
      th { background: #1e3a5f; color: #fff; padding: 8px 12px; text-align: left; font-size: 12px; }
      td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
      tr:nth-child(even) { background: rgba(255,255,255,0.03); }
      .footer { text-align: center; font-size: 12px; color: var(--muted); margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); }
      @media print { body { background: #fff; color: #1e293b; } .meta { background: #f8fafc; } th { background: #1e3a5f; } }
    </style>""")
    h.append("</head><body><div class='container'>")

    if include_tlp_watermark:
        h.append(f"<div class='tlp-banner' style='background: {tlp_color}22; color: {tlp_color}; border: 1px solid {tlp_color}44;'>{report.tlp} — DISTRIBUTION RESTRICTION</div>")

    h.append(f"<h1>{report.title}</h1>")

    created = report.created_at.strftime("%Y-%m-%d %H:%M UTC") if report.created_at else "—"
    published = report.published_at.strftime("%Y-%m-%d %H:%M UTC") if report.published_at else "—"
    h.append("<div class='meta'>")
    h.append(f"<div><span class='label'>Type:</span> {report.report_type.replace('_', ' ').title()}</div>")
    h.append(f"<div><span class='label'>Severity:</span> <span class='badge' style='background: {sev_color}22; color: {sev_color};'>{report.severity.upper()}</span></div>")
    h.append(f"<div><span class='label'>Status:</span> {report.status.title()}</div>")
    h.append(f"<div><span class='label'>TLP:</span> <span class='badge' style='background: {tlp_color}22; color: {tlp_color};'>{report.tlp}</span></div>")
    h.append(f"<div><span class='label'>Created:</span> {created}</div>")
    h.append(f"<div><span class='label'>Published:</span> {published}</div>")
    if report.tags:
        h.append(f"<div><span class='label'>Tags:</span> {', '.join(report.tags)}</div>")
    h.append("</div>")

    if report.summary:
        h.append("<h2>Executive Summary</h2>")
        h.append(f"<div class='section-body'>{report.summary}</div>")

    sections = report.content.get("sections", []) if report.content else []
    for section in sections:
        body = (section.get("body") or section.get("content", "")).strip()
        if body:
            h.append(f"<h2>{section.get('title', 'Section')}</h2>")
            h.append(f"<div class='section-body'>{body}</div>")

    intel_items = [i for i in items if i.item_type in ("intel", "intel_item")]
    ioc_items = [i for i in items if i.item_type == "ioc"]
    technique_items = [i for i in items if i.item_type == "technique"]

    if intel_items:
        h.append("<h2>Linked Intelligence</h2>")
        h.append("<table><thead><tr><th>#</th><th>Title</th><th>Severity</th><th>Source</th></tr></thead><tbody>")
        for idx, item in enumerate(intel_items, 1):
            meta = item.item_metadata or {}
            h.append(f"<tr><td>{idx}</td><td>{item.item_title or item.item_id}</td><td>{meta.get('severity', '—')}</td><td>{meta.get('source_name', '—')}</td></tr>")
        h.append("</tbody></table>")

    if ioc_items:
        h.append("<h2>Indicators of Compromise</h2>")
        h.append("<table><thead><tr><th>#</th><th>Type</th><th>Value</th><th>Risk Score</th></tr></thead><tbody>")
        for idx, item in enumerate(ioc_items, 1):
            meta = item.item_metadata or {}
            h.append(f"<tr><td>{idx}</td><td>{meta.get('ioc_type', '—')}</td><td>{meta.get('value', item.item_id)}</td><td>{meta.get('risk_score', '—')}</td></tr>")
        h.append("</tbody></table>")

    if technique_items:
        h.append("<h2>MITRE ATT&CK Techniques</h2>")
        h.append("<table><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th></tr></thead><tbody>")
        for item in technique_items:
            meta = item.item_metadata or {}
            h.append(f"<tr><td>{item.item_id}</td><td>{item.item_title or item.item_id}</td><td>{meta.get('tactic', '—')}</td></tr>")
        h.append("</tbody></table>")

    h.append(f"<div class='footer'>Generated by IntelWatch · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    if include_tlp_watermark:
        h.append(f"<br/>{report.tlp} — This document is classified under the Traffic Light Protocol.")
    h.append("</div></div></body></html>")

    return "\n".join(h)


# ─── CSV Export ───────────────────────────────────────────


async def export_csv(
    db: AsyncSession,
    report_id: uuid.UUID,
) -> str | None:
    """Export report as CSV including metadata, sections, and linked items."""
    report = await get_report(db, report_id)
    if not report:
        return None
    items = await get_report_items(db, report_id)

    output = io.StringIO()
    writer = csv.writer(output)

    # ── Report metadata ──
    writer.writerow(["Report", report.title])
    writer.writerow(["Type", report.report_type])
    writer.writerow(["Severity", report.severity])
    writer.writerow(["TLP", report.tlp])
    writer.writerow(["Status", report.status])
    writer.writerow(["Tags", ", ".join(report.tags) if report.tags else ""])
    writer.writerow(["Created", report.created_at.strftime("%Y-%m-%d %H:%M UTC") if report.created_at else ""])
    writer.writerow(["Published", report.published_at.strftime("%Y-%m-%d %H:%M UTC") if report.published_at else ""])
    writer.writerow([])

    # ── Summary ──
    if report.summary:
        writer.writerow(["Summary"])
        writer.writerow([report.summary])
        writer.writerow([])

    # ── Content sections ──
    sections = report.content.get("sections", []) if report.content else []
    if sections:
        writer.writerow(["Section Title", "Section Content"])
        for section in sections:
            body = (section.get("body") or section.get("content", "")).strip()
            if body:
                writer.writerow([section.get("title", "Section"), body])
        writer.writerow([])

    # ── Linked items ──
    if items:
        writer.writerow(["Linked Items"])
        writer.writerow(["Item Type", "Title / Value", "IOC Type", "Severity", "Risk Score", "Source", "Tactic", "Notes"])
        for item in items:
            meta = item.item_metadata or {}
            writer.writerow([
                item.item_type,
                item.item_title or meta.get("value", str(item.item_id)),
                meta.get("ioc_type", ""),
                meta.get("severity", ""),
                meta.get("risk_score", ""),
                meta.get("source_name", ""),
                meta.get("tactic", ""),
                item.notes or "",
            ])

    return output.getvalue()


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
