"""NVD / EPSS / CISA-KEV enrichment for Vulnerable Products.

Enriches intel_vulnerable_products rows that have a CVE but lack authoritative
CVSS, EPSS, or KEV data.  Designed to be called from the RQ worker on a
schedule (every 30 min).

Rate limits
-----------
- NVD public API: ~5 requests / 30s (no key), 50 req/30s with API key.
- EPSS API (api.first.org): no documented limit — we batch 100 CVEs per call.
- CISA KEV JSON: single file download, cached for 6 hours.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select, update, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.models import VulnerableProduct

logger = get_logger("nvd_enrichment")
settings = get_settings()

# ── Constants ────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Pause between NVD API calls to stay within rate limits
NVD_DELAY_SECONDS = 6.5  # ~9 req/min (safe for no-key usage)

# How many CVEs to enrich per run (avoid long-running jobs)
# With API key: higher throughput due to faster rate limits
MAX_CVE_PER_RUN = 100 if (get_settings().nvd_api_key) else 30

# Only re-check CVEs that haven't been enriched in the last N days
RECHECK_INTERVAL_DAYS = 7


# ──────────────────────────────────────────────────────────
# Main sync entry point (called by RQ worker)
# ──────────────────────────────────────────────────────────

def enrich_products_from_nvd_sync(session: Session) -> dict:
    """Enrich vulnerable products with NVD CVSS, EPSS scores, and KEV status.

    Returns dict with counts of enriched products.
    """
    # 1. Find products with a CVE that need enrichment
    cutoff = datetime.now(timezone.utc) - timedelta(days=RECHECK_INTERVAL_DAYS)

    rows = session.execute(
        select(VulnerableProduct.id, VulnerableProduct.cve_id)
        .where(
            VulnerableProduct.cve_id.isnot(None),
            VulnerableProduct.cve_id != "",
            # Only products not yet enriched or stale (enriched > 7 days ago)
            (VulnerableProduct.cvss_score.is_(None)) | (VulnerableProduct.updated_at < cutoff),
        )
        .order_by(VulnerableProduct.last_seen.desc())
        .limit(MAX_CVE_PER_RUN)
    ).all()

    if not rows:
        logger.info("nvd_enrich_skip", reason="no products need enrichment")
        return {"enriched": 0, "total_candidates": 0}

    # Collect unique CVEs to look up
    product_cve_map: dict[str, list] = {}  # cve -> [product_ids]
    for pid, cve in rows:
        product_cve_map.setdefault(cve, []).append(pid)

    unique_cves = list(product_cve_map.keys())
    logger.info("nvd_enrich_start", products=len(rows), unique_cves=len(unique_cves))

    # 2. Batch fetch EPSS scores (up to 100 CVEs in one call)
    epss_map = _fetch_epss_batch(unique_cves)

    # 3. Download CISA KEV catalog
    kev_set = _fetch_kev_catalog()

    # 4. Fetch NVD CVSS data per CVE (with rate limiting)
    nvd_map = _fetch_nvd_batch(unique_cves)

    # 5. Update products
    enriched = 0
    now = datetime.now(timezone.utc)

    for cve, product_ids in product_cve_map.items():
        nvd = nvd_map.get(cve, {})
        epss = epss_map.get(cve)
        is_kev = cve in kev_set

        cvss_score = nvd.get("cvss_score")
        nvd_severity = nvd.get("severity")
        affected_versions = nvd.get("affected_versions")
        patch_available = nvd.get("patch_available", False)
        exploit_available = nvd.get("exploit_available", False)

        update_values = {"updated_at": now}

        if cvss_score is not None:
            update_values["cvss_score"] = cvss_score
            # Always derive severity from real CVSS (overrides AI guess)
            if cvss_score >= 9.0:
                update_values["severity"] = "critical"
            elif cvss_score >= 7.0:
                update_values["severity"] = "high"
            elif cvss_score >= 4.0:
                update_values["severity"] = "medium"
            else:
                update_values["severity"] = "low"
        elif nvd_severity:
            update_values["severity"] = nvd_severity
        if epss is not None:
            update_values["epss_score"] = round(epss * 100, 2)  # store as 0-100
        if is_kev:
            update_values["is_kev"] = True
        if affected_versions:
            update_values["affected_versions"] = affected_versions[:2000]
        if patch_available:
            update_values["patch_available"] = True
        if exploit_available:
            update_values["exploit_available"] = True

        if len(update_values) > 1:  # more than just updated_at
            try:
                session.execute(
                    update(VulnerableProduct)
                    .where(VulnerableProduct.id.in_(product_ids))
                    .values(**update_values)
                )
                enriched += len(product_ids)
            except Exception as e:
                logger.warning("nvd_update_error", cve=cve, error=str(e))

    try:
        session.commit()
    except Exception as e:
        logger.error("nvd_commit_error", error=str(e))
        session.rollback()
        return {"error": str(e)}

    # 6. Recalculate confidence for all enriched products
    _recalculate_confidence(session)

    logger.info("nvd_enrich_done", enriched=enriched, cves_looked_up=len(unique_cves))
    return {
        "enriched": enriched,
        "unique_cves": len(unique_cves),
        "nvd_hits": len(nvd_map),
        "epss_hits": len(epss_map),
        "kev_count": len(kev_set),
    }


# ──────────────────────────────────────────────────────────
# Confidence Score Recalculation
# ──────────────────────────────────────────────────────────

def _recalculate_confidence(session: Session) -> None:
    """Recalculate composite confidence for enriched products.

    Score is based on: source_count, NVD confirmation (cvss_score present),
    CISA KEV listing, EPSS score, and number of linked campaigns.
    Maps to: high (>=6 points), medium (>=3), low (<3).
    """
    try:
        session.execute(text("""
            UPDATE intel_vulnerable_products SET confidence = CASE
                WHEN (
                    (CASE WHEN source_count >= 3 THEN 2 WHEN source_count >= 2 THEN 1 ELSE 0 END) +
                    (CASE WHEN cvss_score IS NOT NULL THEN 2 ELSE 0 END) +
                    (CASE WHEN is_kev THEN 2 ELSE 0 END) +
                    (CASE WHEN epss_score >= 50 THEN 2 WHEN epss_score >= 10 THEN 1 ELSE 0 END) +
                    (CASE WHEN exploit_available THEN 1 ELSE 0 END)
                ) >= 6 THEN 'high'
                WHEN (
                    (CASE WHEN source_count >= 3 THEN 2 WHEN source_count >= 2 THEN 1 ELSE 0 END) +
                    (CASE WHEN cvss_score IS NOT NULL THEN 2 ELSE 0 END) +
                    (CASE WHEN is_kev THEN 2 ELSE 0 END) +
                    (CASE WHEN epss_score >= 50 THEN 2 WHEN epss_score >= 10 THEN 1 ELSE 0 END) +
                    (CASE WHEN exploit_available THEN 1 ELSE 0 END)
                ) >= 3 THEN 'medium'
                ELSE 'low'
            END
            WHERE cvss_score IS NOT NULL
              AND updated_at >= NOW() - INTERVAL '1 day'
        """))
        session.commit()
    except Exception as e:
        logger.warning("confidence_recalc_error", error=str(e))
        session.rollback()


# ──────────────────────────────────────────────────────────
# NVD API
# ──────────────────────────────────────────────────────────

def _fetch_nvd_batch(cves: list[str]) -> dict[str, dict]:
    """Fetch CVSS data from NVD for a list of CVEs (one call per CVE)."""
    result: dict[str, dict] = {}
    nvd_api_key = getattr(settings, "nvd_api_key", None) or ""

    headers = {}
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    for cve in cves:
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.get(
                    NVD_API_BASE,
                    params={"cveId": cve},
                    headers=headers,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    parsed = _parse_nvd_response(data, cve)
                    if parsed:
                        result[cve] = parsed
                elif resp.status_code == 403:
                    logger.warning("nvd_rate_limited", cve=cve)
                    time.sleep(30)  # back off on 403
                else:
                    logger.debug("nvd_no_data", cve=cve, status=resp.status_code)
        except Exception as e:
            logger.debug("nvd_fetch_error", cve=cve, error=str(e))

        # Rate limit — wait between calls
        delay = 2 if nvd_api_key else NVD_DELAY_SECONDS
        time.sleep(delay)

    return result


def _parse_nvd_response(data: dict, cve_id: str) -> dict | None:
    """Extract CVSS score, severity, and metadata from NVD API response."""
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve_data = vulns[0].get("cve", {})

    # Extract CVSS score — prefer v3.1, then v3.0, then v2
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    severity = None

    for version_key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(version_key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "").lower()
            break

    if cvss_score is None:
        entries = metrics.get("cvssMetricV2", [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            # Map V2 score to severity
            if cvss_score:
                if cvss_score >= 9.0:
                    severity = "critical"
                elif cvss_score >= 7.0:
                    severity = "high"
                elif cvss_score >= 4.0:
                    severity = "medium"
                else:
                    severity = "low"

    # Extract affected versions from configurations/CPE
    affected_versions = _extract_affected_versions(cve_data)

    # Check references for patch/exploit indicators
    patch_available = False
    exploit_available = False
    for ref in cve_data.get("references", []):
        tags = ref.get("tags", [])
        if "Patch" in tags or "Vendor Advisory" in tags:
            patch_available = True
        if "Exploit" in tags:
            exploit_available = True

    return {
        "cvss_score": cvss_score,
        "severity": severity if severity in ("critical", "high", "medium", "low") else None,
        "affected_versions": affected_versions,
        "patch_available": patch_available,
        "exploit_available": exploit_available,
    }


def _extract_affected_versions(cve_data: dict) -> str | None:
    """Extract affected version ranges from NVD CPE configurations."""
    configs = cve_data.get("configurations", [])
    versions = []
    for config in configs[:3]:  # limit to avoid huge strings
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 6:
                    product = parts[4]
                    version = parts[5] if parts[5] != "*" else ""
                    version_end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                    if version_end:
                        versions.append(f"{product} <= {version_end}")
                    elif version:
                        versions.append(f"{product} {version}")

    return "; ".join(versions[:10]) if versions else None


# ──────────────────────────────────────────────────────────
# EPSS API (batch)
# ──────────────────────────────────────────────────────────

def _fetch_epss_batch(cves: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for up to 100 CVEs in one API call."""
    if not cves:
        return {}

    result: dict[str, float] = {}

    # EPSS API accepts comma-separated CVEs (batch up to 100)
    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.get(
                    EPSS_API_BASE,
                    params={"cve": ",".join(batch)},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get("data", []):
                        cve_id = entry.get("cve", "")
                        try:
                            score = float(entry.get("epss", 0))
                            result[cve_id] = score
                        except (ValueError, TypeError):
                            pass
        except Exception as e:
            logger.debug("epss_fetch_error", error=str(e))

    return result


# ──────────────────────────────────────────────────────────
# CISA KEV Catalog
# ──────────────────────────────────────────────────────────

# Module-level cache for KEV catalog (avoid re-downloading within same worker job)
_kev_cache: tuple[set[str], float] | None = None
_KEV_CACHE_TTL = 3600 * 6  # 6 hours


def _fetch_kev_catalog() -> set[str]:
    """Download CISA KEV catalog and return set of CVE IDs."""
    global _kev_cache

    now = time.time()
    if _kev_cache and (now - _kev_cache[1]) < _KEV_CACHE_TTL:
        return _kev_cache[0]

    kev_set: set[str] = set()
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(KEV_JSON_URL)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cveID", "")
                    if cve.startswith("CVE-"):
                        kev_set.add(cve)
                logger.info("kev_catalog_loaded", count=len(kev_set))
    except Exception as e:
        logger.warning("kev_fetch_error", error=str(e))
        # Return cached if available, even if stale
        if _kev_cache:
            return _kev_cache[0]

    _kev_cache = (kev_set, now)
    return kev_set
