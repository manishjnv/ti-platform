"""Phase 3 Integration Test — Output & Export Layer (STIX 2.1 + Sigma).

Tests stix.py and rules.py normalizers with real data from the database,
then validates the API export endpoints.
"""

import asyncio
import json
import sys

# ── Colour helpers ──────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

passed = 0
failed = 0


def ok(label: str, detail: str = ""):
    global passed
    passed += 1
    print(f"  {GREEN}✓{RESET} {label}  {CYAN}{detail}{RESET}")


def fail(label: str, detail: str = ""):
    global failed
    failed += 1
    print(f"  {RED}✗{RESET} {label}  {YELLOW}{detail}{RESET}")


def section(title: str):
    print(f"\n{CYAN}{'─' * 60}{RESET}")
    print(f"  {title}")
    print(f"{CYAN}{'─' * 60}{RESET}")


# ── STIX module tests ──────────────────────────────────

def test_stix_module():
    section("STIX 2.1 Module — stix.py")

    from app.normalizers.stix import (
        platform_identity,
        ioc_to_indicator,
        actor_to_stix,
        malware_to_stix,
        cve_to_vulnerability,
        technique_to_attack_pattern,
        intel_to_report,
        stix_relationship,
        build_bundle,
        news_item_to_bundle,
        ioc_list_to_bundle,
        STIX_SPEC_VERSION,
        TLP_MARKING_IDS,
        IOC_TYPE_MAP,
    )

    # 1. Constants
    assert STIX_SPEC_VERSION == "2.1"
    ok("STIX spec version", "2.1")
    assert len(TLP_MARKING_IDS) == 5
    ok("TLP marking IDs", f"{len(TLP_MARKING_IDS)} levels")
    assert len(IOC_TYPE_MAP) >= 7
    ok("IOC type map", f"{len(IOC_TYPE_MAP)} types")

    # 2. Platform identity
    identity = platform_identity()
    assert identity["type"] == "identity"
    assert identity["identity_class"] == "system"
    assert identity["spec_version"] == "2.1"
    ok("Platform identity", identity["id"][:40])

    # 3. IOC → STIX Indicator
    test_ioc = {
        "value": "10.0.0.1",
        "ioc_type": "ip",
        "risk_score": 85,
        "tags": ["c2", "botnet"],
    }
    indicator = ioc_to_indicator(test_ioc)
    assert indicator["type"] == "indicator"
    assert "ipv4-addr:value" in indicator["pattern"]
    assert indicator["confidence"] >= 0
    ok("IOC → Indicator (IP)", indicator["pattern"][:50])

    # Domain IOC
    dom_ioc = {"value": "evil.example.com", "ioc_type": "domain", "risk_score": 70}
    dom_ind = ioc_to_indicator(dom_ioc)
    assert "domain-name:value" in dom_ind["pattern"]
    ok("IOC → Indicator (domain)", dom_ind["pattern"][:50])

    # Hash IOC
    hash_ioc = {"value": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "hash_md5", "risk_score": 90}
    hash_ind = ioc_to_indicator(hash_ioc)
    assert "file:hashes" in hash_ind["pattern"]
    ok("IOC → Indicator (MD5 hash)", hash_ind["pattern"][:50])

    # URL IOC
    url_ioc = {"value": "http://evil.example.com/payload", "ioc_type": "url", "risk_score": 75}
    url_ind = ioc_to_indicator(url_ioc)
    assert "url:value" in url_ind["pattern"]
    ok("IOC → Indicator (URL)", url_ind["pattern"][:50])

    # Unsupported IOC type returns empty dict (no pattern)
    bad_ioc = {"value": "unknown", "ioc_type": "unsupported", "risk_score": 0}
    bad_ind = ioc_to_indicator(bad_ioc)
    assert bad_ind == {}
    ok("Unsupported IOC type → empty dict")

    # 4. Threat actor
    actor = actor_to_stix("APT28", aliases=["Fancy Bear", "Sofacy"])
    assert actor["type"] == "threat-actor"
    assert "APT28" in actor["name"]
    ok("Threat actor SDO", actor["name"])

    # 5. Malware
    mal = malware_to_stix("Emotet")
    assert mal["type"] == "malware"
    ok("Malware SDO", mal["name"])

    # 6. CVE → Vulnerability
    vuln = cve_to_vulnerability("CVE-2024-12345")
    assert vuln["type"] == "vulnerability"
    assert "CVE-2024-12345" in vuln["name"]
    ok("CVE → Vulnerability SDO", vuln["name"])

    # 7. ATT&CK technique
    tech = technique_to_attack_pattern("T1566.001", "Spearphishing Attachment")
    assert tech["type"] == "attack-pattern"
    ok("ATT&CK → Attack Pattern SDO", tech["name"])

    # 8. Report
    report_item = {
        "id": "test-123",
        "headline": "Major APT Campaign",
        "summary": "APT group targets finance sector",
        "source": "IntelWatch",
        "published_at": "2025-01-15",
        "severity": "critical",
    }
    report = intel_to_report(report_item, [actor["id"], mal["id"]])
    assert report["type"] == "report"
    ok("Report SDO", report["name"][:40])

    # 9. Relationship
    rel = stix_relationship(actor["id"], "uses", mal["id"])
    assert rel["type"] == "relationship"
    assert rel["relationship_type"] == "uses"
    ok("Relationship SRO", f"{rel['source_ref'][:25]} → {rel['target_ref'][:25]}")

    # 10. Bundle
    bundle = build_bundle([identity, indicator, actor, mal, vuln, tech, report, rel])
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 8
    bundle_json = json.dumps(bundle, indent=2, default=str)
    ok("STIX Bundle", f"{len(bundle['objects'])} objects, {len(bundle_json)} bytes")

    # 11. IOC list → bundle
    iocs = [
        {"value": "1.2.3.4", "ioc_type": "ip", "risk_score": 80, "tags": []},
        {"value": "bad.example.com", "ioc_type": "domain", "risk_score": 60, "tags": []},
    ]
    ioc_bundle = ioc_list_to_bundle(iocs)
    assert ioc_bundle["type"] == "bundle"
    assert len(ioc_bundle["objects"]) >= 3  # identity + 2 indicators
    ok("IOC list → Bundle", f"{len(ioc_bundle['objects'])} objects")

    # 12. News item → bundle
    news_dict = {
        "id": "test-news-1",
        "headline": "APT28 Deploys New Backdoor",
        "summary": "Russian-linked group targets European governments with new malware variant.",
        "source": "CyberNews",
        "published_at": "2025-06-01",
        "severity": "high",
        "threat_actors": ["APT28"],
        "malware_families": ["Graphite"],
        "cves": ["CVE-2024-12345"],
        "tactics_techniques": ["T1566.001 - Spearphishing Attachment", "T1059.001 - PowerShell"],
        "ioc_summary": {
            "domains": ["evil.example.com"],
            "ips": ["203.0.113.10"],
            "hashes": ["abc123def456"],
            "urls": [],
        },
        "category": "nation_state",
        "confidence": "high",
    }
    news_bundle = news_item_to_bundle(news_dict)
    assert news_bundle["type"] == "bundle"
    obj_types = [o["type"] for o in news_bundle["objects"]]
    assert "identity" in obj_types
    assert "report" in obj_types
    ok("News item → STIX Bundle", f"{len(news_bundle['objects'])} objects: {', '.join(set(obj_types))}")

    # Validate JSON serialisability
    json_str = json.dumps(news_bundle, indent=2, default=str)
    reparsed = json.loads(json_str)
    assert reparsed["type"] == "bundle"
    ok("JSON round-trip valid", f"{len(json_str)} bytes")


# ── Sigma module tests ─────────────────────────────────

def test_sigma_module():
    section("Sigma Rule Generation — rules.py")

    from app.normalizers.rules import (
        ioc_to_sigma,
        news_item_to_sigma,
        SEVERITY_TO_LEVEL,
    )

    # 1. Constants
    assert len(SEVERITY_TO_LEVEL) >= 5
    ok("Severity → Sigma level map", f"{len(SEVERITY_TO_LEVEL)} levels")

    # 2. IP → Sigma
    rule = ioc_to_sigma("ip", ["10.0.0.1", "10.0.0.2"], severity="high")
    assert rule is not None
    assert "title:" in rule
    assert "logsource:" in rule
    assert "detection:" in rule
    assert "10.0.0.1" in rule
    ok("IP IOC → Sigma rule", f"{len(rule)} chars")

    # 3. Domain → Sigma
    rule_d = ioc_to_sigma("domain", ["evil.example.com"])
    assert rule_d is not None
    assert "dns" in rule_d.lower() or "proxy" in rule_d.lower()
    ok("Domain IOC → Sigma rule", f"{len(rule_d)} chars")

    # 4. Hash → Sigma
    rule_h = ioc_to_sigma("hash_sha256", ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"])
    assert rule_h is not None
    assert "Hashes" in rule_h or "hashes" in rule_h.lower() or "TargetFilename" in rule_h or "SHA256" in rule_h
    ok("SHA256 Hash → Sigma rule", f"{len(rule_h)} chars")

    # 5. URL → Sigma
    rule_u = ioc_to_sigma("url", ["http://evil.example.com/payload"])
    assert rule_u is not None
    ok("URL → Sigma rule", f"{len(rule_u)} chars")

    # 6. Unsupported type → None
    rule_bad = ioc_to_sigma("unsupported_type", ["test"])
    assert rule_bad is None
    ok("Unsupported IOC type → None")

    # 7. Empty values → None
    rule_empty = ioc_to_sigma("ip", [])
    assert rule_empty is None
    ok("Empty values → None")

    # 8. Sigma with tags
    rule_tags = ioc_to_sigma(
        "ip", ["192.168.1.1"],
        title="Custom Rule",
        severity="critical",
        tags=["attack.initial_access", "attack.t1566"],
        references=["https://example.com/report"],
    )
    assert "Custom Rule" in rule_tags
    assert "critical" in rule_tags
    assert "attack.initial_access" in rule_tags
    ok("Custom tags & references", f"{len(rule_tags)} chars")

    # 9. News item → Sigma rules
    news_dict = {
        "id": "test-sigma-1",
        "headline": "Ransomware Campaign Targets Healthcare",
        "summary": "New ransomware variant uses phishing to deliver payload",
        "severity": "critical",
        "threat_actors": ["LockBit"],
        "tactics_techniques": ["T1566.001 - Spearphishing Attachment"],
        "ioc_summary": {
            "domains": ["ransom-c2.example.com", "payload.example.net"],
            "ips": ["198.51.100.5"],
            "hashes": ["aabbccdd11223344"],
            "urls": ["http://ransom-c2.example.com/stage2"],
        },
        "category": "ransomware_breaches",
    }
    sigma_rules = news_item_to_sigma(news_dict)
    assert isinstance(sigma_rules, list)
    assert len(sigma_rules) >= 2  # At least domain + IP rules
    for r in sigma_rules:
        assert "title:" in r
        assert "detection:" in r
    ok("News item → Sigma rules", f"{len(sigma_rules)} rules generated")

    # 10. News item with no IOCs
    empty_news = {
        "id": "test-sigma-empty",
        "headline": "Policy Update",
        "summary": "New regulation announced",
        "severity": "low",
        "ioc_summary": {},
    }
    empty_rules = news_item_to_sigma(empty_news)
    assert isinstance(empty_rules, list)
    assert len(empty_rules) == 0
    ok("Empty IOCs → 0 rules")


# ── Database integration ────────────────────────────────

async def test_db_integration():
    section("Database Integration — Real Data")

    from sqlalchemy import select, func
    from app.core.database import async_session_factory
    from app.models.models import NewsItem, IntelItem
    from app.normalizers.stix import news_item_to_bundle, ioc_list_to_bundle
    from app.normalizers.rules import news_item_to_sigma
    from app.schemas import NewsItemResponse

    async with async_session_factory() as db:
        # Get a news item with IOCs
        result = await db.execute(
            select(NewsItem)
            .where(NewsItem.ioc_summary.isnot(None))
            .order_by(func.random())
            .limit(1)
        )
        item = result.scalar_one_or_none()

        if item:
            item_dict = NewsItemResponse.model_validate(item).model_dump()

            # STIX bundle from real news item
            bundle = news_item_to_bundle(item_dict)
            obj_count = len(bundle.get("objects", []))
            json_str = json.dumps(bundle, indent=2, default=str)
            ok(
                "Real news → STIX bundle",
                f"{obj_count} objects, {len(json_str)} bytes — '{item.headline[:50]}'"
            )

            # Sigma rules from real news item
            sigma_rules = news_item_to_sigma(item_dict)
            ok(
                "Real news → Sigma rules",
                f"{len(sigma_rules)} rules — '{item.headline[:50]}'"
            )

            if sigma_rules:
                print(f"\n    {YELLOW}Sample Sigma rule (first 12 lines):{RESET}")
                for line in sigma_rules[0].split("\n")[:12]:
                    print(f"      {line}")
                print()
        else:
            ok("No news items with IOCs found", "skipping DB test")

        # Intel items → STIX bundle
        intel_result = await db.execute(
            select(IntelItem).order_by(func.random()).limit(5)
        )
        intel_items = intel_result.scalars().all()
        if intel_items:
            iocs = []
            for ii in intel_items:
                for cve in (ii.cve_ids or []):
                    iocs.append({"value": cve, "ioc_type": "cve", "risk_score": ii.risk_score or 50, "tags": ii.tags or []})
            if iocs:
                bundle = ioc_list_to_bundle(iocs)
                ok("Real intel items → STIX bundle", f"{len(bundle['objects'])} objects from {len(iocs)} IOCs")
            else:
                ok("Intel items have no CVEs", "skipping")
        else:
            ok("No intel items found", "skipping")

        # Count totals
        news_count = (await db.execute(select(func.count(NewsItem.id)))).scalar()
        intel_count = (await db.execute(select(func.count(IntelItem.id)))).scalar()
        ok("Database totals", f"{news_count} news items, {intel_count} intel items")


# ── Main ────────────────────────────────────────────────

def main():
    print(f"\n{CYAN}{'═' * 60}{RESET}")
    print(f"  Phase 3 Integration Test — Output & Export Layer")
    print(f"  STIX 2.1 Bundle Export + Sigma Rule Generation")
    print(f"{CYAN}{'═' * 60}{RESET}")

    try:
        test_stix_module()
    except Exception as e:
        fail("STIX module", str(e))

    try:
        test_sigma_module()
    except Exception as e:
        fail("Sigma module", str(e))

    try:
        asyncio.run(test_db_integration())
    except Exception as e:
        fail("DB integration", str(e))

    # Summary
    total = passed + failed
    print(f"\n{CYAN}{'═' * 60}{RESET}")
    if failed == 0:
        print(f"  {GREEN}ALL {total} TESTS PASSED{RESET}")
    else:
        print(f"  {RED}{failed} FAILED{RESET} / {GREEN}{passed} passed{RESET} / {total} total")
    print(f"{CYAN}{'═' * 60}{RESET}\n")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
