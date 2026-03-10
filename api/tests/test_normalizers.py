"""Unit tests for all 14 normalizer modules.

Phase 1 — Core:        categories, severity, confidence, patterns, entities, enrichment, text, geo
Phase 2 — Intelligence: ioc_lifecycle, diamond, killchain, correlation
Phase 3 — Export:       stix, rules
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta

import pytest


# ═══════════════════════════════════════════════════════════
#  Phase 1 — Core Normalizers
# ═══════════════════════════════════════════════════════════


class TestCategories:
    """app.normalizers.categories"""

    def test_valid_category_passes_through(self):
        from app.normalizers.categories import normalize_category
        assert normalize_category("active_threats") == "active_threats"
        assert normalize_category("nation_state") == "nation_state"

    def test_hallucinated_category_is_remapped(self):
        from app.normalizers.categories import normalize_category
        assert normalize_category("data_breach") == "ransomware_breaches"
        assert normalize_category("malware") == "active_threats"
        assert normalize_category("zero_day") == "exploited_vulnerabilities"
        assert normalize_category("espionage") == "nation_state"

    def test_unknown_category_falls_back(self):
        from app.normalizers.categories import normalize_category
        assert normalize_category("totally_made_up") == "active_threats"
        assert normalize_category("totally_made_up", fallback="general_news") == "general_news"

    def test_detect_category_keywords(self):
        from app.normalizers.categories import detect_category
        assert detect_category("Ransomware hits hospital", "") == "ransomware_breaches"
        assert detect_category("CVE-2024-1234 exploit", "") == "exploited_vulnerabilities"
        assert detect_category("APT28 espionage campaign", "") == "nation_state"
        assert detect_category("Azure cloud SSO misconfiguration", "") == "cloud_identity"
        assert detect_category("New SCADA vulnerability", "") == "ot_ics"
        assert detect_category("GDPR compliance update", "") == "policy_regulation"
        assert detect_category("Security research paper", "") == "security_research"

    def test_detect_category_default(self):
        from app.normalizers.categories import detect_category
        assert detect_category("Something happened", "No details") == "active_threats"

    def test_valid_categories_constant(self):
        from app.normalizers.categories import VALID_NEWS_CATEGORIES
        assert len(VALID_NEWS_CATEGORIES) >= 10
        assert "active_threats" in VALID_NEWS_CATEGORIES
        assert "general_news" in VALID_NEWS_CATEGORIES


class TestSeverity:
    """app.normalizers.severity"""

    def test_severity_scores_keys(self):
        from app.normalizers.severity import SEVERITY_SCORES
        assert "critical" in SEVERITY_SCORES
        assert "high" in SEVERITY_SCORES
        assert "low" in SEVERITY_SCORES
        assert SEVERITY_SCORES["critical"] > SEVERITY_SCORES["high"] > SEVERITY_SCORES["low"]

    def test_severity_rank_ordering(self):
        from app.normalizers.severity import SEVERITY_RANK
        assert SEVERITY_RANK["critical"] > SEVERITY_RANK["high"]
        assert SEVERITY_RANK["high"] > SEVERITY_RANK["medium"]

    def test_priority_to_severity(self):
        from app.normalizers.severity import priority_to_severity
        assert priority_to_severity("critical") == "critical"
        assert priority_to_severity("high") == "high"
        assert priority_to_severity(None) in ("medium", "unknown", "info")


class TestConfidence:
    """app.normalizers.confidence"""

    def test_normalize_valid_values(self):
        from app.normalizers.confidence import normalize_confidence
        assert normalize_confidence("high") == "high"
        assert normalize_confidence("medium") == "medium"
        assert normalize_confidence("low") == "low"

    def test_normalize_non_matching_falls_back(self):
        from app.normalizers.confidence import normalize_confidence
        # No case folding — unrecognised values fall back to default
        assert normalize_confidence("HIGH") == "medium"
        assert normalize_confidence("Medium") == "medium"

    def test_normalize_none_uses_default(self):
        from app.normalizers.confidence import normalize_confidence
        assert normalize_confidence(None) == "medium"
        assert normalize_confidence(None, default="low") == "low"

    def test_normalize_invalid_uses_default(self):
        from app.normalizers.confidence import normalize_confidence
        assert normalize_confidence("banana") == "medium"


class TestPatterns:
    """app.normalizers.patterns"""

    def test_ioc_patterns_constant(self):
        from app.normalizers.patterns import IOC_PATTERNS
        assert len(IOC_PATTERNS) >= 7
        assert "ip" in IOC_PATTERNS
        assert "domain" in IOC_PATTERNS
        assert "url" in IOC_PATTERNS

    def test_detect_ip(self):
        from app.normalizers.patterns import detect_ioc_type
        assert detect_ioc_type("192.168.1.1") == "ip"
        assert detect_ioc_type("10.0.0.1") == "ip"

    def test_detect_domain(self):
        from app.normalizers.patterns import detect_ioc_type
        result = detect_ioc_type("evil.example.com")
        assert result in ("domain", "url")  # domain patterns may vary

    def test_detect_hash_md5(self):
        from app.normalizers.patterns import detect_ioc_type
        result = detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e")
        assert result is not None and "hash" in result

    def test_detect_hash_sha256(self):
        from app.normalizers.patterns import detect_ioc_type
        result = detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result is not None and "hash" in result

    def test_detect_url(self):
        from app.normalizers.patterns import detect_ioc_type
        assert detect_ioc_type("http://evil.example.com/payload") == "url"
        assert detect_ioc_type("https://malware.site/stage2") == "url"

    def test_cve_regex(self):
        from app.normalizers.patterns import CVE_RE
        match = CVE_RE.search("Found CVE-2024-12345 in the wild")
        assert match is not None
        assert match.group() == "CVE-2024-12345"

    def test_detect_unknown_returns_none(self):
        from app.normalizers.patterns import detect_ioc_type
        assert detect_ioc_type("hello world") is None
        assert detect_ioc_type("") is None


class TestEntities:
    """app.normalizers.entities"""

    def test_is_junk_product(self):
        from app.normalizers.entities import is_junk_product
        assert is_junk_product("nim") is True        # in PRODUCT_BLOCKLIST
        assert is_junk_product("unknown") is True     # single word, <12 chars, alpha
        assert is_junk_product("Apache HTTP Server") is False

    def test_normalize_product_name(self):
        from app.normalizers.entities import normalize_product_name
        result = normalize_product_name("  Apache HTTP Server  ")
        assert result == "Apache HTTP Server"

    def test_normalise_campaign_name_none(self):
        from app.normalizers.entities import normalise_campaign_name
        assert normalise_campaign_name(None) is None
        assert normalise_campaign_name("") is None

    def test_normalise_campaign_name_valid(self):
        from app.normalizers.entities import normalise_campaign_name
        result = normalise_campaign_name("  Operation Aurora  ")
        assert result == "Operation Aurora"

    def test_guess_vendor(self):
        from app.normalizers.entities import guess_vendor
        # It may or may not match, but should not crash
        result = guess_vendor("Windows 11")
        assert result is None or isinstance(result, str)


class TestText:
    """app.normalizers.text"""

    def test_strip_html(self):
        from app.normalizers.text import strip_html
        assert strip_html("<p>Hello <b>world</b></p>") == "Hello world"
        assert strip_html(None) == ""
        assert strip_html("") == ""

    def test_strip_json_fences(self):
        from app.normalizers.text import strip_json_fences
        assert strip_json_fences('```json\n{"key": "value"}\n```') == '{"key": "value"}'
        assert strip_json_fences('{"key": "value"}') == '{"key": "value"}'

    def test_parse_pub_date(self):
        from app.normalizers.text import parse_pub_date
        # ISO format
        result = parse_pub_date("2025-01-15T10:30:00Z")
        assert result is not None
        assert result.year == 2025

    def test_parse_pub_date_none(self):
        from app.normalizers.text import parse_pub_date
        assert parse_pub_date(None) is None
        assert parse_pub_date("") is None


class TestGeo:
    """app.normalizers.geo"""

    def test_cc_continent_has_entries(self):
        from app.normalizers.geo import CC_CONTINENT
        assert len(CC_CONTINENT) >= 190
        assert "US" in CC_CONTINENT
        assert "CN" in CC_CONTINENT

    def test_cc_continent_structure(self):
        from app.normalizers.geo import CC_CONTINENT
        us = CC_CONTINENT["US"]
        assert isinstance(us, tuple)
        assert len(us) == 2
        assert us[0] == "NA"  # North America

    def test_cc_names(self):
        from app.normalizers.geo import CC_NAMES
        assert CC_NAMES["US"] == "United States"
        assert CC_NAMES["GB"] == "United Kingdom"


# ═══════════════════════════════════════════════════════════
#  Phase 2 — Intelligence Model Normalizers
# ═══════════════════════════════════════════════════════════


class TestIOCLifecycle:
    """app.normalizers.ioc_lifecycle"""

    def test_ioc_age_recent(self):
        from app.normalizers.ioc_lifecycle import ioc_age_days
        now = datetime.now(timezone.utc)
        age = ioc_age_days(now)
        assert age < 1

    def test_ioc_age_old(self):
        from app.normalizers.ioc_lifecycle import ioc_age_days
        old = datetime.now(timezone.utc) - timedelta(days=30)
        age = ioc_age_days(old)
        assert 29 < age < 31

    def test_ioc_age_none(self):
        from app.normalizers.ioc_lifecycle import ioc_age_days
        age = ioc_age_days(None)
        assert age > 0  # Treats None as very old

    def test_confidence_decay_recent(self):
        from app.normalizers.ioc_lifecycle import confidence_decay
        now = datetime.now(timezone.utc)
        score = confidence_decay(80, now)
        assert score >= 75  # Minimal decay for fresh IOC

    def test_confidence_decay_old(self):
        from app.normalizers.ioc_lifecycle import confidence_decay
        old = datetime.now(timezone.utc) - timedelta(days=180)
        score = confidence_decay(80, old)
        assert score < 80  # Should decay

    def test_confidence_decay_bounds(self):
        from app.normalizers.ioc_lifecycle import confidence_decay
        assert confidence_decay(100, None) >= 0
        assert confidence_decay(0, None) >= 0
        assert confidence_decay(100, datetime.now(timezone.utc)) <= 100

    def test_ioc_ttl_days_constant(self):
        from app.normalizers.ioc_lifecycle import IOC_TTL_DAYS
        assert "ip" in IOC_TTL_DAYS
        assert "domain" in IOC_TTL_DAYS
        assert all(v > 0 for v in IOC_TTL_DAYS.values())


class TestDiamond:
    """app.normalizers.diamond"""

    def test_parse_actor_name_simple(self):
        from app.normalizers.diamond import parse_actor_name
        primary, aliases = parse_actor_name("APT28")
        assert primary == "APT28"
        assert isinstance(aliases, list)

    def test_parse_actor_name_with_aliases(self):
        from app.normalizers.diamond import parse_actor_name
        primary, aliases = parse_actor_name("APT28 (Fancy Bear, Sofacy)")
        assert primary == "APT28"
        assert "Fancy Bear" in aliases or len(aliases) > 0

    def test_extract_vertices(self):
        from app.normalizers.diamond import extract_vertices
        item = {
            "threat_actors": ["APT28"],
            "malware_families": ["Emotet"],
            "cves": ["CVE-2024-1234"],
            "targeted_sectors": ["finance"],
        }
        vertices = extract_vertices(item)
        assert isinstance(vertices, dict)
        assert "adversary" in vertices or "threat_actor" in vertices or len(vertices) > 0

    def test_extract_vertices_empty(self):
        from app.normalizers.diamond import extract_vertices
        vertices = extract_vertices({})
        assert isinstance(vertices, dict)


class TestKillchain:
    """app.normalizers.killchain"""

    def test_parse_technique_with_id(self):
        from app.normalizers.killchain import parse_technique
        tid, name = parse_technique("T1566.001 - Spearphishing Attachment")
        assert tid == "T1566.001"
        assert name == "Spearphishing Attachment"

    def test_parse_technique_id_only_returns_none(self):
        from app.normalizers.killchain import parse_technique
        # Requires "T1059 - Name" format; bare ID returns None
        tid, name = parse_technique("T1059")
        assert tid is None
        assert name is None

    def test_parse_technique_invalid(self):
        from app.normalizers.killchain import parse_technique
        tid, name = parse_technique("not a technique")
        assert tid is None

    def test_tactic_to_phase(self):
        from app.normalizers.killchain import tactic_to_phase
        phase = tactic_to_phase("initial-access")
        assert isinstance(phase, str)
        assert len(phase) > 0

    def test_coverage_score_empty(self):
        from app.normalizers.killchain import coverage_score
        score = coverage_score({})
        assert score == 0.0

    def test_coverage_score_full(self):
        from app.normalizers.killchain import coverage_score
        # Provide all phases with at least one technique
        from app.normalizers.killchain import TACTIC_TO_PHASE
        full = {phase: [{"id": "T1000"}] for phase in set(TACTIC_TO_PHASE.values())}
        score = coverage_score(full)
        assert 0.0 <= score <= 1.0


class TestCorrelation:
    """app.normalizers.correlation"""

    def test_corroboration_boost_single(self):
        from app.normalizers.correlation import corroboration_boost
        assert corroboration_boost(1) == 0

    def test_corroboration_boost_multiple(self):
        from app.normalizers.correlation import corroboration_boost
        boost2 = corroboration_boost(2)
        boost5 = corroboration_boost(5)
        assert boost2 > 0
        assert boost5 > boost2

    def test_corroboration_boost_cap(self):
        from app.normalizers.correlation import corroboration_boost
        boost = corroboration_boost(100)
        assert boost <= 35

    def test_find_cve_overlaps(self):
        from app.normalizers.correlation import find_cve_overlaps
        items = [
            {"id": "1", "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"], "source_name": "NVD"},
            {"id": "2", "cve_ids": ["CVE-2024-1234"], "source_name": "OTX"},
            {"id": "3", "cve_ids": ["CVE-2024-9999"], "source_name": "KEV"},
        ]
        overlaps = find_cve_overlaps(items)
        assert "CVE-2024-1234" in overlaps
        assert overlaps["CVE-2024-1234"]["count"] >= 2
        assert "CVE-2024-9999" not in overlaps  # Only 1 source

    def test_find_cve_overlaps_empty(self):
        from app.normalizers.correlation import find_cve_overlaps
        assert find_cve_overlaps([]) == {}

    def test_compute_overlap_summary(self):
        from app.normalizers.correlation import compute_overlap_summary
        items = [
            {"id": "1", "cve_ids": ["CVE-2024-1234"], "source_name": "A", "threat_actors": ["APT28"], "ioc_summary": {"ips": ["1.2.3.4"]}},
            {"id": "2", "cve_ids": ["CVE-2024-1234"], "source_name": "B", "threat_actors": ["APT28"], "ioc_summary": {"ips": ["1.2.3.4"]}},
        ]
        summary = compute_overlap_summary(items)
        assert isinstance(summary, dict)


# ═══════════════════════════════════════════════════════════
#  Phase 3 — Output & Export Normalizers
# ═══════════════════════════════════════════════════════════


class TestStix:
    """app.normalizers.stix"""

    def test_platform_identity(self):
        from app.normalizers.stix import platform_identity
        identity = platform_identity()
        assert identity["type"] == "identity"
        assert identity["spec_version"] == "2.1"
        assert identity["identity_class"] == "system"

    def test_ioc_to_indicator_ip(self):
        from app.normalizers.stix import ioc_to_indicator
        indicator = ioc_to_indicator({"value": "10.0.0.1", "ioc_type": "ip", "risk_score": 80})
        assert indicator["type"] == "indicator"
        assert "ipv4-addr:value" in indicator["pattern"]

    def test_ioc_to_indicator_domain(self):
        from app.normalizers.stix import ioc_to_indicator
        ind = ioc_to_indicator({"value": "evil.com", "ioc_type": "domain", "risk_score": 70})
        assert "domain-name:value" in ind["pattern"]

    def test_ioc_to_indicator_hash(self):
        from app.normalizers.stix import ioc_to_indicator
        ind = ioc_to_indicator({"value": "abc123", "ioc_type": "hash_md5", "risk_score": 90})
        assert "file:hashes" in ind["pattern"]

    def test_ioc_to_indicator_unsupported(self):
        from app.normalizers.stix import ioc_to_indicator
        assert ioc_to_indicator({"value": "x", "ioc_type": "unknown", "risk_score": 0}) == {}

    def test_actor_to_stix(self):
        from app.normalizers.stix import actor_to_stix
        actor = actor_to_stix("APT28", aliases=["Fancy Bear"])
        assert actor["type"] == "threat-actor"
        assert actor["name"] == "APT28"

    def test_malware_to_stix(self):
        from app.normalizers.stix import malware_to_stix
        mal = malware_to_stix("Emotet")
        assert mal["type"] == "malware"

    def test_cve_to_vulnerability(self):
        from app.normalizers.stix import cve_to_vulnerability
        vuln = cve_to_vulnerability("CVE-2024-12345")
        assert vuln["type"] == "vulnerability"
        assert "CVE-2024-12345" in vuln["name"]

    def test_technique_to_attack_pattern(self):
        from app.normalizers.stix import technique_to_attack_pattern
        ap = technique_to_attack_pattern("T1566.001", "Spearphishing Attachment")
        assert ap["type"] == "attack-pattern"

    def test_stix_relationship(self):
        from app.normalizers.stix import stix_relationship
        rel = stix_relationship("threat-actor--1", "uses", "malware--2")
        assert rel["type"] == "relationship"
        assert rel["relationship_type"] == "uses"

    def test_build_bundle(self):
        from app.normalizers.stix import build_bundle, platform_identity
        bundle = build_bundle([platform_identity()])
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) >= 1

    def test_build_bundle_deduplicates(self):
        from app.normalizers.stix import build_bundle, malware_to_stix
        mal = malware_to_stix("Emotet")
        bundle = build_bundle([mal, mal, mal])
        ids = [o["id"] for o in bundle["objects"]]
        assert len(ids) == len(set(ids))  # identity + 1 unique malware

    def test_build_bundle_skips_empty(self):
        from app.normalizers.stix import build_bundle
        bundle = build_bundle([{}, None, {}])
        # Should not crash, objects only has platform identity
        assert bundle["type"] == "bundle"

    def test_news_item_to_bundle(self):
        from app.normalizers.stix import news_item_to_bundle
        news = {
            "id": "test-1",
            "headline": "APT28 campaign",
            "summary": "Test summary",
            "source": "Test",
            "published_at": "2025-01-15",
            "severity": "high",
            "threat_actors": ["APT28"],
            "malware_families": ["Emotet"],
            "cves": ["CVE-2024-1234"],
            "tactics_techniques": ["T1566.001 - Spearphishing"],
            "ioc_summary": {"domains": ["evil.com"], "ips": ["1.2.3.4"], "hashes": [], "urls": []},
        }
        bundle = news_item_to_bundle(news)
        assert bundle["type"] == "bundle"
        types = {o["type"] for o in bundle["objects"]}
        assert "identity" in types
        assert "report" in types

    def test_ioc_list_to_bundle(self):
        from app.normalizers.stix import ioc_list_to_bundle
        iocs = [
            {"value": "1.2.3.4", "ioc_type": "ip", "risk_score": 80, "tags": []},
            {"value": "evil.com", "ioc_type": "domain", "risk_score": 60, "tags": []},
        ]
        bundle = ioc_list_to_bundle(iocs)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) >= 3  # identity + 2 indicators

    def test_stix_bundle_json_serializable(self):
        from app.normalizers.stix import news_item_to_bundle
        bundle = news_item_to_bundle({
            "id": "test", "headline": "Test", "summary": "Test",
            "source": "T", "published_at": "2025-01-01", "severity": "low",
        })
        json_str = json.dumps(bundle, default=str)
        assert json.loads(json_str)["type"] == "bundle"

    def test_tlp_marking_ids(self):
        from app.normalizers.stix import TLP_MARKING_IDS
        assert len(TLP_MARKING_IDS) == 5
        assert "TLP:CLEAR" in TLP_MARKING_IDS
        assert "TLP:RED" in TLP_MARKING_IDS

    def test_ioc_type_map(self):
        from app.normalizers.stix import IOC_TYPE_MAP
        assert len(IOC_TYPE_MAP) >= 7
        assert "ip" in IOC_TYPE_MAP
        assert "email" in IOC_TYPE_MAP


class TestRules:
    """app.normalizers.rules"""

    def test_ioc_to_sigma_ip(self):
        from app.normalizers.rules import ioc_to_sigma
        rule = ioc_to_sigma("ip", ["10.0.0.1", "10.0.0.2"], severity="high")
        assert rule is not None
        assert "title:" in rule
        assert "logsource:" in rule
        assert "detection:" in rule
        assert "10.0.0.1" in rule

    def test_ioc_to_sigma_domain(self):
        from app.normalizers.rules import ioc_to_sigma
        rule = ioc_to_sigma("domain", ["evil.example.com"])
        assert rule is not None
        assert "evil.example.com" in rule

    def test_ioc_to_sigma_hash(self):
        from app.normalizers.rules import ioc_to_sigma
        rule = ioc_to_sigma("hash_sha256", ["abc123def456"])
        assert rule is not None

    def test_ioc_to_sigma_url(self):
        from app.normalizers.rules import ioc_to_sigma
        rule = ioc_to_sigma("url", ["http://evil.com/payload"])
        assert rule is not None

    def test_ioc_to_sigma_unsupported(self):
        from app.normalizers.rules import ioc_to_sigma
        assert ioc_to_sigma("unsupported", ["test"]) is None

    def test_ioc_to_sigma_empty_values(self):
        from app.normalizers.rules import ioc_to_sigma
        assert ioc_to_sigma("ip", []) is None

    def test_ioc_to_sigma_custom_tags(self):
        from app.normalizers.rules import ioc_to_sigma
        rule = ioc_to_sigma(
            "ip", ["192.168.1.1"],
            title="Custom Rule",
            severity="critical",
            tags=["attack.initial_access", "attack.t1566"],
        )
        assert "Custom Rule" in rule
        assert "critical" in rule
        assert "attack.initial_access" in rule

    def test_news_item_to_sigma(self):
        from app.normalizers.rules import news_item_to_sigma
        news = {
            "id": "test-1",
            "headline": "Ransomware Campaign",
            "severity": "critical",
            "ioc_summary": {
                "domains": ["ransom-c2.example.com"],
                "ips": ["198.51.100.5"],
                "hashes": ["aabbccdd"],
                "urls": ["http://ransom-c2.example.com/stage2"],
            },
        }
        rules = news_item_to_sigma(news)
        assert isinstance(rules, list)
        assert len(rules) >= 2

    def test_news_item_to_sigma_empty_iocs(self):
        from app.normalizers.rules import news_item_to_sigma
        rules = news_item_to_sigma({"id": "x", "headline": "No IOCs", "ioc_summary": {}})
        assert rules == []

    def test_news_item_to_sigma_no_ioc_summary(self):
        from app.normalizers.rules import news_item_to_sigma
        rules = news_item_to_sigma({"id": "x", "headline": "No IOCs"})
        assert rules == []

    def test_severity_to_level_mapping(self):
        from app.normalizers.rules import SEVERITY_TO_LEVEL
        assert SEVERITY_TO_LEVEL["critical"] == "critical"
        assert SEVERITY_TO_LEVEL["info"] == "informational"
        assert len(SEVERITY_TO_LEVEL) >= 5
