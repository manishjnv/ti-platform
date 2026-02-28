#!/usr/bin/env python3
"""Test all 5 report export formats — creates a sample report, adds linked items, exports each."""

import subprocess, json, sys, tempfile, os

BASE = "http://localhost:8000/api/v1"
COOKIE = "-b /tmp/cookies.txt"

def curl(method, path, data=None):
    if data:
        # Write JSON to temp file to avoid shell escaping issues
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            f.flush()
            tmp = f.name
        cmd = f"curl -s {COOKIE} -X {method} {BASE}{path} -H 'Content-Type: application/json' -d @{tmp}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        os.unlink(tmp)
    else:
        cmd = f"curl -s {COOKIE} -X {method} {BASE}{path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except:
        return result.stdout

def curl_raw(method, path):
    cmd = f"curl -s {COOKIE} -X {method} '{BASE}{path}' -o /dev/null -w '%{{http_code}}|%{{size_download}}|%{{content_type}}'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    parts = result.stdout.strip().split("|")
    return {"status": int(parts[0]), "size": int(parts[1]), "content_type": parts[2] if len(parts) > 2 else ""}

def curl_content(method, path, max_chars=500):
    cmd = f"curl -s {COOKIE} -X {method} '{BASE}{path}'"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    try:
        return result.stdout[:max_chars].decode('utf-8', errors='replace')
    except:
        return result.stdout[:max_chars].hex()

def curl_binary_head(method, path, num_bytes=4):
    """Get raw bytes from response (for binary format checks like PDF)."""
    cmd = f"curl -s {COOKIE} -X {method} '{BASE}{path}'"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout[:num_bytes]

passed = total = 0
def test(name, cond, detail=""):
    global passed, total
    total += 1
    if cond:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name} — {detail}")

# ─── Create a rich sample report ──────────────────────────
print("\n=== SETUP: Create sample report ===")

report = curl("POST", "/reports", {
    "title": "APT29 Spear-Phishing Campaign — Q1 2026 Advisory",
    "summary": "Russian-linked APT29 (Cozy Bear) has been conducting targeted spear-phishing campaigns against NATO government agencies and defense contractors since January 2026. The campaign uses macro-enabled documents to deliver custom backdoors.",
    "report_type": "threat_advisory",
    "severity": "critical",
    "tlp": "TLP:RED",
    "tags": ["apt29", "cozy-bear", "russia", "nato", "spear-phishing"],
    "content": {
        "sections": [
            {"key": "executive_summary", "title": "Executive Summary", "body": "APT29 (Cozy Bear), a Russian state-sponsored threat group, has launched a sophisticated spear-phishing campaign targeting NATO member government agencies and defense contractors. The campaign began in January 2026 and has compromised at least 12 organizations across 7 countries."},
            {"key": "threat_overview", "title": "Threat Overview", "body": "The campaign uses carefully crafted spear-phishing emails impersonating diplomatic communications. Attachments contain macro-enabled Word documents that deploy a custom backdoor dubbed 'DarkHalo v3'. The malware establishes C2 communication over HTTPS using compromised legitimate websites as proxies."},
            {"key": "ttps", "title": "Tactics, Techniques & Procedures", "body": "Initial Access: Spear-phishing Attachment (T1566.001)\nExecution: User Execution of Malicious File (T1204.002)\nPersistence: Registry Run Keys (T1547.001)\nDefense Evasion: Obfuscated Files (T1027)\nC2: HTTPS Protocol (T1071.001)\nExfiltration: Automated Exfiltration (T1020)"},
            {"key": "indicators", "title": "Indicators of Compromise", "body": "Domains: darkhalo-c2.example[.]com, proxy-relay.example[.]net\nIPs: 198.51.100.42, 203.0.113.55\nHashes (SHA-256): a1b2c3d4e5f6... (DarkHalo dropper), f6e5d4c3b2a1... (Backdoor payload)\nEmail: diplomatic-update@example[.]com"},
            {"key": "affected_systems", "title": "Affected Systems", "body": "Microsoft Office 2019/2021/365 (Windows)\nWindows 10/11 endpoints\nExchange Online mailboxes\nActive Directory environments"},
            {"key": "mitigations", "title": "Mitigations", "body": "1. Block macro execution in documents from external sources\n2. Deploy YARA rule: rule APT29_DarkHalo_v3 { ... }\n3. Add IOCs to threat intelligence feeds and EDR blocklists\n4. Enable Advanced Threat Protection for email\n5. Monitor for suspicious PowerShell execution patterns"}
        ]
    }
})
report_id = report.get("id")
test("Report created", report_id is not None, str(report)[:200])
print(f"  Report ID: {report_id}")

# Add some linked items
print("\n=== SETUP: Add linked items ===")

# Find a real intel item to link
intel_list = curl("GET", "/intel?page=1&page_size=1")
intel_id = None
if intel_list.get("items") and len(intel_list["items"]) > 0:
    intel_id = intel_list["items"][0]["id"]
    item = intel_list["items"][0]
    added = curl("POST", f"/reports/{report_id}/items", {
        "item_type": "intel_item",
        "item_id": intel_id,
        "item_title": item.get("title", "Sample Intel"),
        "item_metadata": {"severity": item.get("severity", "high"), "source_name": item.get("source_name", "NVD"), "cve_ids": item.get("cve_ids", [])},
    })
    test("Linked intel item", added.get("id") is not None, str(added)[:200])
else:
    print("  [SKIP] No intel items available to link")

# ─── Test all 5 export formats ────────────────────────────
print("\n" + "=" * 60)
print("TESTING ALL EXPORT FORMATS")
print("=" * 60)

# 1. Markdown
print("\n=== 1. MARKDOWN EXPORT ===")
md_info = curl_raw("GET", f"/reports/{report_id}/export?format=markdown")
test("Markdown status 200", md_info["status"] == 200, f"status={md_info['status']}")
test("Markdown has content", md_info["size"] > 100, f"size={md_info['size']}")
test("Markdown content-type", "text/markdown" in md_info["content_type"], md_info["content_type"])
md_content = curl_content("GET", f"/reports/{report_id}/export?format=markdown")
test("Has TLP watermark", "TLP:RED" in md_content, md_content[:100])
test("Has report title", "APT29" in md_content, md_content[:200])
test("Has sections", "Executive Summary" in md_content or "Threat Overview" in md_content)
print(f"  Preview: {md_content[:120]}...")

# 2. PDF
print("\n=== 2. PDF EXPORT ===")
pdf_info = curl_raw("GET", f"/reports/{report_id}/export?format=pdf")
test("PDF status 200", pdf_info["status"] == 200, f"status={pdf_info['status']}")
test("PDF has content", pdf_info["size"] > 1000, f"size={pdf_info['size']}")
test("PDF content-type", "application/pdf" in pdf_info["content_type"], pdf_info["content_type"])
# Check PDF magic bytes
pdf_head = curl_binary_head("GET", f"/reports/{report_id}/export?format=pdf")
test("PDF valid header (%PDF)", pdf_head[:4] == b"%PDF", repr(pdf_head[:10]))
print(f"  PDF size: {pdf_info['size']} bytes")

# 3. STIX 2.1
print("\n=== 3. STIX 2.1 BUNDLE EXPORT ===")
stix_info = curl_raw("GET", f"/reports/{report_id}/export?format=stix")
test("STIX status 200", stix_info["status"] == 200, f"status={stix_info['status']}")
test("STIX has content", stix_info["size"] > 100, f"size={stix_info['size']}")
test("STIX content-type", "application/json" in stix_info["content_type"], stix_info["content_type"])
stix = curl("GET", f"/reports/{report_id}/export?format=stix")
if isinstance(stix, dict):
    test("STIX is bundle", stix.get("type") == "bundle", stix.get("type"))
    test("STIX has objects", len(stix.get("objects", [])) >= 2, f"objects={len(stix.get('objects', []))}")
    obj_types = [o["type"] for o in stix.get("objects", [])]
    test("Has identity object", "identity" in obj_types, str(obj_types))
    test("Has report object", "report" in obj_types, str(obj_types))
    report_objs = [o for o in stix.get("objects", []) if o["type"] == "report"]
    if report_objs:
        report_obj = report_objs[0]
        test("Report has name", "APT29" in report_obj.get("name", ""))
        test("Report has TLP marking", len(report_obj.get("object_marking_refs", [])) > 0, str(report_obj.get("object_marking_refs")))
        test("Report has confidence", report_obj.get("confidence") == 90, f"confidence={report_obj.get('confidence')}")
        test("Report has labels/tags", "apt29" in report_obj.get("labels", []), str(report_obj.get("labels")))
    else:
        for _ in range(4):
            test("Report object detail", False, "No report object found")
    print(f"  STIX objects: {obj_types}")
else:
    test("STIX parsed as JSON", False, str(stix)[:200])

# 4. HTML
print("\n=== 4. HTML EXPORT ===")
html_info = curl_raw("GET", f"/reports/{report_id}/export?format=html")
test("HTML status 200", html_info["status"] == 200, f"status={html_info['status']}")
test("HTML has content", html_info["size"] > 500, f"size={html_info['size']}")
test("HTML content-type", "text/html" in html_info["content_type"], html_info["content_type"])
html_content = curl_content("GET", f"/reports/{report_id}/export?format=html", 6000)
test("Has DOCTYPE", "<!DOCTYPE html>" in html_content)
test("Has title tag", "APT29" in html_content)
test("Has TLP banner", "TLP:RED" in html_content)
test("Has dark theme CSS", "var(--bg)" in html_content or "#0f172a" in html_content)
test("Has section headings", "Executive Summary" in html_content or "Threat Overview" in html_content)
test("Has print styles", "@media print" in html_content)
print(f"  HTML size: {html_info['size']} bytes")

# 5. CSV
print("\n=== 5. CSV EXPORT ===")
csv_info = curl_raw("GET", f"/reports/{report_id}/export?format=csv")
test("CSV status 200", csv_info["status"] == 200, f"status={csv_info['status']}")
test("CSV has content", csv_info["size"] > 50, f"size={csv_info['size']}")
test("CSV content-type", "text/csv" in csv_info["content_type"], csv_info["content_type"])
csv_content = curl_content("GET", f"/reports/{report_id}/export?format=csv")
test("CSV has report title", "APT29" in csv_content)
test("CSV has TLP", "TLP:RED" in csv_content)
test("CSV has headers", "Item Type" in csv_content)
print(f"  CSV size: {csv_info['size']} bytes")

# 6. Invalid format
print("\n=== 6. INVALID FORMAT ===")
inv_info = curl_raw("GET", f"/reports/{report_id}/export?format=docx")
test("Invalid format returns 400", inv_info["status"] == 400, f"status={inv_info['status']}")

# ─── Cleanup ──────────────────────────────────────────────
print("\n=== CLEANUP ===")
del_result = curl("DELETE", f"/reports/{report_id}")
test("Deleted test report", del_result.get("deleted") == True, str(del_result))

# ─── Results ──────────────────────────────────────────────
print(f"\n{'=' * 60}")
print(f"RESULTS: {passed}/{total} passed ({total - passed} failed)")
if passed == total:
    print("ALL EXPORT TESTS PASSED!")
else:
    print(f"FAILURES: {total - passed}")
print(f"{'=' * 60}\n")

sys.exit(0 if passed == total else 1)
