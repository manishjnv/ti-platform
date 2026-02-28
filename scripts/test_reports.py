#!/usr/bin/env python3
"""Test all report endpoints for accuracy."""
import subprocess
import json
import sys

API = "http://localhost:8000/api/v1"
COOKIE = ["-b", "/tmp/cookies.txt"]

def curl(method, path, data=None):
    cmd = ["curl", "-s"] + COOKIE
    if method != "GET":
        cmd += ["-X", method]
    if data:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(data)]
    cmd.append(f"{API}{path}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"_raw": r.stdout, "_err": r.stderr}

def test(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    return 1 if passed else 0

# ─── Test Suite ───
passed = 0
total = 0

print("\n=== 1. STATS ENDPOINT ===")
stats = curl("GET", "/reports/stats")
total += 1; passed += test("Stats returns total_reports", "total_reports" in stats, f"total={stats.get('total_reports')}")
total += 1; passed += test("Stats has by_status", "by_status" in stats)
total += 1; passed += test("Stats has by_type", "by_type" in stats)
total += 1; passed += test("Stats has recent_published", "recent_published" in stats)

print("\n=== 2. TEMPLATES ENDPOINT ===")
templates = curl("GET", "/reports/templates")
total += 1; passed += test("Returns 5 templates", len(templates) == 5, f"got {len(templates)}")
for tpl_key in ["incident", "threat_advisory", "weekly_summary", "ioc_bulletin", "custom"]:
    total += 1; passed += test(f"Template '{tpl_key}' exists", tpl_key in templates)
    if tpl_key in templates:
        total += 1; passed += test(f"  has sections", len(templates[tpl_key].get("sections", [])) > 0, f"{len(templates[tpl_key].get('sections', []))} sections")

print("\n=== 3. CREATE REPORTS (all 5 types) ===")
report_ids = {}
create_tests = [
    ("incident", {"title": "Test Incident Report", "report_type": "incident", "severity": "high", "tlp": "TLP:AMBER", "tags": ["apt", "ransomware"]}),
    ("threat_advisory", {"title": "Test Threat Advisory", "report_type": "threat_advisory", "severity": "critical", "tlp": "TLP:RED", "tags": ["apt28"]}),
    ("weekly_summary", {"title": "Test Weekly Summary", "report_type": "weekly_summary", "severity": "medium", "tlp": "TLP:GREEN", "tags": ["weekly"]}),
    ("ioc_bulletin", {"title": "Test IOC Bulletin", "report_type": "ioc_bulletin", "severity": "medium", "tlp": "TLP:GREEN", "tags": ["malware"]}),
    ("custom", {"title": "Test Custom Report", "report_type": "custom", "severity": "low", "tlp": "TLP:CLEAR", "tags": []}),
]
for rtype, data in create_tests:
    report = curl("POST", "/reports", data)
    rid = report.get("id", "")
    report_ids[rtype] = rid
    total += 1; passed += test(f"Create {rtype}", bool(rid), f"id={rid[:8]}..." if rid else f"ERROR: {report}")
    total += 1; passed += test(f"  status=draft", report.get("status") == "draft", report.get("status"))
    total += 1; passed += test(f"  report_type={rtype}", report.get("report_type") == rtype, report.get("report_type"))
    total += 1; passed += test(f"  severity matches", report.get("severity") == data["severity"], report.get("severity"))
    total += 1; passed += test(f"  tlp matches", report.get("tlp") == data["tlp"], report.get("tlp"))
    total += 1; passed += test(f"  tags match", report.get("tags") == data["tags"], report.get("tags"))
    sections = report.get("content", {}).get("sections", [])
    expected_sections = len(templates.get(rtype, {}).get("sections", []))
    total += 1; passed += test(f"  template sections populated", len(sections) == expected_sections, f"{len(sections)}/{expected_sections}")

print("\n=== 4. LIST REPORTS ===")
rlist = curl("GET", "/reports?page=1&page_size=50")
total += 1; passed += test("List returns reports", "reports" in rlist, f"keys={list(rlist.keys())}")
total += 1; passed += test("List has total", "total" in rlist, f"total={rlist.get('total')}")
total += 1; passed += test("Total >= 5", rlist.get("total", 0) >= 5, f"got {rlist.get('total')}")

# Test filters
rlist_filtered = curl("GET", "/reports?status=draft&report_type=incident")
total += 1; passed += test("Filter by status+type works", "reports" in rlist_filtered)

# Test search
rlist_search = curl("GET", "/reports?search=Incident")
total += 1; passed += test("Search filter works", "reports" in rlist_search and rlist_search.get("total", 0) >= 1, f"found {rlist_search.get('total', 0)}")

print("\n=== 5. GET SINGLE REPORT ===")
test_id = report_ids.get("incident", "")
if test_id:
    single = curl("GET", f"/reports/{test_id}")
    total += 1; passed += test("Get by ID returns report", single.get("id") == test_id)
    total += 1; passed += test("Has author_email", "author_email" in single, single.get("author_email"))
    total += 1; passed += test("Has items list", "items" in single, f"items={len(single.get('items', []))}")
    total += 1; passed += test("Has content with sections", "sections" in single.get("content", {}))
else:
    print("  [SKIP] No incident report ID available")

print("\n=== 6. UPDATE REPORT ===")
if test_id:
    updated = curl("PUT", f"/reports/{test_id}", {"title": "Updated Incident Report", "summary": "This is an updated summary", "severity": "critical"})
    total += 1; passed += test("Update title", updated.get("title") == "Updated Incident Report", updated.get("title"))
    total += 1; passed += test("Update summary", updated.get("summary") == "This is an updated summary")
    total += 1; passed += test("Update severity", updated.get("severity") == "critical", updated.get("severity"))
    total += 1; passed += test("Status unchanged (still draft)", updated.get("status") == "draft")

print("\n=== 7. STATUS WORKFLOW ===")
if test_id:
    # Draft -> Review
    review = curl("PUT", f"/reports/{test_id}", {"status": "review"})
    total += 1; passed += test("Draft -> Review", review.get("status") == "review", review.get("status"))
    
    # Review -> Published
    published = curl("PUT", f"/reports/{test_id}", {"status": "published"})
    total += 1; passed += test("Review -> Published", published.get("status") == "published", published.get("status"))
    total += 1; passed += test("published_at set", published.get("published_at") is not None, published.get("published_at"))
    
    # Published -> Archived
    archived = curl("PUT", f"/reports/{test_id}", {"status": "archived"})
    total += 1; passed += test("Published -> Archived", archived.get("status") == "archived", archived.get("status"))

    # Check stats updated
    stats2 = curl("GET", "/reports/stats")
    total += 1; passed += test("Stats updated after workflow", stats2.get("total_reports", 0) >= 5)

print("\n=== 8. ADD/REMOVE REPORT ITEMS ===")
link_id = report_ids.get("threat_advisory", "")
if link_id:
    # Get some intel items to link
    intel_list = curl("GET", "/intel?page=1&page_size=3")
    intel_items = intel_list.get("items", [])
    
    if len(intel_items) >= 1:
        item = intel_items[0]
        item_data = {
            "item_type": "intel_item",
            "item_id": item["id"],
            "item_title": item.get("title", "Test Item"),
            "notes": "Linked during testing"
        }
        added = curl("POST", f"/reports/{link_id}/items", item_data)
        total += 1; passed += test("Add item to report", "id" in added, f"item_id={added.get('id', 'ERR')[:8]}...")
        
        # Verify linked count updated
        report_after = curl("GET", f"/reports/{link_id}")
        total += 1; passed += test("linked_intel_count incremented", report_after.get("linked_intel_count", 0) >= 1, f"count={report_after.get('linked_intel_count')}")
        total += 1; passed += test("Items list has entry", len(report_after.get("items", [])) >= 1)
        
        # Add duplicate should fail or be handled
        dup_result = curl("POST", f"/reports/{link_id}/items", item_data)
        total += 1; passed += test("Duplicate add handled", "detail" in dup_result or "id" in dup_result, f"{'error' if 'detail' in dup_result else 'ok'}")
        
        # Remove item
        if added.get("id"):
            removed = curl("DELETE", f"/reports/{link_id}/items/{added['id']}")
            total += 1; passed += test("Remove item from report", removed.get("deleted") == True, str(removed))
            
            # Verify count decremented
            report_after2 = curl("GET", f"/reports/{link_id}")
            total += 1; passed += test("linked_intel_count decremented", report_after2.get("linked_intel_count", 999) < report_after.get("linked_intel_count", 999))
    else:
        print("  [SKIP] No intel items available for linking")

print("\n=== 9. AI SUMMARY ===")
ai_id = report_ids.get("weekly_summary", "")
if ai_id:
    # First add some content to make AI summary meaningful
    curl("PUT", f"/reports/{ai_id}", {
        "content": {
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "content": "This week saw significant threat activity including APT campaigns targeting financial institutions."},
                {"key": "key_threats", "title": "Key Threats", "content": "Multiple ransomware variants detected across healthcare sector."}
            ]
        }
    })
    ai_result = curl("POST", f"/reports/{ai_id}/ai-summary")
    total += 1; passed += test("AI summary endpoint responds", "summary" in ai_result or "detail" in ai_result or "error" in ai_result, 
                                f"{'has summary' if 'summary' in ai_result else ai_result.get('detail', ai_result.get('error', str(ai_result)[:100]))}")

print("\n=== 10. MARKDOWN EXPORT ===")
export_id = report_ids.get("threat_advisory", "")
if export_id:
    # Update it first with some content
    curl("PUT", f"/reports/{export_id}", {
        "summary": "Critical threat advisory for APT28 campaign",
        "content": {
            "sections": [
                {"key": "executive_summary", "title": "Executive Summary", "content": "APT28 is conducting phishing operations targeting NATO allies."},
                {"key": "threat_overview", "title": "Threat Overview", "content": "The campaign uses spearphishing with macro-enabled documents."},
                {"key": "indicators", "title": "Indicators of Compromise", "content": "malicious.domain.com, 192.168.1.100"}
            ]
        }
    })
    # Export
    export_cmd = ["curl", "-s"] + COOKIE + [f"{API}/reports/{export_id}/export"]
    r = subprocess.run(export_cmd, capture_output=True, text=True)
    md = r.stdout
    total += 1; passed += test("Export returns markdown", len(md) > 50, f"{len(md)} chars")
    total += 1; passed += test("Has TLP watermark", "TLP:" in md.upper(), md[:100].replace("\n", " "))
    total += 1; passed += test("Has report title", "Test Threat Advisory" in md)
    total += 1; passed += test("Has section content", "APT28" in md)
    total += 1; passed += test("Has metadata", "Severity" in md or "severity" in md)

print("\n=== 11. DELETE REPORT ===")
del_id = report_ids.get("custom", "")
if del_id:
    del_result = curl("DELETE", f"/reports/{del_id}")
    total += 1; passed += test("Delete report", del_result.get("deleted") == True, str(del_result))
    
    # Verify it's gone
    get_deleted = curl("GET", f"/reports/{del_id}")
    total += 1; passed += test("Deleted report returns 404", "detail" in get_deleted, get_deleted.get("detail", ""))

    # Verify stats updated
    stats3 = curl("GET", "/reports/stats")
    total += 1; passed += test("Stats total decremented after delete", stats3.get("total_reports", 0) < rlist.get("total", 0), f"now={stats3.get('total_reports')}")

print("\n=== 12. EDGE CASES ===")
# Invalid report type
bad = curl("POST", "/reports", {"title": "Bad", "report_type": "nonexistent"})
total += 1; passed += test("Invalid report_type rejected", "detail" in bad, str(bad.get("detail", ""))[:80])

# Missing title
bad2 = curl("POST", "/reports", {"report_type": "custom"})
total += 1; passed += test("Missing title rejected", "detail" in bad2)

# Get non-existent report
bad3 = curl("GET", "/reports/00000000-0000-0000-0000-000000000000")
total += 1; passed += test("Non-existent report returns 404", "detail" in bad3)

# Update non-existent report
bad4 = curl("PUT", "/reports/00000000-0000-0000-0000-000000000000", {"title": "x"})
total += 1; passed += test("Update non-existent returns 404", "detail" in bad4)

print(f"\n{'='*50}")
print(f"RESULTS: {passed}/{total} passed ({total-passed} failed)")
if passed == total:
    print("ALL TESTS PASSED!")
else:
    print(f"FAILURES: {total-passed} tests failed")
print(f"{'='*50}\n")
