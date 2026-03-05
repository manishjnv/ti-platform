#!/usr/bin/env python3
"""Test P2 improvements: status transitions, bulk ops, export, filters, assignees."""
import json, sys, os, uuid

import redis.asyncio
import redis
from jose import jwt
import httpx
from datetime import datetime, timedelta, timezone

SECRET_KEY = os.environ.get("SECRET_KEY", "ca11ded3d44a5499adec236209a4d0ff62cd0a935c7d019b239d47d983917962")
ALGORITHM = "HS256"
API_BASE = "http://localhost:8000/api/v1"

# Create a valid session: store session_id in Redis, create JWT with matching sid
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
r = redis.Redis(host=REDIS_HOST, port=6379, password="IntelWatch_R3dis_2026", db=0)

session_id = str(uuid.uuid4())
# We need first to get admin user ID from DB, but we can use a placeholder
# The auth middleware calls get_or_create_user with the email from JWT payload
# So we just need a valid JWT + valid session in Redis

# Create JWT token
token_data = {
    "sub": "admin-user-id",  # This gets overridden by get_or_create_user lookup
    "email": "manishjnvk@gmail.com",
    "role": "admin",
    "name": "Admin",
    "sid": session_id,
    "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    "iat": datetime.now(timezone.utc),
    "jti": str(uuid.uuid4()),
}
token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

# Store session in Redis (just needs to exist)
r.setex(f"session:{session_id}", 3600, "admin-user-id")

client = httpx.Client(base_url=API_BASE, cookies={"iw_session": token}, timeout=30)

results = []

def test(name, passed, detail=""):
    status = "PASS" if passed else "FAIL"
    results.append((name, status, detail))
    print(f"  [{status}] {name}" + (f" - {detail}" if detail else ""))

print("\n=== P2 Improvements Test Suite ===\n")

# 1. Test GET /cases/assignees
print("1. Assignees endpoint")
resp = client.get("/cases/assignees")
test("GET /cases/assignees", resp.status_code == 200, f"status={resp.status_code}")
assignees = resp.json() if resp.status_code == 200 else []
test("Returns list", isinstance(assignees, list), f"count={len(assignees)}")

# 2. Create test cases for bulk/filter/export tests
print("\n2. Create test cases")
case_ids = []
test_cases = [
    {"title": "P2 Test Critical IR", "case_type": "incident_response", "priority": "critical", "severity": "critical", "tlp": "TLP:RED", "tags": ["ransomware", "urgent"]},
    {"title": "P2 Test High Hunt", "case_type": "hunt", "priority": "high", "severity": "high", "tlp": "TLP:AMBER", "tags": ["apt", "lateral"]},
    {"title": "P2 Test Medium Inv", "case_type": "investigation", "priority": "medium", "severity": "medium", "tlp": "TLP:GREEN", "tags": ["phishing"]},
]
for tc in test_cases:
    resp = client.post("/cases", json=tc)
    test(f"Create '{tc['title']}'", resp.status_code == 201, f"status={resp.status_code}")
    if resp.status_code == 201:
        case_ids.append(resp.json()["id"])

# 3. Test expanded filters
print("\n3. Expanded filters")
resp = client.get("/cases", params={"severity": "critical"})
sev_ok = resp.status_code == 200
sev_total = 0
if sev_ok:
    try: sev_total = resp.json()["total"]
    except: pass
test("Filter by severity=critical", sev_ok and sev_total >= 1, f"total={sev_total}")

resp = client.get("/cases", params={"tlp": "TLP:RED"})
tlp_ok = resp.status_code == 200
tlp_total = 0
if tlp_ok:
    try: tlp_total = resp.json()["total"]
    except: pass
test("Filter by tlp=TLP:RED", tlp_ok and tlp_total >= 1, f"total={tlp_total}")

resp = client.get("/cases", params={"tag": "ransomware"})
try:
    tag_total = resp.json().get("total", 0) if resp.status_code == 200 else 0
except Exception:
    tag_total = 0
test("Filter by tag=ransomware", resp.status_code == 200 and tag_total >= 1, f"status={resp.status_code}, total={tag_total}")

resp = client.get("/cases", params={"severity": "info"})
try:
    info_total = resp.json().get("total", 0) if resp.status_code == 200 else 0
except Exception:
    info_total = 0
test("Filter severity=info (0 results)", resp.status_code == 200, f"total={info_total}")

# 4. Status transitions
print("\n4. Status transitions")
if len(case_ids) >= 1:
    cid = case_ids[0]
    # Valid: new -> in_progress
    resp = client.put(f"/cases/{cid}", json={"status": "in_progress"})
    test("Valid transition new→in_progress", resp.status_code == 200, f"status={resp.status_code}")

    # Valid: in_progress -> resolved
    resp = client.put(f"/cases/{cid}", json={"status": "resolved"})
    test("Valid transition in_progress→resolved", resp.status_code == 200, f"status={resp.status_code}")

    # Invalid: resolved -> pending (not allowed)
    resp = client.put(f"/cases/{cid}", json={"status": "pending"})
    test("Invalid transition resolved→pending (422)", resp.status_code == 422, f"status={resp.status_code}")

    # Valid: resolved -> closed
    resp = client.put(f"/cases/{cid}", json={"status": "closed"})
    test("Valid transition resolved→closed", resp.status_code == 200, f"status={resp.status_code}")

    # Valid: closed -> in_progress (reopen)
    resp = client.put(f"/cases/{cid}", json={"status": "in_progress"})
    test("Valid transition closed→in_progress (reopen)", resp.status_code == 200, f"status={resp.status_code}")

# 5. Bulk operations
print("\n5. Bulk operations")
if len(case_ids) >= 2:
    # Bulk status update
    resp = client.post("/cases/bulk/status", json={"case_ids": case_ids[1:], "status": "in_progress"})
    test("Bulk status update", resp.status_code == 200, f"body={resp.text[:100]}")

    # Bulk assign (assign to first assignee if available)
    if assignees:
        assignee_id = assignees[0]["id"]
        resp = client.post("/cases/bulk/assign", json={"case_ids": case_ids, "assignee_id": assignee_id})
        test("Bulk assign", resp.status_code == 200, f"body={resp.text[:100]}")
    else:
        test("Bulk assign (skipped)", True, "no assignees available")

# 6. Export
print("\n6. Export")
resp = client.get("/cases/export", params={"format": "json"})
test("Export JSON", resp.status_code == 200, f"content_type={resp.headers.get('content-type', '')[:30]}")
if resp.status_code == 200:
    export_data = resp.json()
    test("Export JSON has cases", isinstance(export_data, list) and len(export_data) > 0, f"count={len(export_data)}")

resp = client.get("/cases/export", params={"format": "csv"})
test("Export CSV", resp.status_code == 200, f"content_type={resp.headers.get('content-type', '')[:30]}")
if resp.status_code == 200:
    lines = resp.text.strip().split("\n")
    test("CSV has header + rows", len(lines) > 1, f"lines={len(lines)}")

# Export specific IDs
if len(case_ids) >= 2:
    resp = client.get("/cases/export", params={"format": "json", "ids": ",".join(case_ids[:2])})
    test("Export JSON filtered by ids", resp.status_code == 200 and len(resp.json()) == 2, f"count={len(resp.json()) if resp.status_code == 200 else 'N/A'}")

# 7. Edit severity/TLP/tags via update
print("\n7. Edit severity/TLP/tags")
if len(case_ids) >= 3:
    cid = case_ids[2]
    resp = client.put(f"/cases/{cid}", json={"severity": "high", "tlp": "TLP:AMBER", "tags": ["updated-tag", "test"]})
    test("Update severity/TLP/tags", resp.status_code == 200, f"status={resp.status_code}")
    # Verify
    resp = client.get(f"/cases/{cid}")
    if resp.status_code == 200:
        d = resp.json()
        test("Severity updated", d.get("severity") == "high", f"got={d.get('severity')}")
        test("TLP updated", d.get("tlp") == "TLP:AMBER", f"got={d.get('tlp')}")
        test("Tags updated", "updated-tag" in d.get("tags", []), f"got={d.get('tags')}")

# 8. Bulk delete (cleanup)
print("\n8. Bulk delete")
if case_ids:
    resp = client.post("/cases/bulk/delete", json={"case_ids": case_ids})
    test("Bulk delete test cases", resp.status_code == 200, f"body={resp.text[:100]}")

# Summary
print(f"\n{'='*50}")
passed = sum(1 for _, s, _ in results if s == "PASS")
failed = sum(1 for _, s, _ in results if s == "FAIL")
print(f"Results: {passed} PASS, {failed} FAIL out of {len(results)}")
if failed > 0:
    print("\nFailed tests:")
    for name, status, detail in results:
        if status == "FAIL":
            print(f"  - {name}: {detail}")
print()
sys.exit(0 if failed == 0 else 1)
