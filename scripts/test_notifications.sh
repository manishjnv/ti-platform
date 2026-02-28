#!/bin/bash
# Phase 1.3 Notification & Alerting – API Integration Tests
set -e

BASE='http://localhost:8000/api/v1'
AUTH='cf-access-authenticated-user-email: dev@intelwatch.local'
PASS=0
FAIL=0

ok()   { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

echo "========================================"
echo "  Notification API Integration Tests"
echo "========================================"
echo ""

# ── Test 1: List notifications ──
echo "Test 1: List Notifications"
RESP=$(curl -sf -H "$AUTH" "$BASE/notifications?limit=10")
TOTAL=$(echo "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["total"])')
if [ "$TOTAL" -ge 0 ] 2>/dev/null; then
    ok "Listed $TOTAL notifications"
else
    fail "Could not list notifications"
fi

# ── Test 2: Unread count ──
echo "Test 2: Unread Count"
UNREAD=$(curl -sf -H "$AUTH" "$BASE/notifications/unread-count" | python3 -c 'import sys,json; print(json.load(sys.stdin)["unread_count"])')
if [ "$UNREAD" -ge 0 ] 2>/dev/null; then
    ok "Unread count: $UNREAD"
else
    fail "Could not get unread count"
fi

# ── Test 3: Notification stats ──
echo "Test 3: Notification Stats"
STATS=$(curl -sf -H "$AUTH" "$BASE/notifications/stats")
LAST24=$(echo "$STATS" | python3 -c 'import sys,json; print(json.load(sys.stdin)["last_24h_total"])')
if [ "$LAST24" -ge 0 ] 2>/dev/null; then
    ok "Stats returned (last_24h=$LAST24)"
else
    fail "Could not get stats"
fi

# ── Test 4: List rules ──
echo "Test 4: List Rules"
RULES=$(curl -sf -H "$AUTH" "$BASE/notifications/rules")
RULE_COUNT=$(echo "$RULES" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')
if [ "$RULE_COUNT" -ge 4 ] 2>/dev/null; then
    ok "Found $RULE_COUNT rules (4 system expected)"
else
    fail "Expected at least 4 rules, got $RULE_COUNT"
fi

# ── Test 5: System rules correctness ──
echo "Test 5: System Rules Correctness"
SYSTEM_NAMES=$(echo "$RULES" | python3 -c '
import sys,json
rules = json.load(sys.stdin)
system = [r for r in rules if r["is_system"]]
names = sorted([r["name"] for r in system])
expected = sorted(["Critical/High Severity Alert","CISA KEV Alert","Feed Health Watchdog","Risk Score Spike"])
if names == expected:
    print("MATCH")
else:
    print(f"MISMATCH: got {names}")
')
if [ "$SYSTEM_NAMES" = "MATCH" ]; then
    ok "All 4 system rules present with correct names"
else
    fail "$SYSTEM_NAMES"
fi

# ── Test 6: Create custom rule ──
echo "Test 6: Create Custom Rule"
CREATE_RESP=$(curl -sf -X POST -H 'Content-Type: application/json' -H "$AUTH" \
    -d '{"name":"Test CVE Watch","description":"Unit test rule","rule_type":"threshold","conditions":{"severity":["critical"],"min_risk_score":80},"cooldown_minutes":10}' \
    "$BASE/notifications/rules")
CUSTOM_ID=$(echo "$CREATE_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))')
if [ -n "$CUSTOM_ID" ] && [ "$CUSTOM_ID" != "None" ]; then
    ok "Created custom rule: $CUSTOM_ID"
else
    fail "Could not create custom rule"
    CUSTOM_ID=""
fi

# ── Test 7: Toggle custom rule ──
echo "Test 7: Toggle Rule"
if [ -n "$CUSTOM_ID" ]; then
    TOGGLE_RESP=$(curl -sf -X POST -H "$AUTH" "$BASE/notifications/rules/$CUSTOM_ID/toggle")
    ACTIVE=$(echo "$TOGGLE_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("is_active",""))')
    if [ "$ACTIVE" = "False" ]; then
        ok "Rule toggled to inactive"
    else
        fail "Expected inactive after toggle, got is_active=$ACTIVE"
    fi
else
    fail "Skipped (no custom rule)"
fi

# ── Test 8: Update custom rule ──
echo "Test 8: Update Rule"
if [ -n "$CUSTOM_ID" ]; then
    UPDATE_RESP=$(curl -sf -X PUT -H 'Content-Type: application/json' -H "$AUTH" \
        -d '{"name":"Updated CVE Watch","cooldown_minutes":30}' \
        "$BASE/notifications/rules/$CUSTOM_ID")
    UPD_NAME=$(echo "$UPDATE_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("name",""))')
    if [ "$UPD_NAME" = "Updated CVE Watch" ]; then
        ok "Rule updated successfully"
    else
        fail "Expected name 'Updated CVE Watch', got '$UPD_NAME'"
    fi
else
    fail "Skipped (no custom rule)"
fi

# ── Test 9: Delete custom rule ──
echo "Test 9: Delete Custom Rule"
if [ -n "$CUSTOM_ID" ]; then
    DEL_RESP=$(curl -sf -X DELETE -H "$AUTH" "$BASE/notifications/rules/$CUSTOM_ID")
    DEL_OK=$(echo "$DEL_RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); print("ok" if d.get("ok") or "deleted" in str(d).lower() else "fail")')
    if [ "$DEL_OK" = "ok" ]; then
        ok "Custom rule deleted"
    else
        fail "Delete returned: $DEL_RESP"
    fi
else
    fail "Skipped (no custom rule)"
fi

# ── Test 10: Verify rule count back to original ──
echo "Test 10: Verify Rule Count After Delete"
RULES_AFTER=$(curl -sf -H "$AUTH" "$BASE/notifications/rules")
COUNT_AFTER=$(echo "$RULES_AFTER" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')
if [ "$COUNT_AFTER" -eq "$RULE_COUNT" ] 2>/dev/null; then
    ok "Rule count back to $COUNT_AFTER"
else
    fail "Expected $RULE_COUNT rules, got $COUNT_AFTER"
fi

# ── Test 11: Mark read ──
echo "Test 11: Mark Notification Read"
FIRST_NOTIF=$(curl -sf -H "$AUTH" "$BASE/notifications?limit=1" | python3 -c 'import sys,json; ns=json.load(sys.stdin)["notifications"]; print(ns[0]["id"] if ns else "")')
if [ -n "$FIRST_NOTIF" ]; then
    MR_RESP=$(curl -sf -X POST -H 'Content-Type: application/json' -H "$AUTH" \
        -d "{\"notification_ids\":[\"$FIRST_NOTIF\"]}" \
        "$BASE/notifications/mark-read")
    MARKED=$(echo "$MR_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("marked",0))')
    if [ "$MARKED" -ge 1 ] 2>/dev/null; then
        ok "Marked 1 notification as read"
    else
        fail "Mark-read response: $MR_RESP"
    fi
else
    fail "No notifications to mark read"
fi

# ── Test 12: Mark all read ──
echo "Test 12: Mark All Read"
MA_RESP=$(curl -sf -X POST -H "$AUTH" "$BASE/notifications/mark-all-read")
MA_MARKED=$(echo "$MA_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("marked",0))')
if [ "$MA_MARKED" -ge 0 ] 2>/dev/null; then
    ok "Marked all as read ($MA_MARKED)"
else
    fail "Mark-all-read response: $MA_RESP"
fi

# ── Test 13: Unread = 0 after mark-all ──
echo "Test 13: Unread Count = 0"
FINAL_UNREAD=$(curl -sf -H "$AUTH" "$BASE/notifications/unread-count" | python3 -c 'import sys,json; print(json.load(sys.stdin)["unread_count"])')
if [ "$FINAL_UNREAD" -eq 0 ] 2>/dev/null; then
    ok "Unread count is 0 after mark-all-read"
else
    fail "Expected 0 unread, got $FINAL_UNREAD"
fi

# ── Test 14: Cannot delete system rule ──
echo "Test 14: Cannot Delete System Rule"
SYS_RULE=$(echo "$RULES" | python3 -c 'import sys,json; rules=json.load(sys.stdin); sys_rules=[r for r in rules if r["is_system"]]; print(sys_rules[0]["id"])')
DEL_SYS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE -H "$AUTH" "$BASE/notifications/rules/$SYS_RULE")
if [ "$DEL_SYS" -ge 400 ] 2>/dev/null; then
    ok "System rule deletion blocked (HTTP $DEL_SYS)"
else
    fail "Expected 4xx for system rule delete, got $DEL_SYS"
fi

# ── Test 15: Notification metadata integrity ──
echo "Test 15: Notification Metadata Integrity"
META_CHECK=$(curl -sf -H "$AUTH" "$BASE/notifications?limit=5" | python3 -c '
import sys,json
data = json.load(sys.stdin)
for n in data["notifications"]:
    m = n.get("metadata", {})
    if not isinstance(m, dict):
        print("FAIL: metadata not a dict")
        sys.exit(0)
    if n["category"] == "alert" and "risk_score" not in m and "top_risk_score" not in m:
        print("FAIL: alert missing risk_score/top_risk_score in metadata")
        sys.exit(0)
    if n["category"] == "feed_error" and "feed_name" not in m:
        print("FAIL: feed_error missing feed_name in metadata")
        sys.exit(0)
print("OK")
')
if [ "$META_CHECK" = "OK" ]; then
    ok "All notification metadata has required fields"
else
    fail "$META_CHECK"
fi

# ── Test 16: Notification schema completeness ──
echo "Test 16: Schema Completeness"
SCHEMA_CHECK=$(curl -sf -H "$AUTH" "$BASE/notifications?limit=1" | python3 -c '
import sys,json
data = json.load(sys.stdin)
required = ["id","user_id","title","message","severity","category","metadata","is_read","created_at"]
for n in data["notifications"]:
    for field in required:
        if field not in n:
            print(f"FAIL: missing field {field}")
            sys.exit(0)
print("OK")
')
if [ "$SCHEMA_CHECK" = "OK" ]; then
    ok "All required fields present in notification schema"
else
    fail "$SCHEMA_CHECK"
fi

# ── Summary ──
echo ""
echo "========================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================"
