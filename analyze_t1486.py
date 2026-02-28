"""Analyze T1486 mapping to verify accuracy."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from worker.tasks import SyncSession
from sqlalchemy import text

s = SyncSession()

# Source distribution for T1486
rows = s.execute(text(
    "SELECT source_name, COUNT(*) c "
    "FROM intel_items i JOIN intel_attack_links l ON i.id=l.intel_id "
    "WHERE l.technique_id = 'T1486' GROUP BY source_name ORDER BY c DESC"
)).fetchall()
print("=== T1486 by source ===")
for r in rows:
    print(f"  {r[0]}: {r[1]}")

# Sample titles of T1486-mapped items
rows = s.execute(text(
    "SELECT LEFT(i.title, 100), i.source_name "
    "FROM intel_items i JOIN intel_attack_links l ON i.id=l.intel_id "
    "WHERE l.technique_id = 'T1486' ORDER BY random() LIMIT 10"
)).fetchall()
print("\n=== Sample T1486 items (random 10) ===")
for r in rows:
    print(f"  [{r[1]}] {r[0]}")

# Check which keyword actually matched
from app.services.mitre import _COMPILED_PATTERNS
rows = s.execute(text(
    "SELECT i.title, i.description, i.summary "
    "FROM intel_items i JOIN intel_attack_links l ON i.id=l.intel_id "
    "WHERE l.technique_id = 'T1486' LIMIT 5"
)).fetchall()
print("\n=== Keyword analysis for 5 items ===")
for r in rows:
    combined = f"{r[0] or ''} {r[2] or ''} {r[1] or ''}"
    for pat, tids in _COMPILED_PATTERNS:
        if "T1486" in tids and pat.search(combined):
            print(f"  Matched keyword pattern: {pat.pattern}")
            match = pat.search(combined)
            start = max(0, match.start() - 20)
            end = min(len(combined), match.end() + 20)
            print(f"    Context: ...{combined[start:end]}...")
            break

s.close()
