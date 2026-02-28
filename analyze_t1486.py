"""Analyze T1486 mapping to verify accuracy."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from worker.tasks import SyncSession
from sqlalchemy import text

s = SyncSession()

# Check tags of KEV items mapped to T1486
rows = s.execute(text(
    "SELECT i.tags, LEFT(i.title, 80) "
    "FROM intel_items i JOIN intel_attack_links l ON i.id=l.intel_id "
    "WHERE l.technique_id = 'T1486' AND i.source_name LIKE 'CISA%' "
    "ORDER BY random() LIMIT 5"
)).fetchall()
print("=== Tags of T1486-mapped KEV items ===")
for r in rows:
    print(f"  Tags: {r[0]}")
    print(f"  Title: {r[1]}")
    print()

# Check how many KEV items have ransomware in tags
cnt = s.execute(text(
    "SELECT COUNT(*) FROM intel_items "
    "WHERE source_name LIKE 'CISA%' AND tags::text LIKE '%ransomware%'"
)).scalar()
print(f"KEV items with 'ransomware' in tags: {cnt}")

# Overall mapping stats
total_links = s.execute(text("SELECT COUNT(*) FROM intel_attack_links")).scalar()
unique_techniques = s.execute(text("SELECT COUNT(DISTINCT technique_id) FROM intel_attack_links")).scalar()
unique_items = s.execute(text("SELECT COUNT(DISTINCT intel_id) FROM intel_attack_links")).scalar()
total_items = s.execute(text("SELECT COUNT(*) FROM intel_items")).scalar()
print(f"\n=== Overall Mapping Stats ===")
print(f"  Total links: {total_links}")
print(f"  Unique techniques used: {unique_techniques}")
print(f"  Items with mappings: {unique_items}/{total_items} ({100*unique_items//total_items}%)")

# Distribution top 10
rows = s.execute(text(
    "SELECT technique_id, COUNT(*) c FROM intel_attack_links "
    "GROUP BY technique_id ORDER BY c DESC LIMIT 10"
)).fetchall()
print(f"\n=== Top technique distribution ===")
for r in rows:
    print(f"  {r[0]}: {r[1]}")

s.close()
