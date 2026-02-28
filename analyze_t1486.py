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

# Count KEV items with Ransomware: Known
cnt = s.execute(text(
    "SELECT COUNT(*) FROM intel_items "
    "WHERE source_name LIKE 'CISA%' "
    "AND (description LIKE '%Ransomware: Known%' OR summary LIKE '%Ransomware: Known%')"
)).scalar()
print(f"\nKEV items with 'Ransomware: Known': {cnt}")

# Count KEV items with just 'ransomware' anywhere
cnt2 = s.execute(text(
    "SELECT COUNT(*) FROM intel_items "
    "WHERE source_name LIKE 'CISA%' "
    "AND (LOWER(description) LIKE '%ransomware%' OR LOWER(summary) LIKE '%ransomware%')"
)).scalar()
print(f"KEV items with any 'ransomware': {cnt2}")

# Overall mapping stats
total_links = s.execute(text("SELECT COUNT(*) FROM intel_attack_links")).scalar()
unique_techniques = s.execute(text("SELECT COUNT(DISTINCT technique_id) FROM intel_attack_links")).scalar()
unique_items = s.execute(text("SELECT COUNT(DISTINCT intel_id) FROM intel_attack_links")).scalar()
total_items = s.execute(text("SELECT COUNT(*) FROM intel_items")).scalar()
print(f"\n=== Overall Mapping Stats ===")
print(f"  Total links: {total_links}")
print(f"  Unique techniques used: {unique_techniques}")
print(f"  Items with mappings: {unique_items}/{total_items} ({100*unique_items//total_items}%)")

s.close()
