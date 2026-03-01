"""Test the Investigate module API endpoints."""
import httpx
import asyncio
from app.services.auth import create_session
from app.core.database import async_session_factory
from sqlalchemy import text


async def main():
    async with async_session_factory() as db:
        result = await db.execute(
            text("SELECT id, email, role, name FROM users WHERE email='admin@intelwatch.local'")
        )
        row = result.fetchone()
        if not row:
            print("No admin user found")
            return

        class FakeUser:
            pass

        u = FakeUser()
        u.id = row[0]
        u.email = row[1]
        u.role = row[2]
        u.name = row[3]

        token = await create_session(u)
        cookies = {"iw_session": token}
        base = "http://localhost:8000/api/v1"

        # 1. Test graph stats
        r = httpx.get(f"{base}/graph/stats", cookies=cookies)
        print(f"[1] graph/stats: {r.status_code} {r.text[:500]}")

        # 2. Test graph explore with high-relationship item
        r2 = httpx.get(
            f"{base}/graph/explore",
            params={
                "entity_id": "06350353-b704-4e71-a652-955a30e68156",
                "entity_type": "intel",
                "depth": 2,
                "limit": 50,
            },
            cookies=cookies,
            timeout=30,
        )
        data = r2.json()
        print(f"[2] graph/explore: {r2.status_code}")
        print(f"    Nodes: {data.get('total_nodes', 0)}, Edges: {data.get('total_edges', 0)}")
        if data.get("nodes"):
            for n in data["nodes"][:5]:
                print(f"    Node: {n['type']:12s} | {n.get('label', '')[:60]}")
        if data.get("edges"):
            for e in data["edges"][:5]:
                print(f"    Edge: {e['type']:20s} | confidence: {e.get('confidence')}")

        # 3. Test graph explore for IOC type
        r3 = httpx.get(
            f"{base}/graph/explore",
            params={"entity_id": "malware", "entity_type": "ioc", "depth": 1, "limit": 20},
            cookies=cookies,
            timeout=30,
        )
        print(f"[3] graph/explore (ioc): {r3.status_code} {r3.text[:300]}")

        # 4. Test graph explore for technique type
        r4 = httpx.get(
            f"{base}/graph/explore",
            params={"entity_id": "T1059", "entity_type": "technique", "depth": 1, "limit": 20},
            cookies=cookies,
            timeout=30,
        )
        print(f"[4] graph/explore (technique): {r4.status_code} {r4.text[:300]}")

        # 5. Test UI page loads
        r5 = httpx.get("http://localhost:3000/investigate", cookies=cookies, timeout=10, follow_redirects=True)
        print(f"[5] UI /investigate page: {r5.status_code} (len={len(r5.text)})")


asyncio.run(main())
