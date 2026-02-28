import asyncio, json
from app.core.database import async_session
from app.services.graph import get_graph_stats, get_entity_graph, get_related_intel

async def test():
    async with async_session() as db:
        # Test 1: Stats
        stats = await get_graph_stats(db)
        print("=== STATS ===")
        print(json.dumps(stats, indent=2))

        # Test 2: Explore graph for a specific intel item
        graph = await get_entity_graph(db, "4c06d43e-e4f2-475a-b429-c067a800c359", "intel", depth=2, limit=50)
        print("=== GRAPH EXPLORE ===")
        nodes = graph["nodes"]
        edges = graph["edges"]
        print(f"Nodes: {len(nodes)}, Edges: {len(edges)}")
        for n in nodes[:5]:
            print(f"  Node: {n['type']} - {n['label'][:60]}")
        for e in edges[:5]:
            print(f"  Edge: {e['type']} conf={e['confidence']}")

        # Test 3: Related intel
        related = await get_related_intel(db, "4c06d43e-e4f2-475a-b429-c067a800c359", limit=10)
        print("=== RELATED INTEL ===")
        print(f"Found {len(related)} related items")
        for r in related[:5]:
            print(f"  {r['title'][:60]} | {r['relationship_type']} | conf={r['confidence']}")

asyncio.run(test())
