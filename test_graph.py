import asyncio, json
from app.core.database import async_session_factory
from app.services.graph import get_graph_stats, get_entity_graph, get_related_intel

TEST_ID = "0e7df68b-c22e-455f-853c-ab64c7992818"  # Most connected: KEV CVE-2017-0213

async def test():
    async with async_session_factory() as db:
        # Test 1: Stats
        stats = await get_graph_stats(db)
        print("=== STATS ===")
        print(json.dumps(stats, indent=2))

        # Test 2: Explore graph — depth 1
        graph1 = await get_entity_graph(db, TEST_ID, "intel", depth=1, limit=50)
        print("\n=== GRAPH EXPLORE (depth=1) ===")
        print(f"Nodes: {len(graph1['nodes'])}, Edges: {len(graph1['edges'])}")
        types = {}
        for n in graph1["nodes"]:
            types[n["type"]] = types.get(n["type"], 0) + 1
        print(f"Node types: {types}")
        edge_types = {}
        for e in graph1["edges"]:
            edge_types[e["type"]] = edge_types.get(e["type"], 0) + 1
        print(f"Edge types: {edge_types}")
        print("Sample nodes:")
        for n in graph1["nodes"][:5]:
            print(f"  [{n['type']}] {n['label'][:65]} (risk={n.get('risk_score', '-')})")

        # Test 3: Explore graph — depth 2
        graph2 = await get_entity_graph(db, TEST_ID, "intel", depth=2, limit=100)
        print(f"\n=== GRAPH EXPLORE (depth=2) ===")
        print(f"Nodes: {len(graph2['nodes'])}, Edges: {len(graph2['edges'])}")

        # Test 4: Related intel
        related = await get_related_intel(db, TEST_ID, limit=10)
        print(f"\n=== RELATED INTEL ({len(related)} items) ===")
        for r in related[:5]:
            print(f"  [{r['severity']}] {r['title'][:55]} | {r['relationship_type']} | {r['confidence']}%")

asyncio.run(test())
