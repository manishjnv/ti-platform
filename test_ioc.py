import asyncio, sys
sys.path.insert(0, '/app/api')
from app.core.database import async_session_factory
from app.services.graph import get_entity_graph, get_graph_stats

async def test():
    async with async_session_factory() as db:
        stats = await get_graph_stats(db)
        print('=== GRAPH STATS ===')
        print(stats)
        graph = await get_entity_graph(db, 'fdf6f6db-feeb-4b48-9bfd-c2ff6ef4b70c', 'ioc', depth=1)
        nodes = graph['nodes']
        edges = graph['edges']
        print('=== IOC GRAPH: %d nodes, %d edges ===' % (len(nodes), len(edges)))
        for n in nodes[:5]:
            print('  %s: %s' % (n['type'], n['label'][:60]))

asyncio.run(test())
