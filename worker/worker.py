"""RQ Worker entry point."""

import sys
import os

# Add api directory to path so worker can import app modules
# This is a no-op when PYTHONPATH is set correctly in Docker
api_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "api")
if api_dir not in sys.path:
    sys.path.insert(0, api_dir)
# Also ensure the parent of worker/ is on the path for RQ to resolve worker.tasks
app_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

from redis import Redis
from rq import Worker, Queue

from app.core.config import get_settings
from app.core.logging import setup_logging

setup_logging()
settings = get_settings()

redis_conn = Redis.from_url(settings.redis_url)

QUEUES = ["high", "default", "low"]


def run_worker():
    queues = [Queue(name, connection=redis_conn) for name in QUEUES]
    worker = Worker(queues, connection=redis_conn)
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    run_worker()
