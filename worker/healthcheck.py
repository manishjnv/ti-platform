#!/usr/bin/env python3
"""Docker healthcheck for the scheduler container.

Exits 0 (healthy) if the expected number of scheduled jobs exist in Redis
and the heartbeat key is fresh. Exits 1 (unhealthy) otherwise.

Docker will auto-restart the container after consecutive failures.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from redis import Redis
from rq_scheduler import Scheduler
from app.core.config import get_settings

EXPECTED_JOBS = 14

try:
    settings = get_settings()
    r = Redis.from_url(settings.redis_url)

    # 1. Check heartbeat exists (proves scheduler loop is alive)
    heartbeat = r.get("scheduler:heartbeat")
    if not heartbeat:
        print(f"UNHEALTHY: no scheduler heartbeat in Redis")
        sys.exit(1)

    # 2. Check job count
    s = Scheduler(queue_name="default", connection=r)
    jobs = list(s.get_jobs())
    if len(jobs) < EXPECTED_JOBS:
        print(f"UNHEALTHY: {len(jobs)}/{EXPECTED_JOBS} jobs in Redis")
        sys.exit(1)

    print(f"HEALTHY: {len(jobs)} jobs, heartbeat OK")
    sys.exit(0)

except Exception as e:
    print(f"UNHEALTHY: {e}")
    sys.exit(1)
