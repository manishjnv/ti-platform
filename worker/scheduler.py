"""RQ Scheduler configuration — schedules periodic feed ingestion jobs."""

import sys
import os

api_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "api")
if api_dir not in sys.path:
    sys.path.insert(0, api_dir)
app_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
if app_dir not in sys.path:
    sys.path.insert(0, app_dir)

from datetime import timedelta, datetime, timezone

from redis import Redis
from rq import Queue
from rq_scheduler import Scheduler

from app.core.config import get_settings
from app.core.logging import setup_logging

setup_logging()
settings = get_settings()

redis_conn = Redis.from_url(settings.redis_url)
scheduler = Scheduler(queue_name="default", connection=redis_conn)


def setup_schedules():
    """Register all periodic jobs. Idempotent — cancels existing first."""
    # Cancel existing scheduled jobs to avoid duplicates
    for job in scheduler.get_jobs():
        scheduler.cancel(job)

    # ─── Feed Ingestion Schedules ─────────────────────────
    # CISA KEV — every 5 minutes
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.ingest_feed",
        args=["cisa_kev"],
        interval=timedelta(minutes=5).total_seconds(),
        queue_name="high",
        meta={"feed": "cisa_kev"},
    )

    # NVD — every 15 minutes
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.ingest_feed",
        args=["nvd"],
        interval=timedelta(minutes=15).total_seconds(),
        queue_name="default",
        meta={"feed": "nvd"},
    )

    # URLhaus — every 5 minutes
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.ingest_feed",
        args=["urlhaus"],
        interval=timedelta(minutes=5).total_seconds(),
        queue_name="high",
        meta={"feed": "urlhaus"},
    )

    # AbuseIPDB — every 15 minutes
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.ingest_feed",
        args=["abuseipdb"],
        interval=timedelta(minutes=15).total_seconds(),
        queue_name="default",
        meta={"feed": "abuseipdb"},
    )

    # OTX — every 30 minutes (to respect API limits)
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.ingest_feed",
        args=["otx"],
        interval=timedelta(minutes=30).total_seconds(),
        queue_name="low",
        meta={"feed": "otx"},
    )

    # VirusTotal — every 15 minutes (free tier: 500 req/day)
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.ingest_feed",
        args=["virustotal"],
        interval=timedelta(minutes=15).total_seconds(),
        queue_name="default",
        meta={"feed": "virustotal"},
    )

    # Shodan — every 30 minutes (free tier: 1 req/sec)
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.ingest_feed",
        args=["shodan"],
        interval=timedelta(minutes=30).total_seconds(),
        queue_name="low",
        meta={"feed": "shodan"},
    )

    # ─── Dashboard refresh — every 2 minutes ─────────────
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.refresh_materialized_views",
        interval=timedelta(minutes=2).total_seconds(),
        queue_name="low",
    )

    # ─── AI Summaries — every 5 minutes ──────────────────
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.generate_ai_summaries",
        kwargs={"batch_size": 5},
        interval=timedelta(minutes=5).total_seconds(),
        queue_name="low",
    )

    # ─── MITRE ATT&CK Sync — every 24 hours ─────────────
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.sync_attack_techniques",
        interval=timedelta(hours=24).total_seconds(),
        queue_name="low",
        meta={"task": "attack_sync"},
    )

    # ─── ATT&CK Auto-Mapping — every 10 minutes ─────────
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc) + timedelta(minutes=2),  # delay to let sync run first
        func="worker.tasks.map_intel_to_attack",
        kwargs={"batch_size": 100},
        interval=timedelta(minutes=10).total_seconds(),
        queue_name="low",
        meta={"task": "attack_mapping"},
    )

    # ─── Relationship Graph Builder — every 15 minutes ───
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc) + timedelta(minutes=3),
        func="worker.tasks.build_relationships",
        kwargs={"batch_size": 300},
        interval=timedelta(minutes=15).total_seconds(),
        queue_name="low",
        meta={"task": "relationship_builder"},
    )

    print(f"Scheduled {len(list(scheduler.get_jobs()))} jobs")


if __name__ == "__main__":
    setup_schedules()
    scheduler.run()
