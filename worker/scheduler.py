"""RQ Scheduler configuration — schedules periodic feed ingestion jobs.

Includes a self-healing watchdog that periodically verifies all expected
jobs exist in Redis and re-registers them if any go missing (prevents the
silent-death scenario where a Redis flush or race condition leaves 0 jobs).
"""

import atexit
import signal
import sys
import os
import threading
import time

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

# ── Constants ────────────────────────────────────────────
EXPECTED_JOB_COUNT = 15          # total scheduled jobs we register
WATCHDOG_INTERVAL = 120          # seconds between health checks
HEARTBEAT_KEY = "scheduler:heartbeat"
HEARTBEAT_TTL = 300              # seconds — expires if scheduler dies


_shutdown = threading.Event()


def _cleanup_on_exit(*args):
    """Signal the watchdog to stop and log shutdown."""
    _shutdown.set()
    print("Scheduler shutting down")


# Register cleanup for normal exit and SIGTERM (docker stop)
atexit.register(_cleanup_on_exit)


def _handle_sigterm(signum, frame):
    """Handle SIGTERM from docker stop — cleanup then exit."""
    _cleanup_on_exit()
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_sigterm)


# ── Heartbeat ────────────────────────────────────────────

def _write_heartbeat():
    """Write a Redis key proving the scheduler is alive."""
    try:
        redis_conn.set(
            HEARTBEAT_KEY,
            datetime.now(timezone.utc).isoformat(),
            ex=HEARTBEAT_TTL,
        )
    except Exception:
        pass  # non-fatal


# ── Self-healing Watchdog ────────────────────────────────

def _watchdog_loop():
    """Background thread: every WATCHDOG_INTERVAL seconds, verify that the
    expected number of jobs exist in Redis.  If jobs have disappeared
    (Redis flush, bug, race condition), re-register them automatically.
    """
    print(f"Watchdog started — checking every {WATCHDOG_INTERVAL}s for {EXPECTED_JOB_COUNT} jobs")
    while not _shutdown.is_set():
        _shutdown.wait(WATCHDOG_INTERVAL)
        if _shutdown.is_set():
            break
        try:
            _write_heartbeat()
            current = list(scheduler.get_jobs())
            if len(current) < EXPECTED_JOB_COUNT:
                print(
                    f"WATCHDOG: only {len(current)}/{EXPECTED_JOB_COUNT} jobs in Redis — "
                    f"re-registering all schedules"
                )
                setup_schedules()
            else:
                # Periodic health log (every check)
                pass
        except Exception as e:
            print(f"WATCHDOG error: {e}")
    print("Watchdog stopped")


def setup_schedules():
    """Register all periodic jobs. Idempotent — cancels existing first."""
    # Cancel existing scheduled jobs to avoid duplicates
    for job in scheduler.get_jobs():
        scheduler.cancel(job)

    # ─── Feed Ingestion Schedules ─────────────────────────
    # CISA KEV — every 60 minutes (public feed, updates ~1x/day)
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.ingest_feed",
        args=["cisa_kev"],
        interval=timedelta(minutes=60).total_seconds(),
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

    # URLhaus — every 30 minutes (public feed, reasonable polling)
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.ingest_feed",
        args=["urlhaus"],
        interval=timedelta(minutes=30).total_seconds(),
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

    # VirusTotal — every 60 minutes (free tier: 500 req/day, 4 req/min)
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.ingest_feed",
        args=["virustotal"],
        interval=timedelta(minutes=60).total_seconds(),
        queue_name="default",
        meta={"feed": "virustotal"},
    )

    # Shodan — every 12 hours (free tier: ~100 credits/month ≈ 3/day)
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc),
        func="worker.tasks.ingest_feed",
        args=["shodan"],
        interval=timedelta(hours=12).total_seconds(),
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

    # ─── IOC Extraction — every 10 minutes ───────────────
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc) + timedelta(minutes=1),
        func="worker.tasks.extract_iocs",
        kwargs={"batch_size": 500},
        interval=timedelta(minutes=10).total_seconds(),
        queue_name="low",
        meta={"task": "ioc_extraction"},
    )

    # ─── Notification Rule Evaluation — every 5 minutes ──
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc) + timedelta(minutes=2),
        func="worker.tasks.evaluate_notification_rules",
        kwargs={"lookback_minutes": 10},
        interval=timedelta(minutes=5).total_seconds(),
        queue_name="low",
        meta={"task": "notification_eval"},
    )

    # ─── IPinfo IP Enrichment — every 10 minutes ────────
    scheduler.schedule(
        scheduled_time=datetime.now(timezone.utc) + timedelta(minutes=3),
        func="worker.tasks.enrich_ips_ipinfo",
        kwargs={"batch_size": 100},
        interval=timedelta(minutes=10).total_seconds(),
        queue_name="low",
        meta={"task": "ipinfo_enrichment"},
    )

    print(f"Scheduled {len(list(scheduler.get_jobs()))} jobs")

    # Log each registered job for debugging
    for job in scheduler.get_jobs():
        func_name = getattr(job, "func_name", "?")
        meta = getattr(job, "meta", {})
        label = meta.get("task") or meta.get("feed") or func_name
        print(f"  → {label} ({func_name})")

    # Write initial heartbeat
    _write_heartbeat()


if __name__ == "__main__":
    setup_schedules()

    # Start self-healing watchdog in background thread
    watchdog = threading.Thread(target=_watchdog_loop, daemon=True, name="scheduler-watchdog")
    watchdog.start()

    scheduler.run()
