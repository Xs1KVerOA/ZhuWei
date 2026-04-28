from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from .analysis import cleanup_expired_source_artifacts_sync
from .config import settings
from .deepseek import refresh_deepseek_balance_sync
from .enrichment import backfill_missing_cvss_sync
from .services import source_service


scheduler = BackgroundScheduler(timezone=settings.scheduler_timezone)


def configure_scheduler() -> None:
    scheduler.add_job(
        source_service.run_category_sync,
        IntervalTrigger(minutes=settings.regular_interval_minutes),
        args=["regular"],
        id="regular_sources",
        name="Regular sources every 30 minutes",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        source_service.run_category_sync,
        CronTrigger(hour=settings.slow_cron_hours, minute=0, timezone=settings.scheduler_timezone),
        args=["slow"],
        id="slow_sources",
        name="Slow sources daily at 10:00 and 18:00",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        refresh_deepseek_balance_sync,
        IntervalTrigger(minutes=settings.deepseek_balance_interval_minutes),
        id="deepseek_balance",
        name=f"DeepSeek balance every {settings.deepseek_balance_interval_minutes} minutes",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        backfill_missing_cvss_sync,
        IntervalTrigger(minutes=30),
        id="nvd_cvss_backfill",
        name="NVD CVSS backfill every 30 minutes",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        cleanup_expired_source_artifacts_sync,
        IntervalTrigger(hours=6),
        id="analysis_source_retention_cleanup",
        name="Analysis source retention cleanup every 6 hours",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )


def start_scheduler() -> None:
    configure_scheduler()
    if not scheduler.running:
        scheduler.start()


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)


def list_jobs() -> list[dict]:
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append(
            {
                "id": job.id,
                "name": job.name,
                "next_run_time": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger),
            }
        )
    return jobs
