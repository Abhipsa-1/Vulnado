"""
Real-time sync daemon for VULNADO.

Schedules automatic fetches from:
  • NVD 2.0 REST API  — every 2 hours  (incremental: last-sync → now)
  • MITRE ATT&CK      — every 24 hours (full refresh, filter by modified date)
  • GitHub Advisories — every 6 hours  (incremental: last-sync → now)

Each fetch:
  1. Calls the existing DataIngestion methods.
  2. Merges results into the HistoricalStore (dedup + append-only).
  3. Upserts new/updated records into Neo4j.
  4. Updates sync_state.json with timestamps + counts.

Runs as a background thread inside the Flask app process — no extra process needed.
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy imports — resolved at first sync, not at import time
# ---------------------------------------------------------------------------
_store = None
_ingestion = None
_neo4j_driver = None
_scheduler: Optional[BackgroundScheduler] = None
_lock = threading.Lock()


def _get_config():
    from VULNADO.config.configuration import get_config
    return get_config()


def _get_store():
    global _store
    if _store is None:
        from VULNADO.components.historical_store import HistoricalStore
        cfg = _get_config()
        hist_dir = Path(cfg.data.raw_dir).parent / "historical"
        _store = HistoricalStore(str(hist_dir))
        logger.info("HistoricalStore initialised at %s", hist_dir)
    return _store


def _get_ingestion():
    global _ingestion
    if _ingestion is None:
        from VULNADO.components.stage_00_data_ingestion import DataIngestion
        cfg = _get_config()
        _ingestion = DataIngestion(
            base_dir=cfg.data.cve_base_dir,
            extract_dir=cfg.data.cve_extract_dir,
            mitre_path=cfg.data.mitre_file,
            gsa_path=cfg.data.gsa_file,
        )
        logger.info("DataIngestion initialised")
    return _ingestion


def _get_neo4j():
    global _neo4j_driver
    if _neo4j_driver is None:
        try:
            from neo4j import GraphDatabase
            cfg = _get_config()
            ns = cfg.neo4j_service
            _neo4j_driver = GraphDatabase.driver(ns.uri, auth=(ns.username, ns.password))
            _neo4j_driver.verify_connectivity()
            logger.info("Neo4j driver ready for sync")
        except Exception as exc:
            logger.warning("Neo4j not reachable for sync: %s", exc)
            _neo4j_driver = None
    return _neo4j_driver


# ---------------------------------------------------------------------------
# Neo4j upsert helpers
# ---------------------------------------------------------------------------

def _neo4j_upsert_cves(records):
    driver = _get_neo4j()
    if not driver or not records:
        return
    query = """
    UNWIND $rows AS r
    MERGE (c:CVE {cve_id: r.cve_id})
    SET c.description      = r.description,
        c.severity         = r.severity,
        c.base_score       = r.base_score,
        c.attack_vector    = r.attack_vector,
        c.cvss_vector      = r.cvss_vector,
        c.published        = r.published,
        c.last_modified    = r.last_modified,
        c.vuln_status      = r.vuln_status,
        c.source           = r.source,
        c.last_synced      = r._last_seen
    """
    try:
        with driver.session() as session:
            # Batch in chunks of 500 to avoid memory spikes
            for i in range(0, len(records), 500):
                session.run(query, rows=records[i:i + 500])
        logger.info("Neo4j upserted %d CVE nodes", len(records))
    except Exception as exc:
        logger.error("Neo4j CVE upsert failed: %s", exc)


def _neo4j_upsert_mitre(records):
    driver = _get_neo4j()
    if not driver or not records:
        return
    query = """
    UNWIND $rows AS r
    MERGE (m:MITRE {technique_id: r.technique_id})
    SET m.technique_name   = r.technique_name,
        m.description      = r.description,
        m.tactics          = r.tactics,
        m.platforms        = r.platforms,
        m.is_subtechnique  = r.is_subtechnique,
        m.detection        = r.detection,
        m.url              = r.url,
        m.version          = r.version,
        m.modified         = r.modified,
        m.source           = r.source,
        m.last_synced      = r._last_seen
    """
    try:
        with driver.session() as session:
            for i in range(0, len(records), 500):
                session.run(query, rows=records[i:i + 500])
        logger.info("Neo4j upserted %d MITRE nodes", len(records))
    except Exception as exc:
        logger.error("Neo4j MITRE upsert failed: %s", exc)


def _neo4j_upsert_gsa(records):
    driver = _get_neo4j()
    if not driver or not records:
        return
    query = """
    UNWIND $rows AS r
    MERGE (g:GSA {ghsa_id: r.ghsa_id})
    SET g.cve_id              = r.cve_id,
        g.summary             = r.summary,
        g.description         = r.description,
        g.severity            = r.severity,
        g.package_name        = r.package,
        g.ecosystem           = r.ecosystem,
        g.vulnerable_versions = r.vulnerable_versions,
        g.fixed_version       = r.fixed_version,
        g.cvss_v3_score       = r.cvss_v3_score,
        g.published_at        = r.published_at,
        g.updated_at          = r.updated_at,
        g.source              = r.source,
        g.last_synced         = r._last_seen
    """
    try:
        with driver.session() as session:
            for i in range(0, len(records), 500):
                session.run(query, rows=records[i:i + 500])
        logger.info("Neo4j upserted %d GSA nodes", len(records))
    except Exception as exc:
        logger.error("Neo4j GSA upsert failed: %s", exc)


# ---------------------------------------------------------------------------
# Per-source sync jobs
# ---------------------------------------------------------------------------

def _last_sync_time(source: str) -> Optional[datetime]:
    """Return the UTC datetime of the last successful sync for a source, or None."""
    try:
        state = _get_store().load_sync_state()
        ts = state.get(source, {}).get("last_sync")
        if ts:
            return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return None


def sync_nvd():
    """Fetch new CVEs from NVD since last sync and store them."""
    with _lock:
        logger.info("[NVD] Starting sync...")
        error = None
        new_count = 0
        try:
            ingestion = _get_ingestion()
            store = _get_store()

            last = _last_sync_time("cve")
            now = datetime.now(timezone.utc)

            # First run: fetch last 7 days; subsequent: incremental from last sync
            if last is None:
                pub_start = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")
            else:
                # Overlap by 10 minutes to handle API lag
                pub_start = (last - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S.000")

            pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

            records = ingestion.fetch_cve_data(
                pub_start_date=pub_start,
                pub_end_date=pub_end,
            )

            if records:
                new_count, _ = store.merge("cve", records)
                # Upsert ALL incoming records to Neo4j (not just new — idempotent MERGE)
                _neo4j_upsert_cves(records)

            store.update_sync_state("cve", new_count)
            logger.info("[NVD] Sync complete — %d new records", new_count)

        except Exception as exc:
            error = str(exc)
            logger.error("[NVD] Sync failed: %s", exc)
            try:
                _get_store().update_sync_state("cve", 0, error=error)
            except Exception:
                pass


def sync_mitre():
    """Fetch MITRE ATT&CK (full refresh filtered by modified date) and store."""
    with _lock:
        logger.info("[MITRE] Starting sync...")
        error = None
        new_count = 0
        try:
            ingestion = _get_ingestion()
            store = _get_store()

            records = ingestion.fetch_mitre_attack_data()

            if records:
                new_count, _ = store.merge("mitre", records)
                _neo4j_upsert_mitre(records)

            store.update_sync_state("mitre", new_count)
            logger.info("[MITRE] Sync complete — %d new records", new_count)

        except Exception as exc:
            error = str(exc)
            logger.error("[MITRE] Sync failed: %s", exc)
            try:
                _get_store().update_sync_state("mitre", 0, error=error)
            except Exception:
                pass


def sync_gsa():
    """Fetch GitHub Security Advisories since last sync and store."""
    with _lock:
        logger.info("[GSA] Starting sync...")
        error = None
        new_count = 0
        try:
            ingestion = _get_ingestion()
            store = _get_store()

            records = ingestion.fetch_gsa_data()

            if records:
                new_count, _ = store.merge("gsa", records)
                _neo4j_upsert_gsa(records)

            store.update_sync_state("gsa", new_count)
            logger.info("[GSA] Sync complete — %d new records", new_count)

        except Exception as exc:
            error = str(exc)
            logger.error("[GSA] Sync failed: %s", exc)
            try:
                _get_store().update_sync_state("gsa", 0, error=error)
            except Exception:
                pass


def sync_all():
    """Run all three syncs sequentially. Used for manual trigger."""
    sync_nvd()
    sync_gsa()
    sync_mitre()


# ---------------------------------------------------------------------------
# Scheduler lifecycle
# ---------------------------------------------------------------------------

def start_scheduler():
    """
    Start the background sync scheduler.
    Call once at Flask app startup.

    Schedule:
      NVD   — every 2 hours
      GSA   — every 6 hours
      MITRE — every 24 hours
    """
    global _scheduler
    if _scheduler is not None:
        logger.warning("Scheduler already running")
        return

    _scheduler = BackgroundScheduler(
        job_defaults={"misfire_grace_time": 300, "coalesce": True},
        timezone="UTC",
    )

    _scheduler.add_job(
        sync_nvd,
        trigger=IntervalTrigger(hours=2),
        id="sync_nvd",
        name="NVD CVE sync",
        next_run_time=datetime.now(timezone.utc) + timedelta(seconds=30),  # first run 30s after boot
    )
    _scheduler.add_job(
        sync_gsa,
        trigger=IntervalTrigger(hours=6),
        id="sync_gsa",
        name="GitHub Advisory sync",
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=2),
    )
    _scheduler.add_job(
        sync_mitre,
        trigger=IntervalTrigger(hours=24),
        id="sync_mitre",
        name="MITRE ATT&CK sync",
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    _scheduler.start()
    logger.info(
        "Real-time sync scheduler started. "
        "NVD: 2h | GSA: 6h | MITRE: 24h"
    )


def stop_scheduler():
    """Gracefully stop the scheduler. Call on Flask app teardown."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Sync scheduler stopped")


def get_sync_status() -> dict:
    """
    Return current sync status for all sources.
    Used by the /api/status Flask endpoint.
    """
    try:
        store = _get_store()
        state = store.load_sync_state()
    except Exception:
        state = {}

    sources = {}
    for source in ("cve", "mitre", "gsa"):
        s = state.get(source, {})
        sources[source] = {
            "last_sync":        s.get("last_sync"),
            "last_new_records": s.get("last_new_records", 0),
            "total_records":    s.get("total_records", 0),
            "error":            s.get("error"),
        }

    next_runs = {}
    if _scheduler and _scheduler.running:
        for job in _scheduler.get_jobs():
            nr = job.next_run_time
            next_runs[job.id] = nr.isoformat() if nr else None

    return {
        "scheduler_running": _scheduler is not None and _scheduler.running,
        "sources": sources,
        "next_runs": next_runs,
    }
