"""
Historical Store — append-only, deduplicated persistent storage for CVE/MITRE/GSA records.

Layout on disk:
  data/historical/
    cve/
      cve_YYYY-MM-DD.json     ← one file per day ingested
      cve_index.json          ← {cve_id: {first_seen, last_seen, file}}
    mitre/
      mitre_YYYY-MM-DD.json
      mitre_index.json        ← {technique_id: {first_seen, last_seen, file}}
    gsa/
      gsa_YYYY-MM-DD.json
      gsa_index.json          ← {ghsa_id: {first_seen, last_seen, file}}
    sync_state.json           ← last successful sync timestamps + record counts
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

_INDEX_FILES = {
    "cve":   "cve_index.json",
    "mitre": "mitre_index.json",
    "gsa":   "gsa_index.json",
}

_ID_FIELDS = {
    "cve":   "cve_id",
    "mitre": "technique_id",
    "gsa":   "ghsa_id",
}

SYNC_STATE_FILE = "sync_state.json"


class HistoricalStore:
    """Append-only deduplicating store for vulnerability intelligence records."""

    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        for source in ("cve", "mitre", "gsa"):
            (self.base_dir / source).mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _index_path(self, source: str) -> Path:
        return self.base_dir / source / _INDEX_FILES[source]

    def _load_index(self, source: str) -> Dict:
        p = self._index_path(source)
        if p.exists():
            with open(p) as f:
                return json.load(f)
        return {}

    def _save_index(self, source: str, index: Dict):
        with open(self._index_path(source), "w") as f:
            json.dump(index, f, separators=(",", ":"))

    def _daily_file(self, source: str, date_str: str) -> Path:
        return self.base_dir / source / f"{source}_{date_str}.json"

    def _load_daily(self, path: Path) -> List[Dict]:
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return []

    def _save_daily(self, path: Path, records: List[Dict]):
        with open(path, "w") as f:
            json.dump(records, f, separators=(",", ":"))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def merge(self, source: str, incoming: List[Dict]) -> Tuple[int, int]:
        """
        Merge a batch of incoming records into the historical store.

        New records are written to today's daily file.
        Existing records (same ID) have their `last_seen` updated in the index
        but the payload is NOT re-written (historical immutability).

        Returns:
            (new_count, updated_count)
        """
        id_field = _ID_FIELDS[source]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        now_iso = datetime.now(timezone.utc).isoformat()

        index = self._load_index(source)
        daily_path = self._daily_file(source, today)
        daily_records = self._load_daily(daily_path)

        # Build a set of IDs already written to today's file so we don't double-append
        today_ids = {r.get(id_field) for r in daily_records}

        new_count = 0
        updated_count = 0

        for record in incoming:
            rid = record.get(id_field)
            if not rid:
                continue

            if rid not in index:
                # Brand-new record — write to today's file
                record["_first_seen"] = now_iso
                record["_last_seen"] = now_iso
                index[rid] = {
                    "first_seen": now_iso,
                    "last_seen": now_iso,
                    "file": daily_path.name,
                }
                if rid not in today_ids:
                    daily_records.append(record)
                    today_ids.add(rid)
                new_count += 1
            else:
                # Known record — just bump last_seen in the index
                index[rid]["last_seen"] = now_iso
                updated_count += 1

        self._save_daily(daily_path, daily_records)
        self._save_index(source, index)

        logger.info(
            "HistoricalStore [%s]: +%d new, %d updated (index size: %d)",
            source, new_count, updated_count, len(index),
        )
        return new_count, updated_count

    def total_records(self, source: str) -> int:
        """Return total unique records ever seen for a source."""
        return len(self._load_index(source))

    def get_all(self, source: str) -> List[Dict]:
        """
        Return all records across all daily files for a source.
        Useful for bulk operations (e.g. re-loading Neo4j from scratch).
        """
        source_dir = self.base_dir / source
        all_records: List[Dict] = []
        for f in sorted(source_dir.glob(f"{source}_*.json")):
            with open(f) as fh:
                all_records.extend(json.load(fh))
        return all_records

    # ------------------------------------------------------------------
    # Sync state (last successful fetch timestamps + counts)
    # ------------------------------------------------------------------

    def _sync_state_path(self) -> Path:
        return self.base_dir / SYNC_STATE_FILE

    def load_sync_state(self) -> Dict:
        p = self._sync_state_path()
        if p.exists():
            with open(p) as f:
                return json.load(f)
        return {}

    def update_sync_state(self, source: str, new_count: int, error: str = None):
        state = self.load_sync_state()
        now = datetime.now(timezone.utc).isoformat()
        state[source] = {
            "last_sync": now,
            "last_new_records": new_count,
            "total_records": self.total_records(source),
            "error": error,
        }
        with open(self._sync_state_path(), "w") as f:
            json.dump(state, f, indent=2)
