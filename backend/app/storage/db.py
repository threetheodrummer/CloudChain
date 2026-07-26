"""
SQLite-backed scan snapshot storage.

Every scan (demo or real) is persisted here so the drift engine can diff
the current run against the previous one. This is what lets CloudChain
say "3 new findings, 1 resolved since last scan" instead of only ever
showing a single point-in-time snapshot -- something none of the free
CSPM tools (Prowler, ScoutSuite) do out of the box.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from typing import Iterator, List, Optional

from app.config import settings
from app.models import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp);
"""


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)


@contextmanager
def get_connection(db_path: Optional[str] = None) -> Iterator[sqlite3.Connection]:
    path = db_path or settings.db_path
    _ensure_dir(path)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def save_scan(scan: ScanResult, db_path: Optional[str] = None) -> None:
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scans (scan_id, mode, timestamp, payload_json) VALUES (?, ?, ?, ?)",
            (scan.scan_id, scan.mode, scan.timestamp.isoformat(), scan.model_dump_json()),
        )


def get_scan(scan_id: str, db_path: Optional[str] = None) -> Optional[ScanResult]:
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT payload_json FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    return ScanResult.model_validate_json(row[0])


def list_scans(mode: Optional[str] = None, limit: int = 50, db_path: Optional[str] = None) -> List[ScanResult]:
    query = "SELECT payload_json FROM scans"
    params: tuple = ()
    if mode:
        query += " WHERE mode = ?"
        params = (mode,)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params = params + (limit,)

    with get_connection(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [ScanResult.model_validate_json(r[0]) for r in rows]


def get_previous_scan(current_scan_id: str, mode: str, db_path: Optional[str] = None) -> Optional[ScanResult]:
    """Returns the scan immediately before `current_scan_id` for the same mode."""
    scans = list_scans(mode=mode, limit=1000, db_path=db_path)
    scans = [s for s in scans if s.scan_id != current_scan_id]
    return scans[0] if scans else None
