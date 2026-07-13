"""SQLite cache cho enrichment result — tránh burn API quota với IOC trùng."""
from __future__ import annotations
import json
import sqlite3
import time
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS enrichment (
    ioc_key    TEXT PRIMARY KEY,   -- "sha256:abc..." | "ip:1.2.3.4"
    provider   TEXT NOT NULL,      -- "virustotal" | "abuseipdb"
    verdict    TEXT NOT NULL,      -- JSON blob
    fetched_at INTEGER NOT NULL    -- unix epoch
);
CREATE INDEX IF NOT EXISTS idx_provider ON enrichment(provider);
"""


class Cache:
    def __init__(self, db_path: str, ttl_hours: int = 24):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl_hours * 3600
        self._conn = sqlite3.connect(str(self.path))
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def get(self, ioc_key: str, provider: str) -> dict | None:
        row = self._conn.execute(
            "SELECT verdict, fetched_at FROM enrichment "
            "WHERE ioc_key=? AND provider=?",
            (f"{provider}:{ioc_key}", provider),
        ).fetchone()
        if not row:
            return None
        verdict_json, fetched_at = row
        if time.time() - fetched_at > self.ttl:
            return None
        return json.loads(verdict_json)

    def put(self, ioc_key: str, provider: str, verdict: dict) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO enrichment(ioc_key, provider, verdict, fetched_at) "
            "VALUES (?,?,?,?)",
            (f"{provider}:{ioc_key}", provider, json.dumps(verdict), int(time.time())),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
