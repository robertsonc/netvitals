"""SQLite persistence: settings, agents, flows, per-second samples, outages, trials, audit.

One connection guarded by one lock. The write rate is a row per leg per second, far below
anything that would justify more machinery.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence

LOG = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY, key TEXT NOT NULL, instance TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
    hostname TEXT, os TEXT, arch TEXT, version TEXT, addrs TEXT NOT NULL DEFAULT '[]',
    test_addr TEXT NOT NULL DEFAULT '', pinned INTEGER NOT NULL DEFAULT 0, remote TEXT,
    first_seen REAL, last_seen REAL, offset_ns INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, topology TEXT NOT NULL, proto TEXT NOT NULL,
    src TEXT NOT NULL, dsts TEXT NOT NULL, port INTEGER NOT NULL, size INTEGER NOT NULL, pps REAL NOT NULL,
    dscp INTEGER NOT NULL, min_echo INTEGER NOT NULL, timeout_ms INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, created REAL);
CREATE TABLE IF NOT EXISTS legs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id INTEGER NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL,
    UNIQUE(flow_id, src, dst));
CREATE TABLE IF NOT EXISTS samples (
    leg INTEGER NOT NULL, ts INTEGER NOT NULL, ts_ms INTEGER NOT NULL,
    sent INTEGER, rcv INTEGER, late INTEGER, dup INTEGER, reord INTEGER, bytes INTEGER,
    rtt_min INTEGER, rtt_avg INTEGER, rtt_max INTEGER, rtt_p50 INTEGER, rtt_p95 INTEGER, rtt_p99 INTEGER,
    fwd INTEGER, rev INTEGER, fj INTEGER, rj INTEGER, tj INTEGER,
    retx INTEGER, srtt INTEGER, reconn INTEGER, ttl INTEGER, kts INTEGER,
    rx INTEGER, rx_dup INTEGER, rx_reord INTEGER,
    PRIMARY KEY (leg, ts)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS samples_time ON samples (ts_ms);
CREATE TABLE IF NOT EXISTS outages (
    leg INTEGER NOT NULL, start_ns INTEGER NOT NULL, start_ms INTEGER NOT NULL, end_ms INTEGER,
    lost INTEGER NOT NULL, open INTEGER NOT NULL, PRIMARY KEY (leg, start_ns)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS outages_time ON outages (start_ms);
CREATE TABLE IF NOT EXISTS trials (
    id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL, cycle INTEGER NOT NULL,
    started_ms INTEGER NOT NULL, ended_ms INTEGER, success INTEGER, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, action TEXT NOT NULL, target TEXT,
    scope TEXT, detail TEXT, result TEXT);
"""

TX_COLS = ("sent", "rcv", "late", "dup", "reord", "bytes", "rtt_min", "rtt_avg", "rtt_max", "rtt_p50",
           "rtt_p95", "rtt_p99", "fwd", "rev", "fj", "rj", "tj", "retx", "srtt", "reconn", "ttl", "kts")


class Store:
    def __init__(self, data_dir: str):
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        self.path = os.path.join(data_dir, "chaoslab.db")
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None, timeout=10)
        self._db.row_factory = sqlite3.Row
        try:
            os.chmod(self.path, 0o600)   # holds lab credentials and agent keys
        except OSError as exc:
            LOG.warning("could not restrict permissions on %s: %s", self.path, exc)
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.executescript(SCHEMA)

    # ----- plumbing -----

    def run(self, sql: str, args: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, args)

    def many(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.executemany(sql, rows)
                self._db.execute("COMMIT")
            except sqlite3.Error:
                self._db.execute("ROLLBACK")
                raise

    def rows(self, sql: str, args: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args).fetchall()]

    def one(self, sql: str, args: Sequence[Any] = ()) -> Optional[Dict[str, Any]]:
        found = self.rows(sql, args)
        return found[0] if found else None

    # ----- settings -----

    def get(self, key: str, default: Any = None) -> Any:
        row = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(row["value"]) if row else default

    def put(self, key: str, value: Any) -> None:
        self.run("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (key, json.dumps(value)))

    # ----- samples -----

    def add_tx(self, rows: List[Dict[str, Any]]) -> None:
        """Sender-side seconds. Idempotent on (leg, ts): an agent retrying an upload cannot double count."""
        cols = ", ".join(TX_COLS)
        sets = ", ".join(f"{c}=excluded.{c}" for c in TX_COLS)
        marks = ", ".join("?" for _ in TX_COLS)
        self.many(f"INSERT INTO samples(leg, ts, ts_ms, {cols}) VALUES(?,?,?,{marks}) "
                  f"ON CONFLICT(leg, ts) DO UPDATE SET ts_ms=excluded.ts_ms, {sets}",
                  [(r["leg"], r["ts"], r["ts_ms"], *[r[c] for c in TX_COLS]) for r in rows])

    def add_rx(self, rows: List[Dict[str, Any]]) -> None:
        """Reflector-side seconds, joined onto the sender's row for the same sender-clock second."""
        self.many("INSERT INTO samples(leg, ts, ts_ms, rx, rx_dup, rx_reord) VALUES(?,?,?,?,?,?) "
                  "ON CONFLICT(leg, ts) DO UPDATE SET rx=excluded.rx, rx_dup=excluded.rx_dup, "
                  "rx_reord=excluded.rx_reord",
                  [(r["leg"], r["ts"], r["ts_ms"], r["rx"], r["dup"], r["reord"]) for r in rows])

    def add_outages(self, rows: List[Dict[str, Any]]) -> None:
        self.many("INSERT INTO outages(leg, start_ns, start_ms, end_ms, lost, open) VALUES(?,?,?,?,?,?) "
                  "ON CONFLICT(leg, start_ns) DO UPDATE SET end_ms=excluded.end_ms, lost=excluded.lost, "
                  "open=excluded.open",
                  [(r["leg"], r["start_ns"], r["start_ms"], r["end_ms"], r["lost"], int(r["open"])) for r in rows])

    def prune(self, keep_days: float) -> None:
        cutoff = int((time.time() - keep_days * 86400) * 1000)
        self.run("DELETE FROM samples WHERE ts_ms < ?", (cutoff,))
        self.run("DELETE FROM outages WHERE start_ms < ?", (cutoff,))

    # ----- audit -----

    def audit(self, action: str, target: str = "", scope: str = "", detail: str = "", result: str = "OK") -> None:
        self.run("INSERT INTO audit(ts, action, target, scope, detail, result) VALUES(?,?,?,?,?,?)",
                 (time.time(), action, target, scope, detail, result))
        LOG.info("[audit] %s | target=%s | scope=%s | result=%s%s", action, target or "-", scope or "-", result,
                 f" | {detail}" if detail else "")
