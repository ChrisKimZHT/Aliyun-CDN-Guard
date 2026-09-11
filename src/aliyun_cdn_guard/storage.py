from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from .models import AccessEvent, BlockDecision, BlockRecord


class Storage:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    occurred_at INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    ua_key TEXT NOT NULL,
                    uri_key TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_window
                    ON events(domain, client_ip, ua_key, uri_key, occurred_at);
                CREATE TABLE IF NOT EXISTS blocks (
                    domain TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    first_blocked_at INTEGER NOT NULL,
                    blocked_until INTEGER NOT NULL,
                    offense_count INTEGER NOT NULL,
                    cdn_owned INTEGER,
                    PRIMARY KEY(domain, client_ip)
                );
                CREATE TABLE IF NOT EXISTS permanent_blocks (
                    domain TEXT NOT NULL,
                    entry TEXT NOT NULL,
                    cdn_owned INTEGER,
                    PRIMARY KEY(domain, entry)
                );
                """
            )

    def record_and_maybe_block(
        self,
        event: AccessEvent,
        ua_key: str,
        uri_key: str,
        threshold: int,
        window_seconds: int,
        base_duration: int,
        multiplier: float,
        max_duration: int,
        use_ua: bool,
        use_uri: bool,
        now: int | None = None,
    ) -> BlockDecision | None:
        now = int(time.time()) if now is None else now
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                inserted = self._connection.execute(
                    "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?, ?, ?)",
                    (event.event_id, event.timestamp, event.domain, event.client_ip, ua_key, uri_key),
                ).rowcount
                if not inserted:
                    self._connection.execute("COMMIT")
                    return None

                clauses = ["domain = ?", "client_ip = ?", "occurred_at >= ?", "occurred_at <= ?"]
                params: list[object] = [event.domain, event.client_ip, event.timestamp - window_seconds + 1, event.timestamp]
                if use_ua:
                    clauses.append("ua_key = ?")
                    params.append(ua_key)
                if use_uri:
                    clauses.append("uri_key = ?")
                    params.append(uri_key)
                count = int(self._connection.execute(
                    f"SELECT COUNT(*) FROM events WHERE {' AND '.join(clauses)}", params
                ).fetchone()[0])

                existing = self._connection.execute(
                    "SELECT * FROM blocks WHERE domain = ? AND client_ip = ?",
                    (event.domain, event.client_ip),
                ).fetchone()
                if count < threshold or (existing and int(existing["blocked_until"]) > now):
                    self._connection.execute("COMMIT")
                    return None

                offense = (int(existing["offense_count"]) + 1) if existing else 1
                duration = min(max_duration, int(base_duration * (multiplier ** (offense - 1))))
                blocked_until = now + duration
                first_blocked = int(existing["first_blocked_at"]) if existing else now
                self._connection.execute(
                    """INSERT INTO blocks(domain, client_ip, first_blocked_at, blocked_until, offense_count, cdn_owned)
                       VALUES (?, ?, ?, ?, ?, NULL)
                       ON CONFLICT(domain, client_ip) DO UPDATE SET
                         blocked_until=excluded.blocked_until,
                         offense_count=excluded.offense_count,
                         cdn_owned=NULL""",
                    (event.domain, event.client_ip, first_blocked, blocked_until, offense),
                )
                self._connection.execute("COMMIT")
                return BlockDecision(event.domain, event.client_ip, count, blocked_until, offense, now)
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def blocks_for_domain(self, domain: str) -> list[BlockRecord]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT domain, client_ip, blocked_until, offense_count, cdn_owned FROM blocks WHERE domain = ?",
                (domain,),
            ).fetchall()
        return [BlockRecord(row["domain"], row["client_ip"], row["blocked_until"], row["offense_count"], None if row["cdn_owned"] is None else bool(row["cdn_owned"])) for row in rows]

    def active_block_entries(self, domain: str, now: int | None = None) -> set[str]:
        now = int(time.time()) if now is None else now
        with self._lock:
            rows = self._connection.execute(
                "SELECT client_ip FROM blocks WHERE domain = ? AND blocked_until > ?",
                (domain, now),
            ).fetchall()
        return {str(row["client_ip"]) for row in rows}

    def set_ownership(self, domain: str, ownership: dict[str, bool]) -> None:
        with self._lock, self._connection:
            self._connection.executemany(
                "UPDATE blocks SET cdn_owned = ? WHERE domain = ? AND client_ip = ?",
                [(int(owned), domain, ip) for ip, owned in ownership.items()],
            )

    def permanent_for_domain(self, domain: str) -> dict[str, bool | None]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT entry, cdn_owned FROM permanent_blocks WHERE domain = ?", (domain,)
            ).fetchall()
        return {row["entry"]: None if row["cdn_owned"] is None else bool(row["cdn_owned"]) for row in rows}

    def sync_permanent_policy(self, domain: str, configured: set[str]) -> None:
        with self._lock, self._connection:
            self._connection.executemany(
                "INSERT OR IGNORE INTO permanent_blocks(domain, entry, cdn_owned) VALUES (?, ?, NULL)",
                [(domain, entry) for entry in configured],
            )

    def set_permanent_ownership(self, domain: str, ownership: dict[str, bool]) -> None:
        with self._lock, self._connection:
            self._connection.executemany(
                "UPDATE permanent_blocks SET cdn_owned = ? WHERE domain = ? AND entry = ?",
                [(int(owned), domain, entry) for entry, owned in ownership.items()],
            )

    def delete_permanent_records(self, domain: str, entries: set[str]) -> None:
        with self._lock, self._connection:
            self._connection.executemany(
                "DELETE FROM permanent_blocks WHERE domain = ? AND entry = ?",
                [(domain, entry) for entry in entries],
            )

    def prune_events(self, before: int) -> int:
        with self._lock, self._connection:
            return self._connection.execute("DELETE FROM events WHERE occurred_at < ?", (before,)).rowcount

    def close(self) -> None:
        with self._lock:
            self._connection.close()
